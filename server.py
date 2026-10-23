#!/usr/bin/env python3
#FileViewer: view PNG images (HTTPS) and stream MP4 videos (TLS TCP stream server).

import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote

BASE_DIR = Path(__file__).resolve().parent # FileViewer dir
FILES_DIR = BASE_DIR / "files"
STATIC_DIR = BASE_DIR / "static"
CERT_DIR = BASE_DIR / "certs"
CERT_FILE = CERT_DIR / "cert.pem"
KEY_FILE = CERT_DIR / "key.pem"

HTTPS_PORT = int(os.environ.get("FILEVIEWER_HTTPS_PORT", 8443))
STREAM_PORT = int(os.environ.get("FILEVIEWER_STREAM_PORT", 8444))
BIND_ADDR = os.environ.get("FILEVIEWER_BIND", "0.0.0.0") # Listen on all addresses by default. set FILEVIEWER_BIND if you want specific one. Set after setting router forwarding

SESSION_TTL = 3 * 3600 # max session lifetime = 3 hours
SESSION_IDLE_TIMEOUT = 10 * 60  # inactive session ends after 10 mins
MAX_SESSIONS = int(os.environ.get("FILEVIEWER_MAX_SESSIONS", 2)) # max 2 sessions
SESSION_COOKIE = "fv_session"
CHUNK_SIZE = 64 * 1024 # chunk size for video streaming
PBKDF2_ITERATIONS = 600000 # The password is hashed 600000 times
MAX_FAILED_LOGINS = 3 # lock out IP after 3 incorrect password attempts
FAILED_LOGIN_WINDOW = 300 # reset failures after 5 min

TIMEOUT = 30 # 30 seconds timeout

# extension -> (kind, MIME type); images go through the web server, videos through the stream server
MEDIA_TYPES = {
    ".png": ("image", "image/png"),
    ".jpg": ("image", "image/jpeg"),
    ".jpeg": ("image", "image/jpeg"),
    ".mp4": ("video", "video/mp4"),
}

SAFE_NAME = re.compile(r"^[\w\-. ]+\.(png|jpe?g|mp4)$", re.IGNORECASE)
SAFE_FOLDER = re.compile(r"^[\w\-. ]+$") # allowed characters in the path - prevent command injection !!!
STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
}
SAFE_STATIC = re.compile(r"^[\w\-]+\.(html|css|js)$")

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    f"connect-src 'self'; media-src https://*:{STREAM_PORT}; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


# ---------------------------------------------------------------- config ---

def prompt_password(): # Ask for password when server starts
    while True:
        pw = getpass.getpass("Set password for this run: ")
        if len(pw) < 8:
            print("Password must be at least 8 characters.")
        elif pw != getpass.getpass("Repeat password: "):
            print("Passwords do not match.")
        else:
            break
    salt = secrets.token_bytes(16) # salt is a random value mixed into the password before hashing - makes every hash unique, even for identical passwords
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERATIONS) # mixes password and salt with SHA-256 and repeats that 600,000 times, feeding each result into the next round
    return {"salt": salt.hex(), "hash": digest.hex(), "iterations": PBKDF2_ITERATIONS}


def check_password(config, attempt):
    digest = hashlib.pbkdf2_hmac(
        "sha256", attempt.encode(), bytes.fromhex(config["salt"]), config["iterations"])
    return hmac.compare_digest(digest.hex(), config["hash"])


def ensure_certificate(): # if there is no certificate, create it
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    CERT_DIR.mkdir(exist_ok=True)
    print("Generating self-signed certificate in certs/ ...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(KEY_FILE), "-out", str(CERT_FILE), "-days", "365",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, capture_output=True)
    os.chmod(KEY_FILE, 0o600)


def make_ssl_context(): # TLS settings
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    return ctx


# -------------------------------------------------------------- sessions ---

class SessionStore:
    def __init__(self):
        self._sessions = {}  # token : (created, last_seen) // token is a random string, stored in cookie
        self._failures = {}
        self._lock = threading.Lock()

    def _prune(self, now):
        """Drop sessions past their lifetime or idle too long. Caller holds the lock."""
        for token, (created, last_seen) in list(self._sessions.items()):
            if now - created > SESSION_TTL or now - last_seen > SESSION_IDLE_TIMEOUT:
                del self._sessions[token]

    def createToken(self):
        now = time.time()
        with self._lock:
            self._prune(now) # have event loop check for expired sessions?
            if len(self._sessions) >= MAX_SESSIONS:
                return None
            token = secrets.token_urlsafe(32)
            self._sessions[token] = (now, now)
        return token

    def valid(self, token):
        if not token:
            return False
        now = time.time()
        with self._lock:
            self._prune(now)
            if token not in self._sessions:
                return False
            created, _ = self._sessions[token]
            self._sessions[token] = (created, now)
            return True

    def destroy(self, token):
        with self._lock:
            self._sessions.pop(token, None)

    def is_locked_out(self, ip): # update self._failures and check if ip should be locked out
        now = time.time()
        with self._lock:
            # Forget old failures for every IP
            for key in list(self._failures):
                recent = [t for t in self._failures[key] if now - t < FAILED_LOGIN_WINDOW]
                if recent:
                    self._failures[key] = recent
                else:
                    del self._failures[key]
            return len(self._failures.get(ip, [])) >= MAX_FAILED_LOGINS

    def record_failure(self, ip):
        with self._lock:
            self._failures.setdefault(ip, []).append(time.time())


SESSIONS = SessionStore()


def session_from_cookie_header(cookie_header):
    for part in (cookie_header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == SESSION_COOKIE:
            return value
    return None


# ----------------------------------------------------------------- files ---

def split_path(rel):
    # splits relative path into parts
    return [part for part in rel.split("/") if part]


def resolve_dir(rel):
    # Return the folder for a path relative to files/, or None if it is not allowed
    parts = split_path(rel)
    if any(part.startswith(".") or not SAFE_FOLDER.match(part) for part in parts):
        return None
    root = FILES_DIR.resolve()
    path = root.joinpath(*parts).resolve()
    if not path.is_relative_to(root) or not path.is_dir():
        return None
    return path


def media_kind(name):
    return MEDIA_TYPES.get(Path(name).suffix.lower(), (None, None))[0]


def media_mime(path):
    return MEDIA_TYPES[path.suffix.lower()][1]

def resolve_file(rel, kind):
    """Return the path for a requested 'folder/.../name' of the given kind, or None if not allowed."""
    folder_rel, _, fileName = rel.rpartition("/")
    folder = resolve_dir(folder_rel) # check names of all dirs in path
    if folder is None or not SAFE_NAME.match(fileName) or media_kind(fileName) != kind: # check fileName and type
        return None
    path = (folder / fileName).resolve()
    if path.parent != folder or not path.is_file():
        return None
    return path


def list_dir(rel):
    # Return (subfolder names, file names) of a rel folder
    folder = resolve_dir(rel)
    if folder is None:
        return None
    folders, files = [], []
    for p in sorted(folder.iterdir()):
        child = "/".join(split_path(rel) + [p.name])
        if p.is_dir() and resolve_dir(child):
            folders.append(p.name)
        elif p.is_file() and SAFE_NAME.match(p.name) and resolve_file(child, media_kind(p.name)):
            files.append(p.name)
    return folders, files


def parse_range(header, size):
    # Parse a 'bytes=' header. Returns (start, end) or None if invalid. This is the chunk to be sent, used for video streaming.
    m = re.fullmatch(r"bytes=(\d*)-(\d*)", (header or "").strip())
    if not m or (not m.group(1) and not m.group(2)):
        return None
    if m.group(1):
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else size - 1
    else:
        start = max(0, size - int(m.group(2)))
        end = size - 1
    end = min(end, size - 1)
    if start > end or start >= size:
        return None
    return start, end


def read_static(name):
    if not SAFE_STATIC.match(name):
        return None
    path = STATIC_DIR / name
    if not path.is_file():
        return None
    return path.read_bytes(), STATIC_TYPES[path.suffix] # return ( file bytes, file type )


def files_json(rel):
    # JSON of files in the folder
    listing = list_dir(rel)
    if listing is None:
        return None
    folders, files = listing
    return json.dumps({
        "path": "/".join(split_path(rel)),
        "stream_port": STREAM_PORT,
        "folders": folders,
        "files": [{"name": name, "type": media_kind(name)} for name in files],
    })


# --------------------------------------------------------- HTTPS server ---

class WebHandler(BaseHTTPRequestHandler):
    server_version = "FileViewer"
    sys_version = ""
    timeout = TIMEOUT  # drop inactive connections (including the TLS handshake)

    def _session(self):
        return session_from_cookie_header(self.headers.get("Cookie"))

    def _authed(self):
        return SESSIONS.valid(self._session())

    def _send(self, status, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body # bytes
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _redirect(self, location, headers=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _send_static(self, name):
        found = read_static(name)
        if not found:
            return self._send(404, "Not found", "text/plain")
        self._send(200, *found)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/login":
            return self._send_static("login.html")
        if path.startswith("/static/"):
            return self._send_static(path[len("/static/"):])
        if not self._authed():
            if path.startswith(("/image/", "/api/")):
                return self._send(401, "Unauthorized", "text/plain")
            return self._redirect("/login")
        if path == "/":
            return self._send_static("index.html")
        if path == "/api/ping":
            return self._send(200, "ok", "text/plain")
        if path == "/api/files":
            listing = files_json(parse_qs(query).get("path", [""])[0])
            if listing is None:
                return self._send(404, "Not found", "text/plain")
            return self._send(200, listing, "application/json")
        if path.startswith("/image/"):
            file = resolve_file(unquote(path[len("/image/"):]), "image")
            if not file:
                return self._send(404, "Not found", "text/plain")
            return self._send(200, file.read_bytes(), media_mime(file),
                              {"Cache-Control": "private, max-age=300"})
        self._send(404, "Not found", "text/plain")

    do_HEAD = do_GET

    def do_POST(self):
        if self.path == "/logout":
            SESSIONS.destroy(self._session())
            return self._redirect("/login", {
                "Set-Cookie": f"{SESSION_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict"})
        if self.path != "/login":
            return self._send(404, "Not found", "text/plain")

        ip = self.client_address[0]
        if SESSIONS.is_locked_out(ip):
            return self._redirect("/login?error=locked")
        length = min(int(self.headers.get("Content-Length") or 0), 4096)
        form = parse_qs(self.rfile.read(length).decode(errors="replace"))
        candidate = form.get("password", [""])[0]
        if not check_password(self.server.config, candidate):
            SESSIONS.record_failure(ip)
            return self._redirect("/login?error=wrong")
        token = SESSIONS.createToken()
        if token is None:
            return self._redirect("/login?error=full")
        self._redirect("/", {
            "Set-Cookie": f"{SESSION_COOKIE}={token}; Max-Age={SESSION_TTL}; Path=/; "
                          f"Secure; HttpOnly; SameSite=Strict"})

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[https] {self.client_address[0]} {fmt % args}\n")


# ------------------------------------------------ TCP video stream server ---
class StreamHandler(socketserver.StreamRequestHandler):
    """Raw TCP handler that streams MP4 files in chunks.

    Browsers can only consume video over HTTP, so this speaks the minimal
    subset of HTTP/1.1 that <video> needs: GET/HEAD and byte Range requests.
    The socket is TLS-wrapped so HTTPS pages may load it.
    """

    # timeout = TIMEOUT

    def handle(self):
        try:
            while self._handle_one(): # reads one request and answers it, then returns True to keep the connection open for another request
                pass
        except (ConnectionError, ssl.SSLError, TimeoutError, OSError):
            pass

    def _read_request(self): # http parser
        line = self.rfile.readline(8192).decode("latin-1").strip() # TLS decryption happens underneath automatically  // reads up to the next newline, but at most 8 KB
        if not line:
            return None
        headers = {}
        while True:
            h = self.rfile.readline(8192).decode("latin-1")
            if h in ("\r\n", "\n", ""):
                break
            k, _, v = h.partition(":")
            headers[k.strip().lower()] = v.strip()
            if len(headers) > 100:
                return None
        parts = line.split()
        if len(parts) != 3:
            return None
        return parts[0], parts[1], headers # method, path, headers

    def _write_head(self, status, reason, headers): # sends http response header
        lines = [f"HTTP/1.1 {status} {reason}"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        self.wfile.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))

    def _error(self, status, reason): # sends http error
        body = reason.encode()
        self._write_head(status, reason, {
            "Content-Type": "text/plain", "Content-Length": len(body), "Connection": "close"})
        self.wfile.write(body)
        return False

    def _handle_one(self): # sends chunk
        req = self._read_request()
        if req is None:
            return False
        method, target, headers = req
        if method not in ("GET", "HEAD"):
            return self._error(405, "Method Not Allowed")
        if not SESSIONS.valid(session_from_cookie_header(headers.get("cookie"))):
            return self._error(401, "Unauthorized")
        path = target.split("?", 1)[0]
        if not path.startswith("/video/"):
            return self._error(404, "Not Found")
        file = resolve_file(unquote(path[len("/video/"):]), "video")
        if not file:
            return self._error(404, "Not Found")

        size = file.stat().st_size
        common = {
            "Content-Type": media_mime(file),
            "Accept-Ranges": "bytes",
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        }
        if "range" in headers:
            rng = parse_range(headers["range"], size)
            if rng is None:
                self._write_head(416, "Range Not Satisfiable",
                                 {"Content-Range": f"bytes */{size}", "Content-Length": 0})
                return True
            start, end = rng
            self._write_head(206, "Partial Content", {
                **common, "Content-Range": f"bytes {start}-{end}/{size}",
                "Content-Length": end - start + 1})
        else:
            start, end = 0, size - 1
            self._write_head(200, "OK", {**common, "Content-Length": size})

        if method == "GET":
            with open(file, "rb") as f:
                f.seek(start)
                remaining = end - start + 1
                while remaining > 0:
                    chunk = f.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk) # sends chunks, encrypted. sudo tcpdump -i lo -A 'tcp port 8444'
                    remaining -= len(chunk)
        self.wfile.flush()
        return headers.get("connection", "").lower() != "close"


class TLSStreamServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, ctx):
        super().__init__(addr, handler, bind_and_activate=False)
        self.ctx = ctx
        self.server_bind()
        self.server_activate()

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(TIMEOUT)
        try:
            return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr
        except (ssl.SSLError, OSError):
            sock.close()
            raise


# ------------------------------------------------------------------ main ---

def main():
    try:
        config = prompt_password()
    except (KeyboardInterrupt, EOFError):
        sys.exit("\nNo password set, exiting.")

    FILES_DIR.mkdir(exist_ok=True)
    ensure_certificate()
    ctx = make_ssl_context()

    stream = TLSStreamServer((BIND_ADDR, STREAM_PORT), StreamHandler, ctx)
    threading.Thread(target=stream.serve_forever, daemon=True).start()

    web = ThreadingHTTPServer((BIND_ADDR, HTTPS_PORT), WebHandler)
    web.daemon_threads = True
    web.config = config

    # Handshake in the handler thread
    web.socket = ctx.wrap_socket(web.socket, server_side=True, do_handshake_on_connect=False)

    print(f"Serving files from {FILES_DIR}")
    print(f"  Web (HTTPS):         https://localhost:{HTTPS_PORT}/")
    print(f"  Video stream (TCP):  port {STREAM_PORT} (TLS)")
    try:
        web.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        web.server_close()
        stream.shutdown()
        stream.server_close()


if __name__ == "__main__":
    main()
