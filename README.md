# FileViewer

Server for viewing files from the `files/` directory in a browser, protected by a password.
Files currently supported: `.png`, `.jpg` and `.mp4`.

- **Images (PNG, JPG)** are served by the HTTPS web server (default port `8443`).
- **Videos (MP4)** are streamed by a separate TCP stream server (default port `8444`).


## Setup

```bash
cp /path/to/*.png /path/to/*.jpg /path/to/*.mp4 files/   # copy files you want to view to the files/ directory
python3 server.py   # set password and start server
```

Each time the server starts, it asks you for a password with at least 8 characters. Only a salted PBKDF2 hash of it is kept in 
memory, and nothing is written to disk. 

Open https://<server-host>:8443/ and sign in to see files.

Certificates: run ./make_certs.sh [public IP] and import ~/.local/share/fileviewer-ca/ca.pem once on the server and client browser. Both ports then work without warnings. Without this, the server creates a self-signed certificate on first run, and you have to accept the warning on both :8443 and :8444 ports.


## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `FILEVIEWER_HTTPS_PORT` | `8443` | Web / image port |
| `FILEVIEWER_STREAM_PORT` | `8444` | Video stream port |
| `FILEVIEWER_BIND` | `0.0.0.0` | Bind address |
| `FILEVIEWER_MAX_SESSIONS` | `2` | How many browsers can be signed in at once |


## Security notes

- The session cookie is `Secure`, `HttpOnly` and `SameSite=Strict`. Both servers check it. A session ends after 8 hours, or after 10 minutes without requests. While the gallery page is open, it pings the server every 2 minutes to stay signed in.
- At most `FILEVIEWER_MAX_SESSIONS` (default 2) browsers can be signed in at once. Closing the tab without logging out frees the slot within about 10 minutes.
- After 5 failed logins from one IP in 5 minutes, that IP is temporarily locked out.
- Only files inside `files/` are served. Every folder name is checked too, and the resolved path must stay inside `files/`. Directories with `..`, hidden folders and symlinks are blocked. Hidden folders (names starting with `.`) are not shown.
- Sessions are kept in memory, so restarting the server logs everyone out.

