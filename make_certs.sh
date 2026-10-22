#!/usr/bin/env bash
# Creates a private certificate authority (CA) once, then uses it to sign the server certificate in certs/
# Usage: ./make_certs.sh [extra IPs]

set -euo pipefail

CA_DIR="${FILEVIEWER_CA_DIR:-$HOME/.local/share/fileviewer-ca}"
CERT_DIR="$(cd "$(dirname "$0")" && pwd)/certs"

mkdir -p "$CA_DIR" "$CERT_DIR"
chmod 700 "$CA_DIR"

if [[ ! -f "$CA_DIR/ca.key" ]]; then
  echo "Creating CA in $CA_DIR ..."
  openssl req -x509 -newkey rsa:3072 -noenc -days 3650 -sha256 \
    -keyout "$CA_DIR/ca.key" -out "$CA_DIR/ca.pem" \
    -subj "/CN=FileViewer private CA ($(hostname))" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "nameConstraints=critical,permitted;DNS:localhost,permitted;IP:0.0.0.0/0.0.0.0" \
    2>/dev/null
  chmod 600 "$CA_DIR/ca.key"
fi

# Names the server certificate is valid for.
san="DNS:localhost"
for ip in 127.0.0.1 $(hostname -I) "$@"; do
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    [[ ",$san," == *",IP:$ip,"* ]] || san="$san,IP:$ip"
  elif [[ "$ip" != *:* ]]; then   # IPv6 from hostname -I is skipped silently
    echo "Only IPv4 addresses are allowed by this CA, not '$ip'." >&2
    exit 1
  fi
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

openssl req -newkey rsa:2048 -noenc -subj "/CN=FileViewer" \
  -keyout "$tmp/key.pem" -out "$tmp/req.csr" 2>/dev/null
cat > "$tmp/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
EOF

# Expiration = 397 days: browsers reject older server certificates.
openssl x509 -req -in "$tmp/req.csr" -days 397 -sha256 \
  -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca.key" -CAserial "$CA_DIR/ca.srl" -CAcreateserial \
  -extfile "$tmp/ext.cnf" -out "$tmp/cert.pem" 2>/dev/null

install -m 600 "$tmp/key.pem" "$CERT_DIR/key.pem"
install -m 644 "$tmp/cert.pem" "$CERT_DIR/cert.pem"

echo "Signed certs/cert.pem for: ${san//,/, }"
echo "Valid until: $(openssl x509 -in "$CERT_DIR/cert.pem" -noout -enddate | cut -d= -f2)"
echo
echo "CA certificate to install on your devices: $CA_DIR/ca.pem"
echo "Restart server.py to use the new certificate."
