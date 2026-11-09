#!/usr/bin/env bash
# Prepare a local (laptop) deployment: secrets, a self-signed TLS cert for localhost, and .env.
# Safe to re-run: existing files are never overwritten.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${WAF_PUBLIC_HOST:-localhost}"
mkdir -p secrets signature-cache
chmod 700 secrets

make_secret() { # name, generator command
  [ -s "secrets/$1" ] || { eval "$2" > "secrets/$1"; chmod 600 "secrets/$1"; echo "created secrets/$1"; }
}

make_secret credential_encryption_key "openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'"
make_secret waf_session_secret "openssl rand -hex 32 | tr -d '\n'"
make_secret waf_operator_username "printf operator"
if [ ! -s secrets/waf_operator_password ]; then
  PASSWORD="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24)"
  printf '%s' "$PASSWORD" > secrets/waf_operator_password; chmod 600 secrets/waf_operator_password
  echo "created secrets/waf_operator_password  (operator login: operator / $PASSWORD)"
fi

if [ ! -s secrets/waf_tls.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout secrets/waf_tls.key -out secrets/waf_tls.crt \
    -subj "/CN=$HOST" -addext "subjectAltName=DNS:$HOST,DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
  chmod 600 secrets/waf_tls.key secrets/waf_tls.crt
  echo "created self-signed TLS certificate for $HOST"
fi

# Placeholders so Compose bind/secret mounts have files. ADC access stays unconfigured.
[ -e secrets/netscaler_password ] || { : > secrets/netscaler_password; chmod 600 secrets/netscaler_password; }
[ -e secrets/netscaler_known_hosts ] || : > secrets/netscaler_known_hosts
[ -e signature-cache/citrix_public.pem ] || : > signature-cache/citrix_public.pem

if [ ! -e .env ]; then
  cat > .env <<ENV
WAF_DB_PASSWORD=$(openssl rand -hex 16)
WAF_PUBLIC_HOST=$HOST
COMPOSE_FILE=docker-compose.yml:docker-compose.local.yml
# Hosts approved for FREE live browsing (POST/PUT/DELETE). Comma-separated names, IPs or CIDRs.
FREE_BROWSING_ALLOWLIST=juice-shop
# Optional hard restriction of ALL scans to these targets. Leave empty to scan any non-internal host.
SCAN_TARGET_ALLOWLIST=
NETSCALER_WRITE_ENABLED=false
NETSCALER_HOST=
NETSCALER_USERNAME=
ENV
  chmod 600 .env
  echo "created .env"
fi
echo "Next: docker compose up -d --build   then open https://$HOST/"
