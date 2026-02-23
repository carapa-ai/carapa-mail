#!/bin/sh
# CarapaMail SnappyMail entrypoint — configures catch-all domain on startup
set -e

DOMAINS_DIR="/var/lib/snappymail/_data_/_default_/domains"
APP_INI="/var/lib/snappymail/_data_/_default_/configs/application.ini"

# Ports from CarapaMail's env (passed through compose environment)
IMAP_PORT="${IMAP_PROXY_PORT:-1993}"
SMTP_PORT="${SMTP_PORT:-2525}"

# Start SnappyMail in the background so it initializes its data directory
/entrypoint.sh &
SNAPPY_PID=$!

# Wait for SnappyMail to create its data structure
echo "[webmail] Waiting for SnappyMail to initialize..."
for i in $(seq 1 30); do
  [ -d "$DOMAINS_DIR" ] && break
  sleep 1
done

if [ ! -d "$DOMAINS_DIR" ]; then
  echo "[webmail] Error: SnappyMail data directory not created after 30s"
  wait $SNAPPY_PID
  exit 1
fi

# Generate catch-all domain config with correct ports
cat > "$DOMAINS_DIR/default.json" <<EOF
{
    "IMAP": {
        "host": "carapamail",
        "port": ${IMAP_PORT},
        "type": 0,
        "timeout": 300,
        "shortLogin": false,
        "lowerLogin": true,
        "sasl": ["PLAIN", "LOGIN"],
        "ssl": {
            "verify_peer": false,
            "verify_peer_name": false,
            "allow_self_signed": true,
            "SNI_enabled": true,
            "disable_compression": true,
            "security_level": 0
        }
    },
    "SMTP": {
        "host": "carapamail",
        "port": ${SMTP_PORT},
        "type": 0,
        "timeout": 60,
        "shortLogin": false,
        "lowerLogin": true,
        "sasl": ["PLAIN", "LOGIN"],
        "ssl": {
            "verify_peer": false,
            "verify_peer_name": false,
            "allow_self_signed": true,
            "SNI_enabled": true,
            "disable_compression": true,
            "security_level": 0
        },
        "useAuth": true,
        "setSender": false,
        "usePhpMail": false
    },
    "Sieve": {
        "host": "",
        "port": 4190,
        "type": 0,
        "timeout": 10,
        "enabled": false
    },
    "whiteList": ""
}
EOF
chown 82:82 "$DOMAINS_DIR/default.json"

# Remove built-in domain configs that conflict
rm -f "$DOMAINS_DIR"/bf*.json 2>/dev/null

echo "[webmail] Catch-all domain config installed (IMAP:${IMAP_PORT}, SMTP:${SMTP_PORT})"

# Lock down identity settings (disable adding/editing identities)
if [ -f "$APP_INI" ]; then
  sed -i \
    -e 's/^allow_additional_identities = On/allow_additional_identities = Off/' \
    -e 's/^allow_identity_edit = On/allow_identity_edit = Off/' \
    "$APP_INI"
  echo "[webmail] Identity editing disabled"
fi

echo "[webmail] Ready — waiting for SnappyMail process"
wait $SNAPPY_PID
