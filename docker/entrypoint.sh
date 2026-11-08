#!/bin/bash
# Entry point of the Huginn container (part of Huginn, AGPL-3.0-or-later).
#   serve          (default) create the SSH key and learn the honeypot's host key on first start, then run Huginn
#   key            print the line to run on the honeypot:  hp-add-huginn-key '<key>'
#   set-password   set or reset the login password (run with: docker compose exec -it huginn huginn set-password)
#   import FILE... / ingest-once / backup / backups / restore-db FILE   same as app.py
set -euo pipefail
D="${HUGINN_BASE:-/data}"
KEY="$D/.ssh/honeypot_ro"
KNOWN="$D/.ssh/known_hosts"
install -d -m 700 "$D/.ssh"
install -d -m 750 "$D/data"

[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "huginn@docker" -f "$KEY"

keyline() { echo "hp-add-huginn-key '$(cat "$KEY.pub")'"; }

learn_hostkey() {
  # Trust on first use, like ssh itself: the fingerprint is printed so you can compare it on the honeypot with
  #   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
  # To trust a new key later (honeypot reinstalled), delete .ssh/known_hosts in the volume and restart.
  [ -n "${HUGINN_HP_HOST:-}" ] || { echo "huginn: HUGINN_HP_HOST is not set — add it to .env"; return 0; }
  [ -s "$KNOWN" ] && return 0
  local port="${HUGINN_HP_PORT:-22022}" tmp
  tmp=$(mktemp)
  if ssh-keyscan -T 10 -t ed25519 -p "$port" "$HUGINN_HP_HOST" 2>/dev/null | grep -v '^#' > "$tmp" && [ -s "$tmp" ]; then
    mv "$tmp" "$KNOWN"; chmod 600 "$KNOWN"
    echo "huginn: trusted the honeypot's host key: $(ssh-keygen -lf "$KNOWN" | awk '{print $2}')"
    echo "huginn: compare it on the honeypot with: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
  else
    rm -f "$tmp"
    echo "huginn: the honeypot $HUGINN_HP_HOST:$port does not answer yet; will try again at the next start"
  fi
}

case "${1:-serve}" in
  serve)
    learn_hostkey
    echo "huginn: if you have not yet, run this once on the honeypot (as root):  $(keyline)"
    exec python3 /app/app.py serve ;;
  key) keyline ;;
  set-password|ingest-once|import|backup|backups|restore-db) exec python3 /app/app.py "$@" ;;
  *) exec "$@" ;;
esac
