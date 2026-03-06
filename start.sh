#!/bin/bash
# ── CarapaMail — Start ───────────────────────────────────────────
# Usage:
#   ./start.sh                     # SQLite, no webmail
#   ./start.sh --postgres          # PostgreSQL, no webmail
#   ./start.sh --webmail           # SQLite + webmail
#   ./start.sh --postgres --webmail # PostgreSQL + webmail
#   ./start.sh --down              # Stop all services
set -e

FILES=()
DB="sqlite"
WEBMAIL=false
DOWN=false

for arg in "$@"; do
  case "$arg" in
    --postgres) DB="postgres" ;;
    --webmail)  WEBMAIL=true ;;
    --down)     DOWN=true ;;
    *)
      echo "Unknown option: $arg"
      echo "Usage: $0 [--postgres] [--webmail] [--down]"
      exit 1
      ;;
  esac
done

if [[ "$DB" == "postgres" ]]; then
  FILES+=(-f docker-compose.postgres.yml)
else
  FILES+=(-f docker-compose.yml)
fi

if [[ "$WEBMAIL" == true ]]; then
  FILES+=(-f docker-compose.webmail.yml)
fi

if [[ "$DOWN" == true ]]; then
  echo "Stopping all CarapaMail services..."
  docker compose -f docker-compose.yml -f docker-compose.webmail.yml down 2>/dev/null
  docker compose -f docker-compose.postgres.yml -f docker-compose.webmail.yml down 2>/dev/null
else
  echo "Starting CarapaMail ($DB${WEBMAIL:+ + webmail})..."
  docker compose "${FILES[@]}" up -d
  echo ""
  docker compose "${FILES[@]}" ps
fi
