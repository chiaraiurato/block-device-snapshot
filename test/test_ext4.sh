#!/usr/bin/env bash
set -euo pipefail

DIR="/home/aries/Documents/GitHub/block-device-snapshot/mount"
FILE="$DIR/the-file_$(date +%Y%m%d_%H%M%S).txt"
MSG="${1:-Hello world.}"

sudo mkdir -p "$DIR"

# Crea il file e scrivi la stringa (con sudo)
printf "%s\n" "$MSG" | sudo tee "$FILE" >/dev/null

# Imposta permessi leggibili
sudo chmod 644 "$FILE"

echo "Creato: $FILE"
sudo ls -l "$FILE"
sudo cat "$FILE"
