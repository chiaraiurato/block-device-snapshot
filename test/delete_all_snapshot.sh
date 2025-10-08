#!/usr/bin/env bash
set -euo pipefail

# Simple purge script: delete ALL contents inside a directory,
# but keep the directory itself.
# Usage: ./delete_all_snapshot.sh
# Note: Requires root;

TARGET="/snapshot"

# Re-exec with sudo if not root
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  exec sudo -- "$0" "$TARGET"
fi

# Resolve absolute path and validate it
if ! TARGET="$(readlink -f -- "$TARGET")" || [[ ! -d "$TARGET" ]]; then
  echo "Error: directory not found: $TARGET" >&2
  exit 1
fi


echo "Purging contents of: $TARGET"
# Remove everything under TARGET (files and subdirectories)
find "$TARGET" -mindepth 1 -exec rm -rf -- {} +
echo "Done."
