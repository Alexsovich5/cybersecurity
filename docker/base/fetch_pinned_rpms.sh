#!/bin/bash
# Download the RPMs listed in pinned-rpms.txt ("<sha256>  <url>" per line),
# verify every file against its sha256 and turn the directory into a yum repo.
#
# Usage: fetch_pinned_rpms.sh DEST_DIR [LIST_FILE]
set -euo pipefail

dest="${1:?usage: fetch_pinned_rpms.sh DEST_DIR [LIST_FILE]}"
list="${2:-$(dirname "$0")/pinned-rpms.txt}"
attempts=3

mkdir -p "$dest"
sums="$dest/SHA256SUMS"
: > "$sums"

while read -r sum url; do
  case "$sum" in ''|'#'*) continue ;; esac
  file="${url##*/}"
  n=1
  until curl -fsSL --connect-timeout 20 -o "$dest/$file" "$url"; do
    if [ "$n" -ge "$attempts" ]; then
      echo "download failed after $attempts attempts: $url" >&2
      exit 1
    fi
    n=$((n + 1))
    sleep 5
  done
  printf '%s  %s\n' "$sum" "$file" >> "$sums"
done < "$list"

(cd "$dest" && sha256sum -c SHA256SUMS)
rm -f "$sums"
createrepo "$dest"
