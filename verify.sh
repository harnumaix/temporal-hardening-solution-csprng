#!/usr/bin/env bash

# Bei Fehlern sofort abbrechen (Strict Mode)
set -euo pipefail

echo "Verifying Checksums..."

# Funktion zur Überprüfung der Prüfsummen 
verify_hashes() {
    local dir=$1
    echo "  > Verifying $dir..."

    # Prüfen, ob der Ordner überhaupt existiert 
    if [ ! -d "$dir" ]; then
        echo "  ⚠️  Warning: Directory $dir not found."
        return
    fi

    # Wir nutzen eine Schleife, um Fehler sauber abzufangen
    while read -r hashfile; do
        if ! shasum -a 256 -c "$hashfile"; then
            echo "❌ Critical Error: Checksum mismatch in $hashfile"
            exit 1
        fi
    done < <(find "$dir" -maxdepth 1 -name "*.sha256")
}

verify_hashes "./src"
verify_hashes "./dist"

echo "Verification Successful!"
exit 0