#!/usr/bin/env bash

# Bei Fehlern sofort abbrechen (Strict Mode)
set -euo pipefail

# Sicherstellen, dass Abhängigkeiten installiert sind
if [ ! -d "node_modules" ]; then
    echo "❌ Error: node_modules not found. Please run 'npm install' first."
    exit 1
fi

echo "Generating Type Definitions..."
# Alte Typdefinitionen bereinigen
rm -f ./src/*.d.ts 2>/dev/null
npx tsc src/*.js --declaration --allowJs --emitDeclarationOnly --outDir src --rootDir ./src --module NodeNext --moduleResolution NodeNext --target esnext 2>/dev/null

# Verzeichnisstruktur nach der tsc-Kompilierung korrigieren
if [ -d "./src/src" ]; then
    mv -f ./src/src/*.* ./src 2>/dev/null
    rm -rf ./src/src 2>/dev/null
fi

echo "Generating Documentation..."
# Dokumentationsordner zurücksetzen
# rm -rf docs 2>/dev/null
node ./node_modules/typedoc/bin/typedoc \
    --entryPointStrategy expand \
    --entryPoints "src/index.d.ts" \
    --entryPoints "src/mini-utils.d.ts" \
    --out docs \
    --readme README.md \
    --name "ths-csprng" \
    --hideGenerator \
    --cleanOutputDir true \
    --skipErrorChecking true || echo '⚠️ TypeDoc hints ignored.'

echo "Injecting Favicon into Documentation HTML..."
# Prüfen, ob der Dokumentationsordner existiert
if [ -d "docs" ]; then
    # Alle .html-Dateien im docs-Ordner finden und per sed bearbeiten
    find docs -type f -name "*.html" | while read -r html_file; do
        # Groß-/Kleinschreibung ignorieren (case-insensitive) und Favicon-Link in <head> einfügen
        # Funktioniert sowohl auf macOS (sed -i '') als auch auf Linux (sed -i)
        sed -i '' -E 's/(<head>)/\1<link rel="icon" type="image\/x-icon" href="https:\/\/cdn.jsdelivr.net\/gh\/harnumaix\/donate@main\/assets\/favicon.ico?v=1" \/>/I' "$html_file" 2>/dev/null || \
        sed -i -E 's/(<head>)/\1<link rel="icon" type="image\/x-icon" href="https:\/\/cdn.jsdelivr.net\/gh\/harnumaix\/donate@main\/assets\/favicon.ico?v=1" \/>/I' "$html_file"
    done
    echo "  > Favicon injected successfully!"
else
    echo "⚠️ Warning: docs folder not found. Skipping favicon injection."
fi

echo "Minifying Distribution..."
# Dist-Ordner für die Veröffentlichung vorbereiten
rm -rf dist 2>/dev/null
mkdir -p dist 2>/dev/null

# Funktion zur Minimierung von JS-Dateien inklusive Source Maps
minify() {
    echo "  > Minifying $1..."
    npx terser "src/$1.js" -o "dist/$1.min.js" \
        --compress --mangle \
        --source-map "url='$1.min.js.map',filename='dist/$1.min.js.map'"
}

# Hauptmodule verarbeiten
minify "index"
minify "mini-utils"

echo "Generating SHA-256 Checksums..."

# Funktion zur Erstellung der Prüfsummen
generate_hashes() {
    local dir=$1
    # Dateien mit passenden Endungen finden
    find "$dir" -maxdepth 1 -type f \( -name "*.js" -o -name "*.d.ts" -o -name "*.min.js" -o -name "*.min.js.map" \) | while read -r file; do
        echo "  > Hashing: $file"
        # Hash generieren und als .sha256 Datei speichern
        shasum -a 256 "$file" > "$file.sha256"
    done
}

# Prüfsummen für src und dist generieren
generate_hashes "./src"
generate_hashes "./dist"

# Verifizierungs-Skript aufrufen
if [ -f "./verify.sh" ]; then
    chmod +x ./verify.sh 2>/dev/null || true

    # Wir prüfen erst, ob wir Ausführrechte haben, sonst direkt per bash
    if [ -x "./verify.sh" ]; then
        ./verify.sh
    else
        bash ./verify.sh
    fi
else
    echo "❌ Error: verify.sh not found!"
    exit 1
fi

echo "Generating AI-Ready Documentation..."
# KI-optimierte Dokumentation generieren (llms-full.txt)
rm -f repomix-output.xml llms-full.txt 2>/dev/null
npx --yes repomix --style markdown \
    --output llms-full.txt \
    --ignore ".git/**,.github/**,node_modules/**,dist/**,docs/**,temp/**,**/*.sh,**/*.png,**/*.ico,**/*.svg,**/*.sha256,**/*.map,**/*.min.js,**/*.eot,**/*.ttf,**/*.woff*"

echo "Build Complete! ✅"
exit 0