#!/bin/sh

set -e

obfuscate() {
    src="$1"
    dst="$2"

    docker compose -f obfuscator/compose.yaml run --rm --volume "$(pwd):/app" pyarmor gen -O "$dst" "$src/"*.py
    rm -rf .pyarmor
    sed -i '' '/^# Pyarmor/d' "$dst/"*.py
}

rm -rf dist
cp -r . dist

docker compose -f obfuscator/compose.yaml build

obfuscate ca/server dist/ca/server
obfuscate web/server dist/web/server
