#!/usr/bin/env bash

set -e

src="$1"
dst="$2"

docker compose -f obfuscator/compose.yaml run --build --rm --volume "$(pwd):/app" pyarmor gen -O "$dst" "$src/"*.py
sed -i '' '/^# Pyarmor/d' "$dst/"*.py
