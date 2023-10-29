#!/usr/bin/env bash

set -e

shopt -s dotglob

src="$1"
dst="$2"

cp -rf "$src/"* "$dst/"
mv "$dst/gunicorn.conf.py" "$dst/gunicorn_conf.py"
docker compose -f obfuscator/compose.yaml run --build --rm --volume "$(pwd):/app" cythonize -3 -i --no-docstrings "$dst/"*.py
rm -rf "$dst/build" "$dst/"*.py "$dst/"*.c
echo 'from gunicorn_conf import *' > "$dst/gunicorn.conf.py"
