#!/bin/sh

set -e

obfuscate() {
    src="$1"
    dst="$2"

    mv "$dst/gunicorn.conf.py" "$dst/gunicorn_conf.py"
    docker compose -f obfuscator/compose.yaml run --rm --volume "$(pwd):/app" cythonize -3 -i --no-docstrings "$dst/"*.py
    rm -f "$dst/"*.py "$dst/"*.c
    echo 'from gunicorn_conf import *' > "$dst/gunicorn.conf.py"
}

rm -rf dist
cp -r . dist

docker compose -f obfuscator/compose.yaml build

obfuscate ca/server dist/ca/server
obfuscate web/server dist/web/server
