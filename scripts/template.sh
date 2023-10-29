#!/usr/bin/env bash

set -e

shopt -s extglob
shopt -s dotglob

src="$1"
dst="$2"

mkdir -p "$dst"
cp -rf "$src/"!("$(basename "$dst")") "$dst/"
