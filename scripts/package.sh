#!/usr/bin/env bash

set -e

machine_names=('bak' 'log' 'ca' 'db' 'web' 'client')

package_dir="$1"

mkdir -p "$package_dir"

vagrant up

for machine_name in "${machine_names[@]}"; do
    VBoxManage export "$machine_name" -o "$package_dir/$machine_name.ova" &
done

wait
