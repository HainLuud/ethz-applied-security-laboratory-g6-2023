#!/usr/bin/env bash

set -e

machine_names=('bak' 'log' 'ca' 'db' 'web' 'client')

package_dir="$1"

mkdir -p "$package_dir"

vagrant halt

# Remove the Vagrant network interface from the client machine
VBoxManage modifyvm client --nic1 none

# Export each machine to an OVA file in parallel
for machine_name in "${machine_names[@]}"; do
    VBoxManage export "$machine_name" -o "$package_dir/$machine_name.ova" &
done

# Wait for all exports to finish
wait

# Re-add the Vagrant network interface to the client machine
VBoxManage modifyvm client --nic1 nat
