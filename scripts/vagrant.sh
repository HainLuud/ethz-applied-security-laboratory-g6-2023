#!/usr/bin/env bash

set -e

machine_names=('bak' 'log' 'ca' 'db' 'web' 'client')

before_provision='before-provision'
after_provision='after-provision'

vagrant up --no-provision

for machine_name in "${machine_names[@]}"; do
    vagrant snapshot save --force "$machine_name" "$before_provision" &
done

wait

vagrant provision

for machine_name in "${machine_names[@]}"; do
    vagrant snapshot save --force "$machine_name" "$after_provision" &
done

wait
