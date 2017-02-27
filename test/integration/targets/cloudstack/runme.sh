#!/bin/bash

docker rm -f cloudstack

set -eu

docker pull resmo/cloudstack-sim
docker run --name cloudstack -d -p 8888:8888 resmo/cloudstack-sim
ansible-playbook cloudstack.yml -v "$@"
docker rm -f cloudstack
