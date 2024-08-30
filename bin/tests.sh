#!/bin/bash

# This script builds the core-v2 Docker image and runs Solidity tests within a Docker container.
# It ensures a clean environment by removing any existing test containers before starting a new one.

set -euo pipefail

ROOT="$(dirname "$(dirname "$(realpath "$0")")")"

docker build -t core-v2:latest -f "$ROOT/dockerfiles/core-v2.Dockerfile" .

# Remove Docker container if it exists
container_id=$(docker ps -a -q -f name=solidity-tests)
if [ -n "$container_id" ]; then
    docker rm -f $container_id > /dev/null
fi

docker run --name solidity-tests core-v2:latest /bin/bash -c 'export FOUNDRY_OUT="out-test" && forge clean && forge test -o $FOUNDRY_OUT'
