#!/bin/bash
# This script uses testnet-config.sh to start a local testnet node and then deploys the contracts to it.

# This script builds Docker images for the core-v2 project and starts a local testnet.
# It ensures a clean environment by removing any existing testnet containers before starting a new one.

# this script allows for passing through arguments to docker compose
# e.g. ./bin/testnet.sh -d

set -euo pipefail

ROOT="$(dirname "$(dirname "$(realpath "$0")")")"

docker build -t smart-contracts:latest -f "$ROOT/dockerfiles/smart-contracts.Dockerfile" .
docker build -t smart-contracts:testnet -f "$ROOT/dockerfiles/testnet.Dockerfile" .

# Remove Docker container if it exists
container_id=$(docker ps -a -q -f name=testnet)
if [ -n "$container_id" ]; then
    docker rm -f $container_id > /dev/null
fi

# Start the compose stack, passing through all arguments
docker compose -f dockerfiles/testnet.compose.yaml -p testnet-deployment up "$@"