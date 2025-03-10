#!/bin/bash

# This script is used to deploy smart contracts to a specified Ethereum network.
# It accepts command line arguments for configuration and uses Foundry's Forge tool for deployment.
#
# Command Line Arguments:
# --rpc: The RPC URL of the network to which the contracts will be deployed (default: http://localhost:8545).
# --chain: The chain ID of the network (default: 1337).
# --private-key: The private key of the deployer account (default: 0x024cf65eb3bc550a1a6675aa21d146d7476fc5b62715d24fb2e0027647a213af).
# --help: Displays the help message with usage instructions.
#
# Example Usage:
# bash bin/deploy.sh --rpc http://localhost:8545 --chain 1337 --private-key 0x024cf65eb3bc550a1a6675aa21d146d7476fc5b62715d24fb2e0027647a213af
#
# Notes:
# - The script assumes that `forge build` has already been run and the contracts are compiled.
# - The script uses the `forge script` command to deploy the contract defined in `unsafe.s.sol`.
#
# The script will terminate on any error due to the `set -euo pipefail` directive.

set -euo pipefail

ROOT="$(dirname "$(dirname "$(realpath "$0")")")"
OUT_FOLDER="$ROOT/out"

# Default values
PRIVATE_KEY="0x024cf65eb3bc550a1a6675aa21d146d7476fc5b62715d24fb2e0027647a213af"
RPC_URL=http://localhost:8545

# Help function
display_help() {
    echo "This script accepts the following command line arguments:"
    echo "--rpc: the network RPC"
    echo "--private-key: The deployer private key"
    echo "--chain: useless. Kept for backwards compatibility."
    echo ""
    
    echo "For example:"
    echo "bash bin/deploy.sh --rpc $RPC_URL --private-key $PRIVATE_KEY"
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rpc)
            RPC_URL="$2"
            shift 2
            ;;
        --private-key)
            PRIVATE_KEY="$2"
            shift 2
            ;;
        --chain)
            CHAIN_ID="$2"
            shift 2
            ;;
        --help)
            display_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1. Use --help for more info."
            display_help
            exit 1
            ;;
    esac
done

echo "Deployer private key: $PRIVATE_KEY"
echo "RPC URL: $RPC_URL"

# push private_key and signature_checker to the environment
export PRIVATE_KEY=$PRIVATE_KEY

# ensure that the deploy script will actually deploy a new proxy
export PROXY_ADDRESS="0x0000000000000000000000000000000000000000"

# get all the contracts in the directory src/signatureCheckers
SIGNATURE_CHECKERS_NAMES=$(find "$ROOT/src/signatureCheckers" -name "*.sol" -exec basename {} .sol \;)

# cleanup the out directory
forge clean && \
forge build

for SIGNATURE_CHECKER_NAME in $SIGNATURE_CHECKERS_NAMES; do
    export SIGNATURE_CHECKER_NAME=$SIGNATURE_CHECKER_NAME
    echo "Deploying the contract with the signature checker $SIGNATURE_CHECKER_NAME..."
    forge script script/Deploy.s.sol \
            --broadcast \
            --rpc-url $RPC_URL
    echo "Proxy address for the signature checker $SIGNATURE_CHECKER_NAME: $(cat "$OUT_FOLDER/KeyringCoreProxy.address")"
    NEW_NAME=$(echo "$SIGNATURE_CHECKER_NAME" | sed 's/SignatureChecker//')
    mv "$OUT_FOLDER/KeyringCoreProxy.address" "$OUT_FOLDER/KeyringCore$NEW_NAME.address"
    mkdir -p "$OUT_FOLDER/KeyringCore$NEW_NAME.sol"
    ln -s "$OUT_FOLDER/KeyringCore.sol/KeyringCore.json" "$OUT_FOLDER/KeyringCore$NEW_NAME.sol/KeyringCore$NEW_NAME.json"
done


