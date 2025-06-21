#!/bin/bash
# This script is intended to be used by testnet.sh to start a local testnet node and then deploys the contracts to it.

# This script configures and starts a local Anvil testnet node with a specified genesis file and funded account.
# It ensures the testnet is properly initialized and ready to accept connections before completing.

# Prerequisites:
# - jq: JSON parsing utility. Ensure it is installed and available in the system's PATH.
# - anvil: The Anvil testnet node software. Ensure it is installed and available in the system's PATH.

set -euo pipefail

ROOT="$(dirname "$(dirname "$(realpath "$0")")")"

# Ensure jq is installed for JSON parsing
if ! command -v jq &> /dev/null
then
    echo "jq could not be found. Please install jq to continue."
    exit 1
fi

# Default values
ANVIL_HOST=127.0.0.1
ANVIL_PORT=8545
ANVIL_CHAIN=1337
ANVIL_GENESIS_FILE="$ROOT/genesis.json"
ANVIL_FUNDED_ACCOUNT="0x7C010FD1B3e279ac063d862199484254f27C2C44"

# Help function
display_help() {
    echo "Usage: bash bin/testnet-config.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --host          Testnet host (default: 127.0.0.1)"
    echo "  --port          Testnet port (default: 8545)"
    echo "  --chain         Testnet chain ID (default: 1337)"
    echo "  --genesis       Path to the genesis file (default: $ANVIL_GENESIS_FILE)"
    echo "  --fund-account  Account to be funded in the genesis file (default: $ANVIL_FUNDED_ACCOUNT)"
    echo "  --help          Display this help message"
    echo ""
    echo "This script configures and starts a local Anvil testnet node with the specified parameters."
    echo "It checks if 'jq' is installed, parses command-line arguments, updates the genesis file,"
    echo "and starts the Anvil node. The script waits until the Anvil node is ready to accept connections."
    echo ""
    echo "Example:"
    echo "  bash bin/testnet-config.sh --genesis /path/to/genesis.json --host 127.0.0.1 --port 8545 --chain 1337 --fund-account $ANVIL_FUNDED_ACCOUNT"
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            ANVIL_HOST="$2"
            shift 2
            ;;
        --port)
            ANVIL_PORT="$2"
            shift 2
            ;;
        --chain)
            ANVIL_CHAIN="$2"
            shift 2
            ;;
        --genesis)
            ANVIL_GENESIS_FILE="$2"
            shift 2
            ;;
        --fund-account)
            ANVIL_FUNDED_ACCOUNT="$2"
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

# Ensure the genesis file contains the correct alloc for the deployer public key
GENESIS_CONTENT=$(jq ".alloc[\"${ANVIL_FUNDED_ACCOUNT}\"] = {\"balance\": \"0xad78ebc5ac6200000\"}" "$ANVIL_GENESIS_FILE")
echo "$GENESIS_CONTENT" > "$ANVIL_GENESIS_FILE"

echo "Genesis file: $ANVIL_GENESIS_FILE"
echo "$GENESIS_CONTENT"

# Start Anvil in the background
echo "- host: $ANVIL_HOST"
echo "- port: $ANVIL_PORT"
echo "- chain: $ANVIL_CHAIN"
anvil --host $ANVIL_HOST --port $ANVIL_PORT --init $ANVIL_GENESIS_FILE --chain-id $ANVIL_CHAIN &

# Wait for avil node to be up and running on port 8545
spinner=( '⠏' '⠛' '⠹' '⢸' '⣰' '⣤' '⣆' '⡇' )

# Wait for anvil node to be up and running on port 8545
while ! (echo > /dev/tcp/localhost/8545) >/dev/null 2>&1; do
    for i in "${spinner[@]}"
    do
        echo -ne "\r$i waiting for anvil to start ..."
        sleep 0.2
    done
done

# For some reason the script doesn't respond to --chain-id flag
echo -e "\r... Ready!                      "
curl -X POST \
    --silent \
    -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"anvil_setChainId\",\"params\":[${ANVIL_CHAIN}],\"id\":1}" \
    http://$ANVIL_HOST:$ANVIL_PORT > /dev/null