# Keyring Network Smart Contracts

[![Tests](https://github.com/keyring-network/smart-contracts/actions/workflows/ci.yml/badge.svg)](https://github.com/keyring-network/smart-contracts/actions/workflows/test.yml)

Smart contracts for [Keyring Network](https://www.keyring.network/), a platform providing institutional-grade compliance automation and permissioning solutions for blockchain protocols powered by zero-knowledge privacy.

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

## Installation

1. Clone the repository:

```bash
git clone git@github.com:Keyring-Network/keyring-smart-contracts.git
cd smart-contracts
```

2. Install dependencies:

```bash
forge soldeer install
```

## Testing

Run all tests:

```bash
forge test --force
```

Generate coverage report:

```bash
forge coverage --force
```

## Deployment

1. Set up environment variables:

Set the required variables listed in the .env.example or copy it as .env

```bash
cp .env.example .env
```

2. Run the deployment script

_w/o Etherscan verification:_

```bash
source .env && forge script script/Deploy.s.sol \
            --force \
            --broadcast \
            --rpc-url $RPC_URL
```

_w/ Etherscan verification:_

```bash
source .env && forge script script/Deploy.s.sol \
            --force \
            --broadcast \
            --rpc-url $RPC_URL
            --verify \
            --etherscan-api-key $ETHERSCAN_API_KEY \
            --verifier-url $ETHERSCAN_BASE_API_URL \
            --retries 20
```
