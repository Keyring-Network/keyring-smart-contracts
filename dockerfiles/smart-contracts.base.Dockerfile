# This Dockerfile sets up a lightweight Ubuntu 20.04 environment with necessary tools for Solidity development.
# It installs dependencies, sets the timezone, and installs Foundry (Forge and Cast).
# The project directory is prepared and dependencies are initialized using Forge.

# Use a lightweight base image
FROM ubuntu:22.04

# Set the timezone to UTC non-interactively
ENV TZ=Etc/UTC
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tzdata \
    curl \
    git \
    build-essential \
    libssl-dev \
    pkg-config \
    jq \
    openssl \
    xxd

ENV NVM_DIR="/usr/local/nvm"
RUN mkdir -p $NVM_DIR
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash

ENV NODE_VERSION="v18.17.0"
RUN /bin/bash -c "source $NVM_DIR/nvm.sh && nvm install $NODE_VERSION && nvm use --delete-prefix $NODE_VERSION"

ENV NODE_PATH="${NVM_DIR}/versions/node/${NODE_VERSION}/lib/node_modules"
ENV PATH="${NVM_DIR}/versions/node/$NODE_VERSION/bin:${PATH}"

# Install Foundry (Forge and Cast)
RUN curl -L https://foundry.paradigm.xyz | bash \
    && ~/.foundry/bin/foundryup

# Ensure the PATH includes Foundry binaries
ENV PATH="/root/.foundry/bin:${PATH}"

# Set up the project directory
WORKDIR /usr/src/app

# Copy the .git directory to ensure forge install works correctly
COPY .git .git
COPY foundry.toml .
COPY remappings.txt .
COPY src ./src

# Initialize the Forge project
RUN forge soldeer install