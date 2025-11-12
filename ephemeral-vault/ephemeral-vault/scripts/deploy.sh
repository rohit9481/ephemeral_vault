#!/bin/bash
set -e

NETWORK=${1:-devnet}

echo "Deploying to $NETWORK..."

# Deploy program
echo "Deploying Anchor program..."
anchor deploy --provider.cluster $NETWORK

# Get program ID
PROGRAM_ID=$(solana address -k target/deploy/ephemeral_vault-keypair.json)
echo "Program ID: $PROGRAM_ID"

# Update .env
echo "Updating .env..."
sed -i "s/PROGRAM_ID=.*/PROGRAM_ID=$PROGRAM_ID/" .env

echo "Deployment complete!"