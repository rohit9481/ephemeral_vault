#!/bin/bash
set -e

echo "======================================"
echo "Building Ephemeral Vault System"
echo "======================================"

# Build Anchor program
echo ""
echo "1. Building Anchor program..."
anchor build

# Build backend
echo ""
echo "2. Building backend service..."
cd backend
cargo build --release
cd ..

# Run tests
echo ""
echo "3. Running tests..."
anchor test

echo ""
echo "4. Running backend tests..."
cd backend
cargo test
cd ..

echo ""
echo "======================================"
echo "Build complete!"
echo "======================================"
echo ""
echo "Artifacts:"
echo "  - Program: target/deploy/ephemeral_vault.so"
echo "  - Backend: backend/target/release/ephemeral-vault-backend"
echo ""