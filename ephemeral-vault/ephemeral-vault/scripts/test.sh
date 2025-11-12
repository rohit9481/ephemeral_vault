#!/bin/bash
set -e

echo "Running all tests..."

# Anchor tests
echo "1. Anchor program tests..."
anchor test

# Backend tests
echo "2. Backend service tests..."
cd backend
cargo test --all-features
cd ..

# Integration tests
echo "3. Integration tests..."
cargo test --test integration_tests

# Security tests
echo "4. Security tests..."
cargo test --test security_tests

echo "All tests passed!"