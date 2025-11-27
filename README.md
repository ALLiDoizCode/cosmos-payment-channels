# CosmWasm Payment Channels

CosmWasm Payment Channels for Nostr-ILP Integration

## Overview

This repository contains a CosmWasm smart contract implementation for payment channels on Cosmos/Akash networks. The contract enables native AKT payments without wrapping or bridging, designed to integrate with the Dassie ILP settlement module.

## Project Status

🚧 **In Development** - Initial project setup in progress

## Prerequisites

- Rust 1.70+
- wasm32-unknown-unknown target
- cargo-generate
- cargo-wasm

## Quick Start

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/cosmos-payment-channels.git
cd cosmos-payment-channels

# Build contract
cargo build

# Run tests
cargo test

# Generate schemas
cargo run --example schema

# Compile to WASM
cargo wasm
```

## Architecture

This contract implements payment channels with the following entry points:
- `instantiate` - Initialize contract state
- `execute` - State-changing operations (open_channel, close_channel)
- `query` - Read-only queries (get_channel, list_channels)
- `migrate` - Contract upgrade logic

## Integration with Dassie

This contract will be consumed by the Dassie Cosmos settlement module (Story 2.7) to enable ILP payments on Akash/Cosmos chains.

## Development

### Build Contract
```bash
cargo build
```

### Run Unit Tests
```bash
cargo test
```

### Generate JSON Schemas
```bash
cargo run --example schema
```

### Compile to WebAssembly
```bash
cargo wasm
```

## License

Apache 2.0

## Contributing

Contributions welcome! Please open an issue or PR.
