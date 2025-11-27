# CosmWasm Payment Channels

CosmWasm Payment Channels for Nostr-ILP Integration

## Overview

This repository contains a CosmWasm smart contract implementation for payment channels on Cosmos/Akash networks. The contract enables native AKT payments without wrapping or bridging, designed to integrate with the Dassie ILP settlement module.

## Project Status

🚧 **In Development** - Initial project setup in progress

## Prerequisites

- Rust 1.70+ (tested with 1.91.1)
- wasm32-unknown-unknown target
- cargo-generate (v0.23.7)
- cargo-wasm (v0.4.1)

## Dependencies

- **cosmwasm-std** v2.2.2 - CosmWasm standard library
- **cosmwasm-schema** v2.2.2 - JSON schema generation
- **cw-storage-plus** v2.0.0 - Enhanced storage patterns
- **cw2** v2.0.0 - Contract metadata
- **schemars** v0.8.22 - JSON schema derivation
- **serde** v1.0.197 - Serialization framework
- **thiserror** v1.0.69 - Error handling

### Dev Dependencies
- **cw-multi-test** v2.5.1 - Integration testing framework

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
- `instantiate` - Initialize contract state on deployment
- `execute` - State-changing operations (OpenChannel, CloseChannel)
- `query` - Read-only queries (GetChannel, ListChannels)
- `migrate` - Contract upgrade logic (optional)

### Contract Entry Points

```rust
#[entry_point]
pub fn instantiate(deps: DepsMut, env: Env, info: MessageInfo, msg: InstantiateMsg)
#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg)
#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg)
```

### Data Model

#### PaymentChannel State

The core data structure representing a payment channel:

```rust
pub struct PaymentChannel {
    pub id: String,              // Unique channel identifier
    pub sender: Addr,            // Payer's Cosmos address
    pub recipient: Addr,         // Payee's Cosmos address (relay operator)
    pub amount: Uint128,         // Locked AKT amount (in uakt)
    pub denom: String,           // Token denomination ("uakt" for Akash)
    pub expiration: u64,         // Expiration timestamp
    pub highest_claim: Uint128,  // Largest verified claim (monotonic nonce)
    pub status: ChannelStatus,   // Channel lifecycle state
}

pub enum ChannelStatus {
    Open,      // Channel is active
    Closed,    // Channel closed normally
    Expired,   // Channel expired (timeout)
}
```

**Field Purposes:**
- `id`: Generated as hash(sender || recipient || timestamp) - prevents collisions
- `sender`: Address that opened channel and locked funds
- `recipient`: Address authorized to claim funds (relay operator)
- `amount`: Total locked funds (immutable after opening)
- `denom`: Always "uakt" for Akash mainnet, "stake" for testnet
- `expiration`: Unix timestamp for automatic expiration
- `highest_claim`: Monotonically increasing nonce for replay protection
- `status`: Current state (Open → Closed/Expired)

#### Storage

Channels are stored using `cw-storage-plus::Map`:

```rust
pub const CHANNELS: Map<&str, PaymentChannel> = Map::new("channels");
```

- Key: `channel_id` (String, ~64 chars)
- Value: `PaymentChannel` (JSON-serialized)
- Efficient lookups: O(1)
- Range queries supported for `ListChannels`

### Message Types

#### ExecuteMsg

State-changing operations:

```rust
pub enum ExecuteMsg {
    OpenChannel {
        recipient: String,      // Bech32 Cosmos address
        expiration: u64,        // Unix timestamp
    },
    CloseChannel {
        channel_id: String,
        final_claim: Claim,     // Signed claim from sender
    },
}
```

**Example JSON:**

```json
// OpenChannel
{
  "open_channel": {
    "recipient": "akash1recipient...",
    "expiration": 1735689600
  }
}

// CloseChannel
{
  "close_channel": {
    "channel_id": "a3f8c2e...",
    "final_claim": {
      "amount": "1000000",
      "nonce": 42,
      "signature": "AQIDBA=="
    }
  }
}
```

#### Claim Struct

Off-chain signed authorization from sender:

```rust
pub struct Claim {
    pub amount: Uint128,     // Amount to claim (≤ channel.amount)
    pub nonce: u64,          // Monotonically increasing (prevents replay)
    pub signature: Binary,   // secp256k1 signature from sender
}
```

**Signature Verification** (Story 3.4):
- Signed message format: `{channel_id}:{amount}:{nonce}`
- Verifies signature is from `channel.sender`
- Checks `nonce > channel.highest_claim`
- Prevents replay attacks and double-spending

#### QueryMsg

Read-only queries:

```rust
pub enum QueryMsg {
    GetChannel { channel_id: String },
    ListChannels {
        sender: Option<String>,     // Filter by sender
        recipient: Option<String>,  // Filter by recipient
    },
}
```

**Example JSON:**

```json
// GetChannel
{
  "get_channel": {
    "channel_id": "a3f8c2e..."
  }
}

// ListChannels (all channels)
{
  "list_channels": {
    "sender": null,
    "recipient": null
  }
}

// ListChannels (filtered by sender)
{
  "list_channels": {
    "sender": "akash1sender...",
    "recipient": null
  }
}
```

#### Query Responses

```rust
pub struct GetChannelResponse {
    pub channel: PaymentChannel,
}

pub struct ListChannelsResponse {
    pub channels: Vec<PaymentChannel>,
}
```

### Error Types

Custom error variants for payment channel operations:

```rust
pub enum ContractError {
    // Standard CosmWasm errors
    Std(StdError),

    // Authorization
    Unauthorized { expected: String },

    // Channel Lifecycle
    ChannelNotFound { channel_id: String },
    ChannelExpired { expiration: u64 },
    ChannelClosed {},

    // Claim Validation (Story 3.4)
    InvalidSignature {},
    InvalidNonce { got: u64, expected: u64 },
    InsufficientBalance { requested: u128, available: u128 },
    InvalidDenom { expected: String, got: String },

    // Implementation placeholder
    Unimplemented { story: String },
}
```

**Error Classification:**
- **Permanent errors** (fail fast, no retry): ChannelNotFound, ChannelClosed, ChannelExpired, InvalidSignature, InvalidNonce
- **Configuration errors**: InvalidDenom

All errors implement `Display` via `thiserror` for human-readable messages.

## Usage Examples

### Opening a Payment Channel

**JSON Message:**
```json
{
  "open_channel": {
    "recipient": "akash1recipient...",
    "expiration": 1735689600
  }
}
```

**With akash CLI:**
```bash
akashd tx wasm execute <contract-addr> \
  '{"open_channel":{"recipient":"akash1recipient...","expiration":1735689600}}' \
  --from sender \
  --amount 1000000uakt \
  --gas auto
```

**Expected Response:**
```json
{
  "data": {
    "channel_id": "a3f8c2e1..."
  }
}
```

### Closing a Payment Channel

To close a payment channel, the recipient must provide a signed claim specifying the amount to withdraw and a nonce for replay protection.

**Claim Signature Generation (Off-Chain):**

The recipient must sign a message containing `channel_id + amount + nonce` using their secp256k1 private key:

```javascript
// Example using @noble/curves (TypeScript/JavaScript)
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

function generateClaim(channelId, amount, nonce, recipientPrivateKey) {
  // Construct message
  const message = `${channelId}${amount}${nonce}`;
  const messageBytes = new TextEncoder().encode(message);

  // Hash with SHA256
  const messageHash = sha256(messageBytes);

  // Sign the hash
  const signature = secp256k1.sign(messageHash, recipientPrivateKey);

  // Get public key (33 bytes compressed)
  const publicKey = secp256k1.getPublicKey(recipientPrivateKey, true);

  return {
    amount: amount.toString(),
    nonce,
    signature: Buffer.from(signature.toCompactRawBytes()).toString('base64'),
    pubkey: Buffer.from(publicKey).toString('base64')
  };
}
```

**JSON Message:**
```json
{
  "close_channel": {
    "channel_id": "a3f8c2e1...",
    "final_claim": {
      "amount": "600000",
      "nonce": 1,
      "signature": "OcTFFWkwKX/c1zd7PoxpK9P...",
      "pubkey": "AoS/dWImK71pQAhXSPO+avpSrjFx..."
    }
  }
}
```

**With akash CLI:**
```bash
akashd tx wasm execute <contract-addr> \
  '{"close_channel":{"channel_id":"a3f8c2e1...","final_claim":{"amount":"600000","nonce":1,"signature":"OcTFFWkwKX/c1zd7PoxpK9P...","pubkey":"AoS/dWImK71pQAhXSPO+avpSrjFx..."}}}' \
  --from recipient \
  --gas auto
```

**Claim Validation:**
- **Signature**: Verified using secp256k1_verify against the provided public key
- **Amount**: Must be ≤ locked channel amount
- **Nonce**: Must be > channel's `highest_claim` (prevents replay attacks)
- **Channel Status**: Must be Open (not Closed or Expired)

**Fund Distribution:**
- **Recipient receives**: `final_claim.amount` of `channel.denom`
- **Sender receives**: `channel.amount - final_claim.amount` (refund)
- If `final_claim.amount == 0`, full refund goes to sender
- If `final_claim.amount == channel.amount`, no refund to sender

**Expired Channels:**
If a channel expires before being closed (current time > expiration), attempting to close it will auto-refund the full locked amount to the sender and set status to Expired.

**Error Scenarios:**
- `ChannelNotFound`: Channel ID doesn't exist
- `ChannelClosed`: Channel already closed
- `ChannelExpired`: Channel expired (triggers auto-refund)
- `InvalidSignature`: Signature verification failed
- `InvalidNonce`: Nonce ≤ highest_claim (replay attack)
- `InsufficientBalance`: Claim amount > locked amount

**Validation Rules:**
- Recipient must be valid bech32 Cosmos address
- Expiration must be future timestamp (not past or current)
- Expiration must be ≤ 90 days from now
- Exactly one coin must be attached
- Coin amount must be > 0

**Error Scenarios:**
- **Invalid address:** `"Invalid address: 0x123"`
- **Past expiration:** `"Invalid expiration: 1000000 (current time: 1735689600)"`
- **No funds:** `"Invalid funds: expected 1 coin(s), received 0"`
- **Wrong denom:** `"Invalid denomination: expected uakt, got uatom"`

## Integration with Dassie

This contract will be consumed by the Dassie Cosmos settlement module (Story 2.7, already complete) to enable ILP payments on Akash/Cosmos chains.

**Integration Flow:**
```
Dassie Settlement Module (TypeScript)
  ↓
CosmJS (@cosmjs/cosmwasm-stargate)
  ↓
Payment Channel Contract (Rust/WASM)
  ↓
Akash Blockchain
```

The JSON schemas generated by this project will be imported into the Dassie settlement module for type-safe contract interactions.

## Development

### Build Contract (Development)
```bash
cargo build
```

This compiles the contract for development/testing (not WASM).

### Compile to WebAssembly
```bash
cargo build --lib --target wasm32-unknown-unknown --release
```

Output: `target/wasm32-unknown-unknown/release/payment_channel.wasm` (321KB unoptimized)

**Note:** Use `--lib` flag to exclude binary targets (schema generator) from WASM compilation.

### Run Unit Tests
```bash
cargo test
```

This runs all unit and integration tests (35 tests):

**State Tests (state.rs):**
- PaymentChannel serialization/deserialization
- ChannelStatus enum variants
- JSON format validation (snake_case)
- Edge cases (empty strings, Uint128::MAX)

**Message Tests (msg.rs):**
- ExecuteMsg serialization (OpenChannel, CloseChannel)
- QueryMsg serialization (GetChannel, ListChannels)
- Claim struct serialization
- Boundary conditions (Uint128::MAX, u64::MAX)

**Error Tests (error.rs):**
- All error variant formatting
- Display trait implementation

**Contract Tests (contract.rs):**
- Proper instantiation
- Execute stubs (Unimplemented errors)
- Query stubs (Unimplemented errors)

**Integration Tests (integration_tests.rs):**
- Full serialization round-trips
- Schema validation
- Invalid JSON deserialization
- cw-multi-test contract lifecycle

### Generate JSON Schemas
```bash
cargo run --bin schema
```

Generates JSON schemas in `schema/` directory:
- `payment-channel.json` - Combined API schema
- `raw/instantiate.json` - InstantiateMsg schema
- `raw/execute.json` - ExecuteMsg schema
- `raw/query.json` - QueryMsg schema

These schemas can be used to generate TypeScript types for client libraries.

### Code Quality

**Format Code:**
```bash
cargo fmt
```

**Lint with Clippy:**
```bash
cargo clippy -- -D warnings
```

**Run All Checks (CI equivalent):**
```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --lib --target wasm32-unknown-unknown --release
cargo run --bin schema
```

## Development Workflow

1. Make changes to contract code in `src/`
2. Run `cargo fmt` to format code
3. Run `cargo clippy` to check for issues
4. Run `cargo test` to verify tests pass
5. Run `cargo build --lib --target wasm32-unknown-unknown --release` to build WASM
6. Run `cargo run --bin schema` to regenerate schemas if message types changed
7. Commit changes with descriptive message

## Continuous Integration

This project uses GitHub Actions for CI/CD. The workflow runs on every push and PR:

- ✅ Format check (`cargo fmt`)
- ✅ Linting (`cargo clippy`)
- ✅ Unit tests (`cargo test`)
- ✅ WASM build (with size check < 1MB)
- ✅ Schema generation

See `.github/workflows/rust.yml` for details.

## Implementation Status

- ✅ **Story 3.1**: Project initialization (COMPLETE)
- ✅ **Story 3.2**: State and message types (COMPLETE - this story)
- 🚧 **Story 3.3**: Implement `open_channel` logic (NEXT)
- 🚧 **Story 3.4**: Implement `close_channel` with signature verification
- 🚧 **Story 3.5**: Implement channel query endpoints
- 🚧 **Story 3.6**: Deploy to Akash testnet
- 🚧 **Story 3.7**: Create TypeScript client library using generated schemas

**Current State:**
- ✅ PaymentChannel state structures defined
- ✅ ExecuteMsg, QueryMsg, Claim message types defined
- ✅ ContractError variants defined
- ✅ Contract stubs created (return Unimplemented)
- ✅ 35 unit and integration tests passing
- ✅ JSON schemas generated successfully
- 🚧 OpenChannel implementation (Story 3.3)
- 🚧 CloseChannel implementation (Story 3.4)
- 🚧 Query implementation (Story 3.5)

## License

Apache 2.0

## Contributing

Contributions welcome! Please open an issue or PR.

### Coding Standards

- Follow Rust naming conventions (snake_case for functions, PascalCase for types)
- Add tests for all new functionality
- Update schemas when message types change
- Keep WASM binary size under 1MB (unoptimized)
