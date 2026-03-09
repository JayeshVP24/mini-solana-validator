# Mini Solana Validator

An in-memory, single-node Solana-compatible JSON-RPC server for local development and testing.

This project accepts real Solana transaction wire format (base64-encoded, signed transactions) and executes instructions against an in-memory ledger.

It is designed so standard Solana clients such as `@solana/web3.js` and `@solana/spl-token` can talk to it like a real cluster.

## Features

- JSON-RPC 2.0 server on `http://localhost:3000/`
- Real transaction decoding + signature verification (ed25519)
- In-memory account ledger (no database)
- Program support:
  - System Program
  - SPL Token Program
  - Associated Token Account Program
- Blockhash issuance and validation
- Signature status tracking
- Transaction atomicity (rollback on failure)

## Tech Stack

- Node.js
- TypeScript
- Express
- `@solana/web3.js`
- `tweetnacl`
- `bs58`

## Getting Started

### Install

```bash
npm install
```

### Run

```bash
npm start
```

The server listens on port `3000`.

## JSON-RPC API

Send HTTP `POST` requests to `/` with JSON-RPC 2.0 bodies.

Example request:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": ["<pubkey>"] }
```

Example success response:

```json
{ "jsonrpc": "2.0", "id": 1, "result": { "context": { "slot": 1 }, "value": 0 } }
```

Example error response:

```json
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32601, "message": "Method not found" } }
```

### Error Codes

- `-32601` Method not found
- `-32600` Invalid request
- `-3` Invalid params
- `-32003` Transaction failed

## Implemented Methods

### Cluster

- `getVersion`
- `getSlot`
- `getBlockHeight`
- `getHealth`

### Blockhash

- `getLatestBlockhash`

### Accounts

- `getBalance`
- `getAccountInfo`
- `getMinimumBalanceForRentExemption`

### Token

- `getTokenAccountBalance`
- `getTokenAccountsByOwner`

### Transactions

- `requestAirdrop`
- `sendTransaction`
- `getSignatureStatuses`

## Program Instruction Support

### System Program (`11111111111111111111111111111111`)

- `CreateAccount`
- `Transfer`

### SPL Token Program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`)

- `InitializeMint2`
- `InitializeAccount3`
- `MintTo`
- `Transfer`
- `TransferChecked`
- `Burn`
- `CloseAccount`

### Associated Token Account Program (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`)

- `Create`

## Transaction Handling Notes

- `sendTransaction` accepts base64-encoded Solana transactions.
- Signatures are fully verified using ed25519.
- Transactions using unknown blockhashes are rejected.
- Instructions are executed sequentially.
- If any instruction fails, all state changes from that transaction are rolled back.

## In-Memory Ledger Model

Each account stores:

- `pubkey`
- `lamports`
- `owner`
- `data`
- `executable`
- `rentEpoch`

No state is persisted across restarts.

## Quick cURL Examples

Get version:

```bash
curl -s http://localhost:3000/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getVersion","params":[]}'
```

Request airdrop:

```bash
curl -s http://localhost:3000/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"requestAirdrop","params":["<pubkey>",1000000]}'
```

## Scope and Limitations

- Single-node, local testing only
- In-memory state only (reset on restart)
- Only the listed RPC methods and program instructions are supported
- No networking, consensus, leader schedule, or real validator runtime behavior

## Project Structure

- `src/index.ts` main server and execution engine
