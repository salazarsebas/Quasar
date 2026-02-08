# Usage Guide

## Installation

Build from source:

```bash
git clone https://github.com/salazarsebas/quasar.git
cd quasar
cargo install --path crates/quasar-cli
```

This installs the `quasar` binary to your Cargo bin directory.

## Writing a Script

Create a `.soro` file with your contract call:

```soro
network testnet
source  GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGKHR
fee     100000
timeout 60

call CB6TLGNLWKZR4VKQPD3FNRPNEUTXOKVMI7AF3WS2QBSF2VMHQGER7BLH transfer(
  address("GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGKHR"),
  address("GCVZ6KBMRLE32NB4UU5K37RPJNPFUNQZFYOPKJMZODDTQX4RREZDDMI"),
  i128("10000000")
)
```

## Workflow

### 1. Check syntax and types

```bash
quasar check transfer.soro
```

Validates the script without producing output. Reports any syntax errors, invalid addresses, or type mismatches.

### 2. Compile to JSON IR

```bash
quasar compile transfer.soro -o transfer.json
```

Produces a JSON intermediate representation with the contract call details and signing metadata.

### 3. Compile to XDR

```bash
quasar xdr transfer.soro
```

Outputs the raw Stellar XDR transaction envelope (base64).

### 4. Simulate against testnet

```bash
quasar simulate transfer.soro --network testnet
```

Sends the transaction to a Soroban RPC node for simulation. Returns the estimated resource costs and any errors, without actually submitting the transaction.

### 5. Execute for real

```bash
quasar run transfer.soro --secret-key SK...
```

Signs and submits the transaction to the network. Polls until the transaction is confirmed or fails.

For mainnet, Quasar will ask for confirmation before submitting. Use `--yes` to skip the prompt.

```bash
quasar run transfer.soro --secret-key SK... --yes
```

## Using Constants

Avoid repeating long addresses with `const`:

```soro
const token = "CB6TLGNLWKZR4VKQPD3FNRPNEUTXOKVMI7AF3WS2QBSF2VMHQGER7BLH"
const me    = address("GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGKHR")
const amount = i128("10000000")

network testnet
source  GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGKHR
fee     100000
timeout 60

call token transfer(me, address("GC..."), amount)
```

## Using Interfaces

Import a contract's ABI for type-checked calls:

```bash
quasar import CB6TL...BLH --network testnet -o token.soroabi
```

Then reference it in your script:

```soro
use "token.soroabi" as Token

network testnet
source  GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGKHR
fee     100000
timeout 60

call Token.transfer(
  address("GB3MR..."),
  address("GC..."),
  i128("10000000")
)
```

The compiler checks that `transfer` exists on the contract and that the argument types match.

## Format a Script

```bash
quasar fmt transfer.soro
```

Rewrites the file with consistent formatting.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `QUASAR_RPC_URL` | Default Soroban RPC endpoint (overrides network defaults) |
| `SORO_SECRET_KEY` | Secret key for signing (alternative to `--secret-key` flag) |

## RPC URL Resolution

The RPC endpoint is resolved in this order:

1. `--rpc-url` flag
2. `QUASAR_RPC_URL` environment variable
3. Network default (`testnet` → `soroban-testnet.stellar.org`, `mainnet` → `soroban-rpc.mainnet.stellar.gateway.fm`)
