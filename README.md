<p align="center">
  <img src="public/logo.png" alt="Quasar" width="180" />
</p>

<h1 align="center">Quasar</h1>

<p align="center">
  A declarative DSL that compiles to Soroban contract invocations.<br/>
  Write readable call scripts. Get validated XDR transactions.
</p>

<p align="center">
  <a href="https://github.com/salazarsebas/quasar/actions/workflows/ci.yml"><img src="https://github.com/salazarsebas/quasar/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://github.com/salazarsebas/quasar"><img src="https://img.shields.io/badge/version-0.1.0-orange.svg" alt="Version" /></a>
</p>

<p align="center">
  <a href="USAGE.md">Usage Guide</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#syntax">Syntax</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="ROADMAP.md">Roadmap</a>
</p>

---

## What is Quasar?

Quasar is a small, safe, declarative language for invoking Soroban smart contracts on Stellar. Instead of writing SDK boilerplate to build transactions, you write `.soro` scripts:

```
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

Quasar compiles this into a validated intermediate representation and ultimately into Stellar XDR transactions ready for simulation, signing, and submission.

**Quasar does NOT execute code.** It compiles. The DSL has no filesystem access, no network calls, no loops, and no side effects. This makes it safe to run on untrusted input.

## Why?

| Problem | Quasar's answer |
|---------|-------------------|
| SDK boilerplate for every contract call | Declarative `.soro` scripts |
| Easy to pass wrong argument types to contracts | Type-checked against contract ABI |
| Hard to audit what a script does | `.soro` files are readable and diffable |
| Building XDR by hand is error-prone | Compiler handles `ScVal` encoding, `Int128Parts` hi/lo split, address validation |
| No dry-run before sending real transactions | `quasar simulate` against Soroban RPC |

## Quick Start

```bash
# Compile a .soro script to intermediate JSON
quasar compile transfer.soro -o transfer.json

# Validate syntax and types without compiling
quasar check transfer.soro

# Simulate against testnet (no signing, no submission)
quasar simulate transfer.soro --network testnet

# Execute for real
quasar run transfer.soro --secret-key SK...
```

## Syntax

### Directives

```
network   testnet | mainnet | futurenet | "custom-passphrase"
source    G...                   # source account (Stellar public key)
fee       100000                 # max fee in stroops
timeout   60                     # transaction timeout in seconds
```

### Call Statements

```
call <contract_id> <method_name>(
  <arg1>,
  <arg2>,
  ...
)
```

Each `call` maps to one `InvokeHostFunctionOp` (one Stellar transaction per call, as Stellar allows only one invoke operation per transaction).

### Argument Types

Types map directly to Soroban `ScVal` variants:

| DSL Type | ScVal Variant | Example |
|----------|--------------|---------|
| `bool(true)` | `ScVal::Bool` | `bool(false)` |
| `u32(42)` | `ScVal::U32` | `u32(1000)` |
| `i32(-1)` | `ScVal::I32` | `i32(-500)` |
| `u64(100)` | `ScVal::U64` | `u64(9999999)` |
| `i64(-100)` | `ScVal::I64` | `i64(-1)` |
| `u128("...")` | `ScVal::U128` | `u128("340282366920938463463")` |
| `i128("...")` | `ScVal::I128` | `i128("-50000000")` |
| `string("...")` | `ScVal::String` | `string("hello")` |
| `symbol("...")` | `ScVal::Symbol` | `symbol("transfer")` |
| `bytes("0x...")` | `ScVal::Bytes` | `bytes("0xdeadbeef")` |
| `address("G...")` | `ScVal::Address(Account)` | `address("GB3MR...")` |
| `address("C...")` | `ScVal::Address(Contract)` | `address("CB6TL...")` |
| `vec(...)` | `ScVal::Vec` | `vec(u32(1), u32(2))` |
| `map(...)` | `ScVal::Map` | `map(symbol("a") => u32(1))` |

Large integers (`i128`, `u128`, `i256`, `u256`) use string notation to avoid parse overflow. The compiler handles the hi/lo split into `Int128Parts` / `UInt128Parts` automatically.

### Comments

```
// Line comments
/* Block comments */
```

### Constants (post-MVP)

```
const token = "CB6TLGNLWKZR4VKQPD3FNRPNEUTXOKVMI7AF3WS2QBSF2VMHQGER7BLH"
const me    = address("GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGKHR")

call token transfer(me, address("GC..."), i128("10000000"))
```

### Interfaces (post-MVP)

```
use "token.soroabi"

// Type-checked: compiler validates arg count, types, and order
call Token.transfer(
  address("GB..."),
  address("GC..."),
  i128("10000000")
)
```

Interface files are auto-generated from deployed contract metadata:

```bash
quasar import CB6TL...BLH --network testnet -o token.soroabi
```

## Architecture

```
                     Quasar Pipeline

  .soro file         Compilation (safe, offline)        Execution (network)
 ┌──────────┐   ┌────────────────────────────────┐   ┌──────────────────┐
 │          │   │                                │   │                  │
 │ network  │──>│  Lexer ─> Parser ─> Validator  │──>│  Simulate (RPC)  │
 │ source   │   │              │                 │   │       │          │
 │ fee      │   │              v                 │   │       v          │
 │ call ... │   │     AST ─> JSON IR ─> XDR      │   │  Sign (keypair)  │
 │          │   │                                │   │       │          │
 └──────────┘   └────────────────────────────────┘   │       v          │
                                                     │  Submit (RPC)    │
                                                     │       │          │
                                                     │       v          │
                                                     │  Poll result     │
                                                     └──────────────────┘
```

### Crate Structure

```
quasar/
├── crates/
│   ├── quasar-syntax/     # Lexer, parser, AST (zero external deps)
│   ├── quasar-check/      # Semantic validation, type checking
│   ├── quasar-compile/    # AST -> JSON IR + XDR (uses stellar-xdr)
│   ├── quasar-exec/       # Simulate, sign, submit (uses reqwest)
│   └── quasar-cli/        # CLI binary
└── tests/
    └── fixtures/            # .soro scripts + expected outputs
```

### Intermediate JSON Format

The compiler produces a JSON intermediate representation before XDR encoding:

```json
{
  "version": 1,
  "network": "testnet",
  "calls": [
    {
      "contract": "CB6TLGNLWKZR4VKQPD3FNRPNEUTXOKVMI7AF3WS2QBSF2VMHQGER7BLH",
      "method": "transfer",
      "args": [
        { "type": "address", "value": "GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGKHR" },
        { "type": "address", "value": "GCVZ6KBMRLE32NB4UU5K37RPJNPFUNQZFYOPKJMZODDTQX4RREZDDMI" },
        { "type": "i128", "value": "10000000" }
      ]
    }
  ],
  "signing": {
    "source": "GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGKHR",
    "fee_stroops": 100000,
    "timeout_seconds": 60
  }
}
```

Each entry in `calls` maps to one `InvokeContractArgs` XDR struct. The `args` use tagged values that correspond 1:1 to `ScVal` variants.

## Stellar Transaction Flow (what Quasar handles for you)

A Soroban contract invocation involves:

1. **Build** a `Transaction` containing one `InvokeHostFunctionOp` with `InvokeContractArgs` (contract address + function name + `ScVal` args)
2. **Simulate** via `simulateTransaction` RPC to obtain the ledger footprint, CPU/memory budget, authorization entries, and resource fee
3. **Assemble** the transaction with `SorobanTransactionData` from the simulation response
4. **Sign** with the source account keypair (plus any additional auth signers)
5. **Submit** via `sendTransaction` RPC
6. **Poll** via `getTransaction` until `SUCCESS` or `FAILED`

Quasar's compiler handles steps 1-3 (encoding ScVal types, building XDR, assembling simulation results). The executor handles steps 4-6.

## Contributing

See [ROADMAP.md](ROADMAP.md) for the implementation plan and current status.

## License

MIT
