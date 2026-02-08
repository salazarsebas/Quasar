# Quasar — Project Conventions

## Overview

Quasar is a declarative DSL that compiles `.soro` scripts into Soroban contract invocations (JSON IR and Stellar XDR). The compiler is written in Rust.

## Architecture

```
quasar-syntax   Zero-dep crate: lexer, parser, AST, span types
quasar-check    Semantic validation (depends on quasar-syntax)
quasar-compile  AST -> JSON IR (depends on quasar-syntax)
quasar-cli      Binary entry point (depends on all above)
```

## Code Conventions

- **No unnecessary dependencies** in `quasar-syntax`. The lexer and parser must have zero external deps.
- **Error types** must always include `Span` for source location. Every error a user sees must show line/column.
- **Snapshot testing** with `insta` for lexer output, AST output, and compiled JSON. Run `cargo insta review` to update snapshots.
- **Test fixtures** live in `tests/fixtures/`. Each `.soro` file can have a matching `.expected.json` for compilation tests.
- Prefer `#[must_use]` on functions returning `Result` or important values.
- No `unwrap()` in library code. Use proper error propagation with `?`.
- `unwrap()` is allowed in tests.

## Naming

- Crate names: `quasar-{name}` (kebab-case)
- Module names: snake_case
- Types: PascalCase
- File extension: `.soro`
- ABI file extension: `.soroabi`

## Testing

```bash
cargo test --workspace              # Run all tests
cargo insta review                  # Review snapshot changes
cargo clippy --workspace -- -D warnings  # Lint
cargo fmt --all -- --check          # Format check
```

## Commit Style

Conventional commits:

```
feat(syntax): add lexer tokenization
fix(check): correct CRC16 validation for C... addresses
test(compile): add snapshot for multi-call scripts
chore: update dependencies
```

## Key Technical Details

- **One InvokeHostFunctionOp per Stellar transaction.** Each `call` in a `.soro` script produces a separate transaction.
- **i128/u128 use string literals** in the DSL to avoid parse overflow. The compiler splits them into `Int128Parts { hi: i64, lo: u64 }` for XDR encoding.
- **Addresses**: `G...` = Stellar account (56 chars, StrKey), `C...` = Soroban contract (56 chars, StrKey). Both include a CRC16-XModem checksum.
- **ScVal** is the universal value type in Soroban. All DSL types map 1:1 to ScVal variants.
