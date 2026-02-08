# Contributing to Quasar

Thanks for your interest in contributing to Quasar!

## Getting Started

```bash
git clone https://github.com/salazarsebas/quasar.git
cd quasar
cargo build --workspace
cargo test --workspace
```

## Development Workflow

1. Create a branch from `main`
2. Make your changes
3. Run the full check suite:

```bash
cargo fmt --all
cargo clippy --workspace
cargo test --workspace
```

4. If you changed lexer/parser/compiler output, review snapshots:

```bash
cargo insta review
```

5. Open a pull request

## Project Structure

```
crates/
  quasar-syntax/     Lexer, parser, AST (zero external deps)
  quasar-check/      Semantic validation, type checking
  quasar-compile/    AST -> JSON IR + XDR encoding
  quasar-exec/       Simulate, sign, submit via Soroban RPC
  quasar-cli/        CLI binary
tests/
  fixtures/          .soro scripts and expected outputs
```

## Conventions

- **Commit style**: conventional commits (`feat(syntax):`, `fix(check):`, `test(compile):`, etc.)
- **Zero deps in `quasar-syntax`**: the lexer and parser must have no external dependencies
- **All errors include source location**: every `Diagnostic` must carry a `Span`
- **No `unwrap()` in library code**: use `?` for error propagation (`unwrap()` is fine in tests)
- **Snapshot testing**: `.snap` files are committed; `.snap.new` files are gitignored

## Reporting Issues

Open an issue on [GitHub](https://github.com/salazarsebas/quasar/issues) with:

- What you expected to happen
- What actually happened
- A minimal `.soro` script that reproduces the problem (if applicable)
