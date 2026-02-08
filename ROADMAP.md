# Quasar Roadmap

Implementation roadmap split into incremental phases. Each phase produces something functional and testable. Early phases are deliberately simple to establish a solid foundation before adding complexity.

---

## Phase 0 — Project Scaffolding

**Goal**: Rust workspace ready with CI, crate structure, and defined conventions.

### Tasks

- [ ] Create Cargo workspace with crates: `quasar-syntax`, `quasar-check`, `quasar-compile`, `quasar-cli`
- [ ] Set up GitHub Actions: `cargo check`, `cargo test`, `cargo clippy`, `cargo fmt --check`
- [ ] Add `insta` as a dev dependency for snapshot testing
- [ ] Create `tests/fixtures/` directory with a sample `.soro` file and its expected `.json` output
- [ ] Define file extension: `.soro`
- [ ] Add `CLAUDE.md` with project conventions

### Tests

- `cargo build --workspace` compiles without errors
- `cargo test --workspace` passes (even if there are no tests yet)
- CI green on push

### Deliverable

Clean workspace, working CI, zero functionality but zero tech debt.

---

## Phase 1 — Lexer

**Goal**: Tokenize `.soro` files and produce a token stream with position information (line/column).

### Grammar to Support

```
Tokens:
  KEYWORD       -> network | source | fee | timeout | call | true | false
  IDENT         -> [a-zA-Z_][a-zA-Z0-9_]*
  STRING        -> "..." (with escapes: \", \\, \n, \t)
  NUMBER        -> [0-9]+
  LPAREN        -> (
  RPAREN        -> )
  COMMA         -> ,
  COMMENT       -> // until end of line
  BLOCK_COMMENT -> /* ... */
  NEWLINE       -> \n (significant for separating statements)
  EOF
```

### Tasks

- [ ] Define `Token` enum with variants and `Span { start, end, line, col }`
- [ ] Implement `Lexer` as an iterator that consumes `&str` and emits `Result<Token, LexError>`
- [ ] Support string escaping: `\"`, `\\`, `\n`, `\t`
- [ ] Support line comments (`//`) and block comments (`/* */`)
- [ ] Emit `LexError` with line, column, and source snippet
- [ ] Ignore whitespace except newlines (newlines are tokens for separating statements)

### Tests

| Test | Input | Expected Result |
|------|-------|-----------------|
| Keywords | `network testnet` | `[KEYWORD("network"), IDENT("testnet")]` |
| String | `"hello \"world\""` | `[STRING("hello \"world\"")]` |
| Numbers | `100000` | `[NUMBER(100000)]` |
| Full call | `call CB6... transfer(address("G..."))` | Correct token stream |
| Line comment | `// ignored\nnetwork` | `[NEWLINE, KEYWORD("network")]` |
| Block comment | `/* skip */call` | `[KEYWORD("call")]` |
| Unclosed string | `"hello` | `LexError` with line and column |
| Invalid character | `@` | `LexError` |
| Snapshot tests | All fixtures from `tests/fixtures/` | Snapshots with `insta` |

### Deliverable

`quasar-syntax` exposes `Lexer::new(source: &str)` that produces `Vec<Token>` or errors with exact position.

---

## Phase 2 — Parser and AST

**Goal**: Parse the token stream into a typed AST. Manual recursive descent parser, no external dependencies.

### AST

```rust
struct Program {
    directives: Vec<Directive>,
    calls: Vec<Call>,
}

enum Directive {
    Network(NetworkDirective),   // network testnet
    Source(SourceDirective),     // source GB3...
    Fee(FeeDirective),          // fee 100000
    Timeout(TimeoutDirective),  // timeout 60
}

struct Call {
    contract: String,           // CB6...XYZ
    method: String,             // transfer
    args: Vec<Value>,           // (address("G..."), i128("10"))
    span: Span,
}

enum Value {
    Bool(bool),
    U32(u32),
    I32(i32),
    U64(u64),
    I64(i64),
    U128(String),               // string to avoid overflow
    I128(String),
    U256(String),
    I256(String),
    String(String),
    Symbol(String),
    Bytes(String),              // hex string with 0x prefix
    Address(String),            // G... or C...
    Vec(Vec<Value>),
    Map(Vec<(Value, Value)>),
}
```

### Tasks

- [ ] Define AST structs in `quasar-syntax/src/ast.rs`
- [ ] Implement `Parser` with recursive descent:
  - `parse_program()` -> `Program`
  - `parse_directive()` -> `Directive`
  - `parse_call()` -> `Call`
  - `parse_value()` -> `Value` (dispatch by type name: `i128`, `address`, etc.)
  - `parse_vec()` -> `Value::Vec`
  - `parse_map()` -> `Value::Map` (with `key => value` syntax)
- [ ] Report `ParseError` with line, column, found vs. expected token, and snippet:
  ```
  error[P001]: expected ')' but found ','
   --> transfer.soro:7:24
    |
  7 |   address("GB...", "GC...")
    |                   ^
  ```
- [ ] Support multiline calls (closing `)` can be on another line)

### Tests

| Test | Input | Expected Result |
|------|-------|-----------------|
| Minimal program | `network testnet` | `Program { directives: [Network("testnet")], calls: [] }` |
| Single call | `call CB6... transfer(u32(1))` | AST with one `Call` and one `Value::U32(1)` |
| Multiline call | Call with args on multiple lines | Parses correctly |
| Multiple calls | Two `call` statements | `Program.calls.len() == 2` |
| All types | One arg of each type | Every `Value` variant parsed |
| Nested vec | `vec(vec(u32(1)))` | `Value::Vec([Value::Vec([Value::U32(1)])])` |
| Map | `map(symbol("a") => u32(1))` | `Value::Map([(Symbol("a"), U32(1))])` |
| Missing parenthesis | `call C... transfer(u32(1)` | `ParseError` with position |
| Unknown type | `call C... transfer(foo(1))` | `ParseError: unknown type "foo"` |
| Empty args | `call C... transfer()` | Parses correctly (0 args is valid) |
| Snapshot tests | All fixtures | AST serialized with `insta` |

### Deliverable

`Parser::parse(tokens: &[Token]) -> Result<Program, ParseError>` with clear errors and exact position.

---

## Phase 3 — Semantic Validation

**Goal**: Validate that the AST is semantically correct before compilation. Useful and specific errors.

### Validation Rules

| Rule | Description |
|------|-------------|
| Valid network | `testnet`, `mainnet`, `futurenet`, or network passphrase string |
| Required directives | `network` and `source` are mandatory; `fee` and `timeout` have defaults |
| Duplicate directives | Error if `network` appears twice |
| Source is account | `source` must start with `G` and be 56 characters (Stellar StrKey) |
| Contract is contract | First arg of `call` must start with `C` and be 56 characters |
| StrKey checksum | Validate CRC16 checksum of `G...` and `C...` addresses |
| u32 range | Value between 0 and 4,294,967,295 |
| i32 range | Value between -2,147,483,648 and 2,147,483,647 |
| u64 range | Value between 0 and 18,446,744,073,709,551,615 |
| i64 range | Value between -9,223,372,036,854,775,808 and 9,223,372,036,854,775,807 |
| Parseable i128 | String parseable as Rust native `i128` |
| Parseable u128 | String parseable as Rust native `u128` |
| Valid hex bytes | Must start with `0x`, even length, only hex characters |
| Valid symbol | Only `[a-zA-Z0-9_]`, max 32 characters (Soroban restriction) |
| Reasonable fee | Warning if fee < 100 or > 10,000,000 stroops |
| Reasonable timeout | Warning if timeout < 10 or > 300 seconds |
| At least one call | Warning if the script has no `call` statements |

### Tasks

- [ ] Implement `Validator` in `quasar-check` that takes a `Program` and returns `Vec<Diagnostic>`
- [ ] Each `Diagnostic` has: severity (Error/Warning), message, span, help text
- [ ] Implement Stellar StrKey validation with CRC16 checksum (no external dependency, it's a 2-byte CRC16-XModem)
- [ ] Error format:
  ```
  error[V003]: invalid Stellar address checksum
   --> transfer.soro:3:9
    |
  3 | source  GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGXXX
    |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: addresses start with G (accounts) or C (contracts) and include a CRC16 checksum
  ```

### Tests

| Test | Input | Expected Result |
|------|-------|-----------------|
| Valid complete script | Fixture with all directives and a call | 0 errors |
| Missing network | Script without `network` | Error: "missing required directive 'network'" |
| Duplicate network | `network testnet\nnetwork mainnet` | Error: "duplicate directive 'network'" |
| Invalid address (length) | `source GB3...` (55 chars) | Error: checksum/format |
| Invalid address (checksum) | `source GB3...XXX` (bad checksum) | Error: "invalid checksum" |
| Contract with G | `call GB3... transfer()` | Error: "expected contract address (C...), got account (G...)" |
| u32 overflow | `u32(5000000000)` | Error: "value exceeds u32 range" |
| Unparseable i128 | `i128("abc")` | Error: "not a valid i128" |
| Invalid hex | `bytes("0xZZ")` | Error: "invalid hex" |
| Odd-length hex | `bytes("0xabc")` | Error: "hex must have even length" |
| Long symbol | `symbol("a]b")` | Error: "invalid symbol character" |
| Fee warning | `fee 50` | Warning: "fee unusually low" |
| Snapshot tests | Fixtures with intentional errors | Diagnostic snapshots |

### Deliverable

`Validator::validate(program: &Program) -> Vec<Diagnostic>` with errors, warnings, and help text with exact position.

---

## Phase 4 — JSON Compiler (Intermediate Representation)

**Goal**: Compile a validated AST to JSON IR. This JSON is the "stable interface" between the compiler and the executor.

### JSON IR Format

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

### Tasks

- [ ] Define JSON IR structs in `quasar-compile/src/ir.rs` with `serde::Serialize`
- [ ] Implement `Compiler::compile(program: &Program) -> JsonIR`
- [ ] Map AST `Value` to tagged JSON format:
  - `Value::Bool(true)` -> `{ "type": "bool", "value": true }`
  - `Value::I128(s)` -> `{ "type": "i128", "value": "..." }`
  - `Value::Vec(vs)` -> `{ "type": "vec", "value": [...] }`
  - `Value::Map(entries)` -> `{ "type": "map", "value": [{"key": ..., "value": ...}] }`
- [ ] Include `version: 1` field for forward compatibility
- [ ] Derive `network_passphrase` from network name:
  - `testnet` -> `"Test SDF Network ; September 2015"`
  - `mainnet` -> `"Public Global Stellar Network ; September 2015"`
  - `futurenet` -> `"Test SDF Future Network ; October 2022"`
- [ ] Default values: `fee` = 100000, `timeout` = 30

### Tests

| Test | Input .soro | Expected .json Output |
|------|-------------|----------------------|
| Minimal | `network testnet\nsource G...\ncall C... transfer()` | JSON with empty args call |
| All types | Call with one arg of each type | Each type correctly serialized |
| Multiple calls | Two `call` statements | `calls` array with 2 entries |
| Defaults | Without `fee` or `timeout` | fee=100000, timeout=30 |
| Nested vec | `vec(u32(1), vec(u32(2)))` | Correctly nested JSON |
| Map | `map(symbol("x") => i128("1"))` | JSON with key/value entries |
| Roundtrip: parse + compile | Complete fixture | JSON matches exact snapshot |
| Valid JSON | Output from any compilation | `serde_json::from_str` doesn't fail |
| Version field | Any input | `"version": 1` present |

### Deliverable

`quasar compile input.soro` produces valid JSON to stdout or to a file with `-o`. The JSON is deterministic (same input = same output byte for byte).

---

## Phase 5 — CLI

**Goal**: Usable binary from the terminal with professional UX.

### Commands

```
quasar compile <file.soro> [-o output.json]   # Compile to JSON IR
quasar check <file.soro>                      # Validate only (errors + warnings)
quasar fmt <file.soro> [--write]              # Format (stdout by default, --write in-place)
quasar version                                # Compiler version
```

### Tasks

- [ ] CLI with `clap` v4 (derive API)
- [ ] `compile`: Lexer -> Parser -> Validator -> Compiler -> JSON output
  - If there are errors, print them formatted to stderr and exit code 1
  - If there are only warnings, print them to stderr but continue compilation
  - `-o file.json` writes to file; without `-o` writes to stdout
- [ ] `check`: Lexer -> Parser -> Validator only, report diagnostics
  - Exit code 0 if no errors (warnings OK)
  - Exit code 1 if there are errors
- [ ] `fmt`: Reformat the `.soro` file with consistent indentation
  - 2-space indentation for call args
  - One line per arg when there are > 1 args
  - `--write` to overwrite the file in-place
- [ ] Terminal colors: errors in red, warnings in yellow, paths in cyan (using `termcolor` or `anstream`)
- [ ] `--no-color` flag for CI/pipes

### Tests

| Test | Command | Expected Result |
|------|---------|-----------------|
| Successful compile | `quasar compile valid.soro` | JSON to stdout, exit code 0 |
| Compile with output | `quasar compile valid.soro -o out.json` | File created, exit code 0 |
| Compile with error | `quasar compile invalid.soro` | Errors to stderr, exit code 1 |
| Valid check | `quasar check valid.soro` | "No errors found", exit code 0 |
| Check with warnings | `quasar check low_fee.soro` | Warning to stderr, exit code 0 |
| Check with errors | `quasar check broken.soro` | Errors to stderr, exit code 1 |
| Idempotent fmt | `quasar fmt file.soro` twice | Same output both times |
| Fmt --write | `quasar fmt file.soro --write` | File overwritten |
| File not found | `quasar compile noexist.soro` | Clear error, exit code 1 |
| Pipe friendly | `quasar compile f.soro \| jq .` | JSON parseable by jq |
| Integration tests | All fixtures from `tests/fixtures/` | Expected results |

### Deliverable

`quasar` binary installable with `cargo install`. Errors with color, exact position, and fix suggestions. A user can write a `.soro` file, compile it, and get valid JSON.

---

## Phase 6 — Immutable Constants

**Goal**: Add `const` to reduce repetition without adding mutability or complexity.

### Syntax

```
const token   = "CB6TLGNLWKZR4VKQPD3FNRPNEUTXOKVMI7AF3WS2QBSF2VMHQGER7BLH"
const sender  = address("GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGKHR")
const amount  = i128("10000000")

network testnet
source  GB3MRDIQO2HFBLAG2CSMHPYZFVPQOYPEV3BUKY2GMQKKQRMO4OERGKHR
fee     100000

call token transfer(sender, address("GC..."), amount)
```

### Rules

- `const` only at the top of the file (before directives and calls)
- Names: `[a-z_][a-z0-9_]*` (snake_case)
- Values: string literal or any typed `Value`
- Immutable: cannot be redefined
- Scope: global to the file, no blocks
- Compile-time substitution (does not exist in JSON output)

### Tasks

- [ ] Add `CONST` to the lexer as a keyword
- [ ] Add `ConstDecl { name, value, span }` to the AST
- [ ] Parser: `parse_const()` before directives and calls
- [ ] Resolver: new pass that substitutes names with values in the AST
  - If an ident in contract ID position matches a string-type const -> substitute
  - If an ident in argument position matches a Value-type const -> substitute
  - If it matches no const -> `ParseError: undefined name "..."`
- [ ] Validation:
  - Duplicate name -> error
  - Unused const -> warning
  - Circular reference (not possible without expressions, but validate just in case)

### Tests

| Test | Input | Expected Result |
|------|-------|-----------------|
| String const | `const c = "CB..."\ncall c transfer()` | JSON with expanded contract_id |
| Value const | `const a = i128("10")\ncall C... f(a)` | JSON with expanded i128 arg |
| Duplicate const | `const x = "a"\nconst x = "b"` | Error: "duplicate const 'x'" |
| Undefined const | `call token transfer()` (no const) | Error: "undefined name 'token'" |
| Unused const | `const unused = "..."` | Warning: "const 'unused' is never used" |
| Const in directive | `const s = "G..."\nsource s` | Error: directives don't support const refs (MVP) |
| Identical output | With and without const (expanded) | Same JSON IR |

### Deliverable

More readable scripts with semantic names. The JSON output is identical — constants are pure compiler syntax sugar.

---

## Phase 7 — XDR Compiler

**Goal**: Compile JSON IR to Stellar XDR types. This is the step that converts the intermediate representation into something Stellar can process.

### DSL -> ScVal Mapping

| JSON IR type | ScVal variant | Encoding |
|-------------|---------------|----------|
| `bool` | `ScVal::Bool(v)` | Direct |
| `u32` | `ScVal::U32(v)` | Direct |
| `i32` | `ScVal::I32(v)` | Direct |
| `u64` | `ScVal::U64(v)` | Direct |
| `i64` | `ScVal::I64(v)` | Direct |
| `u128` | `ScVal::U128(UInt128Parts { hi, lo })` | `hi = (v >> 64) as u64`, `lo = v as u64` |
| `i128` | `ScVal::I128(Int128Parts { hi, lo })` | `hi = (v >> 64) as i64`, `lo = v as u64` |
| `u256` | `ScVal::U256(UInt256Parts { ... })` | Split into 4 x u64 |
| `i256` | `ScVal::I256(Int256Parts { ... })` | Split into 4 (hi_hi signed) |
| `string` | `ScVal::String(ScString)` | Direct |
| `symbol` | `ScVal::Symbol(ScSymbol)` | Direct, max 32 chars |
| `bytes` | `ScVal::Bytes(ScBytes)` | Decode hex -> bytes |
| `address` (G...) | `ScVal::Address(ScAddress::Account(...))` | StrKey decode -> AccountId |
| `address` (C...) | `ScVal::Address(ScAddress::Contract(...))` | StrKey decode -> Hash(32 bytes) |
| `vec` | `ScVal::Vec(Some(ScVec(values)))` | Recursive |
| `map` | `ScVal::Map(Some(ScMap(entries)))` | Recursive |

### Output Struct

```rust
struct CompiledTransaction {
    network_passphrase: String,
    source_account: AccountId,
    fee: u32,
    timeout_seconds: u64,
    invoke_args: InvokeContractArgs,  // contract + method + ScVal args
}
```

### Tasks

- [ ] Add dependency: `stellar-xdr` (crate `rs-stellar-xdr`)
- [ ] Implement `XdrCompiler::compile(ir: &JsonIR) -> Result<Vec<CompiledTransaction>, XdrError>`
  - One `CompiledTransaction` per entry in `calls[]`
- [ ] Implement `to_scval(arg: &JsonArg) -> ScVal` function with the mapping above
- [ ] Implement `i128_to_parts(s: &str) -> Int128Parts`:
  ```rust
  let v: i128 = s.parse()?;
  Int128Parts { hi: (v >> 64) as i64, lo: v as u64 }
  ```
- [ ] Implement `u128_to_parts(s: &str) -> UInt128Parts` analogously
- [ ] Implement `decode_strkey(s: &str) -> ScAddress`:
  - `G...` -> `ScAddress::Account(AccountId(PublicKey::Ed25519(...)))`
  - `C...` -> `ScAddress::Contract(Hash(...))`
- [ ] Serialize `InvokeContractArgs` to XDR bytes + base64
- [ ] New CLI command: `quasar xdr input.soro` (output: base64 XDR per call)

### Tests

| Test | Input | Expected Result |
|------|-------|-----------------|
| Positive i128 | `i128("10000000")` | `Int128Parts { hi: 0, lo: 10000000 }` |
| Negative i128 | `i128("-1")` | `Int128Parts { hi: -1, lo: u64::MAX }` |
| Large i128 | `i128("170141183460469231731687303715884105727")` | Correct parts (i128::MAX) |
| Zero u128 | `u128("0")` | `UInt128Parts { hi: 0, lo: 0 }` |
| G address decode | `address("GB3MR...")` | `ScAddress::Account(...)` with correct bytes |
| C address decode | `address("CB6TL...")` | `ScAddress::Contract(Hash(...))` with correct bytes |
| Bool | `bool(true)` | `ScVal::Bool(true)` |
| Symbol | `symbol("transfer")` | `ScVal::Symbol(ScSymbol("transfer"))` |
| Vec | `vec(u32(1), u32(2))` | `ScVal::Vec(Some(ScVec([U32(1), U32(2)])))` |
| XDR roundtrip | Compile and deserialize XDR | Identical structs |
| Valid base64 | Output of `quasar xdr` | Base64 decodable to valid XDR |

### Deliverable

Given a `.soro` file, produce `InvokeContractArgs` in base64 XDR, ready to be used in a `TransactionBuilder`. Tests validate encoding bit by bit.

---

## Phase 8 — Simulation (Soroban RPC)

**Goal**: Connect to Soroban RPC to simulate transactions before signing and submitting.

### Flow

```
.soro -> Compile -> XDR (InvokeContractArgs)
                        |
                        v
              Build Transaction (unsigned)
                        |
                        v
              simulateTransaction (RPC call)
                        |
                        v
              Parse SimulationResponse:
                - resource fee
                - soroban data (footprint)
                - auth entries
                - return value
                - events
```

### Tasks

- [ ] Add dependency: `soroban-client` or `reqwest` + manual JSON-RPC
- [ ] Implement `Simulator` in `quasar-exec`:
  1. Load account sequence number via `getAccount` RPC
  2. Build `Transaction` with `InvokeHostFunctionOp`
  3. Serialize to base64 XDR
  4. Send to `simulateTransaction` RPC endpoint
  5. Parse response
- [ ] Handle simulation responses:
  - **Success**: display return value, resource costs, events
  - **Error**: display detailed error
  - **Restore needed**: inform that `RestoreFootprint` is required first
- [ ] Format simulation output:
  ```
  Simulating call 1/2: CB6...XYZ.transfer()
    Status:     success
    Return:     void
    CPU:        45,231 instructions
    Read:       312 bytes
    Write:      128 bytes
    Fee:        154,231 stroops (resource) + 100 (base) = 154,331 total
    Events:     1 contract event
  ```
- [ ] New CLI command: `quasar simulate input.soro [--network testnet]`
- [ ] Support for configurable RPC URL: `--rpc-url <url>` or env `QUASAR_RPC_URL`
- [ ] Default RPC URLs:
  - testnet: `https://soroban-testnet.stellar.org`
  - mainnet: `https://soroban-rpc.mainnet.stellar.gateway.fm` (or similar)
  - futurenet: `https://rpc-futurenet.stellar.org`

### Tests

| Test | Scenario | Expected Result |
|------|----------|-----------------|
| Successful simulation | Valid call against testnet | Status success, costs displayed |
| Nonexistent contract | Call to a C... contract that doesn't exist | Clear RPC error |
| Nonexistent method | Call to a method that doesn't exist on the contract | Error with method name |
| Incorrect args | Arg types don't match the contract | Simulator error |
| Unreachable network | Invalid RPC URL | Clear connection error |
| Multiple calls | Script with 2 calls | Independent simulation of each one |
| JSON output | `--json` flag | Simulation response in JSON |
| Dry run | Simulation doesn't modify anything | Verify no transaction was sent |

### Deliverable

`quasar simulate script.soro` runs a dry-run against the network and shows costs, return values, and potential errors without spending XLM.

---

## Phase 9 — ABI Import (Contract Spec)

**Goal**: Read the metadata of a deployed contract and generate a `.soroabi` file that describes its interface.

### Technical Context

Soroban contracts embed their ABI as serialized XDR in the `contractspecv0` custom section of the WASM binary. This section contains a stream of `SCSpecEntry` values that describe functions, structs, enums, unions, and error enums.

### `.soroabi` Format

```json
{
  "contract_id": "CB6TLGNLWKZR4VKQPD3FNRPNEUTXOKVMI7AF3WS2QBSF2VMHQGER7BLH",
  "name": "Token",
  "functions": [
    {
      "name": "transfer",
      "doc": "Transfer tokens from one address to another",
      "inputs": [
        { "name": "from", "type": "address" },
        { "name": "to", "type": "address" },
        { "name": "amount", "type": "i128" }
      ],
      "outputs": [{ "type": "void" }]
    },
    {
      "name": "balance",
      "doc": "Get the balance of an address",
      "inputs": [
        { "name": "id", "type": "address" }
      ],
      "outputs": [{ "type": "i128" }]
    }
  ],
  "types": [
    {
      "name": "TokenMetadata",
      "kind": "struct",
      "fields": [
        { "name": "name", "type": "string" },
        { "name": "symbol", "type": "symbol" },
        { "name": "decimals", "type": "u32" }
      ]
    }
  ]
}
```

### Tasks

- [ ] Implement `AbiImporter` in `quasar-check`:
  1. Call RPC `getContractData` or `getLedgerEntries` to get the WASM hash
  2. Call `getLedgerEntries` to get the WASM binary
  3. Parse the `contractspecv0` custom section from the WASM
  4. Deserialize the stream of `SCSpecEntry` (XDR)
  5. Map `SCSpecTypeDef` to DSL types
  6. Generate `.soroabi` JSON
- [ ] `SCSpecTypeDef` -> DSL type mapping:
  - `SC_SPEC_TYPE_ADDRESS` -> `"address"`
  - `SC_SPEC_TYPE_I128` -> `"i128"`
  - `SC_SPEC_TYPE_VEC` -> `"vec<element_type>"`
  - `SC_SPEC_TYPE_MAP` -> `"map<key_type, value_type>"`
  - `SC_SPEC_TYPE_UDT` -> reference by name to the custom type
- [ ] New CLI command: `quasar import <contract_id> --network testnet [-o token.soroabi]`
- [ ] Local cache: save `.soroabi` to avoid re-fetching every time

### Tests

| Test | Scenario | Expected Result |
|------|----------|-----------------|
| Import SAC token | Import the Stellar Asset Contract on testnet | `.soroabi` with standard functions (transfer, balance, etc.) |
| Import custom contract | Deploy a test contract and import | Correct custom functions and types |
| Contract without spec | Contract without `contractspecv0` | Clear error: "contract has no spec" |
| Complex types | Contract with structs, enums, vecs | `.soroabi` reflects all types |
| Cache hit | Import the same contract twice | Second time uses cache |
| Valid JSON | Import output | Parseable as JSON |
| Offline | No RPC connection | Clear connection error |

### Deliverable

`quasar import CB6...XYZ --network testnet` generates a `.soroabi` with the complete contract interface, readable and usable by the next phase.

---

## Phase 10 — Interfaces and Type Checking

**Goal**: Validate calls against the contract interface. Type errors at compile time, not at runtime.

### Syntax

```
use "token.soroabi"

network testnet
source  GB3...

// The compiler knows Token.transfer expects (address, address, i128)
call Token.transfer(
  address("GB..."),
  address("GC..."),
  i128("10000000")
)

// COMPILE ERROR: balance expects 1 arg, not 2
call Token.balance(address("GB..."), u32(1))
```

### Tasks

- [ ] Add `USE` to the lexer as a keyword
- [ ] Add `UseDecl { path: String, alias: Option<String>, span }` to the AST
- [ ] Parser: `use "path.soroabi" [as Alias]`
- [ ] Add `InterfaceCall` as a Call variant: `Token.transfer(...)` -> contract ID comes from the `.soroabi`
- [ ] `TypeChecker` in `quasar-check`:
  1. Load the `.soroabi` referenced by `use`
  2. For each `call Interface.method(...)`:
     - Verify that `method` exists in the interface
     - Verify argument count
     - Verify each argument's type against the signature
  3. Errors:
     ```
     error[T001]: wrong number of arguments for Token.transfer
      --> script.soro:8:6
       |
     8 | call Token.transfer(address("GB..."))
       |      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
       = expected 3 arguments (from, to, amount) but got 1
     ```
     ```
     error[T002]: type mismatch for argument 'amount' of Token.transfer
      --> script.soro:10:5
        |
     10 |   u32(100)
        |   ^^^^^^^^ expected i128, got u32
     ```
- [ ] Support UDT types: if an argument expects a struct, validate that a `map` with the correct fields is passed (or special syntax for structs)

### Tests

| Test | Input | Expected Result |
|------|-------|-----------------|
| Correct call | `call Token.transfer(addr, addr, i128)` | 0 errors |
| Missing args | `call Token.transfer(addr)` | Error: expected 3 args, got 1 |
| Extra args | `call Token.transfer(addr, addr, i128, u32)` | Error: expected 3 args, got 4 |
| Wrong type | `call Token.transfer(addr, addr, u32(1))` | Error: expected i128, got u32 |
| Nonexistent method | `call Token.foo()` | Error: "Token has no method 'foo'" |
| Interface not found | `use "missing.soroabi"` | Error: file not found |
| No interface (raw call) | `call C... transfer(...)` | Still works without type check |
| Mixed interface + raw | Both styles in one script | Both compile correctly |
| Method suggestion | `call Token.tranfer(...)` (typo) | "did you mean 'transfer'?" |
| UDT struct | Arg that expects a custom struct | Field validation |

### Deliverable

Full type checking against the ABI. Errors at compile time instead of at runtime. The compiler becomes the first line of defense before spending gas.

---

## Phase 11 — Full Execution

**Goal**: Close the loop. Sign and submit real transactions to the network.

### Full Flow

```
.soro -> Compile -> XDR -> Simulate -> Assemble -> Sign -> Submit -> Poll
```

### Tasks

- [ ] Implement `Executor` in `quasar-exec`:
  1. Compile to XDR (reuse Phase 7)
  2. Simulate (reuse Phase 8)
  3. Assemble: apply `SorobanTransactionData` + auth entries from simulation
  4. Sign with provided keypair
  5. Submit via `sendTransaction` RPC
  6. Poll `getTransaction` until `SUCCESS` or `FAILED`
- [ ] Signing options:
  - `--secret-key SK...` (for testing/scripts, with security warning)
  - `--env SORO_SECRET_KEY` (read from env var)
  - (future) `--signer ledger` (hardware wallet)
- [ ] Execution output:
  ```
  Executing call 1/1: CB6...XYZ.transfer()
    Simulating...    OK (fee: 154,331 stroops)
    Signing...       OK
    Submitting...    OK (hash: 7a8b9c...)
    Waiting...       SUCCESS (ledger: 1234567)
    Return value:    void

  Transaction: 7a8b9c...
  Explorer:    https://stellar.expert/explorer/testnet/tx/7a8b9c...
  ```
- [ ] Post-submission error handling:
  - `FAILED`: display the error from the transaction result XDR
  - `TRY_AGAIN_LATER`: automatic retry with backoff
  - `DUPLICATE`: inform that it was already submitted
- [ ] New CLI command: `quasar run input.soro --secret-key SK...`
- [ ] Interactive confirmation before submitting on mainnet:
  ```
  WARNING: This will submit 2 transactions to MAINNET
  Estimated total fee: 308,662 stroops (0.0308662 XLM)
  Continue? [y/N]
  ```
- [ ] Multiple calls are executed sequentially (each one is a separate transaction, since Stellar only allows one `InvokeHostFunctionOp` per tx)

### Tests

| Test | Scenario | Expected Result |
|------|----------|-----------------|
| Testnet transfer | Token transfer between two test accounts | SUCCESS + verifiable balance |
| Nonexistent contract | Call to a contract that doesn't exist | Clear error from simulator before sending |
| Insufficient funds | Transfer more than the account holds | Simulator error |
| Multiple calls | Script with 2 calls | Both executed sequentially |
| Mainnet confirmation | `--network mainnet` | Confirmation prompt |
| Invalid secret key | `--secret-key INVALID` | Error before attempting to sign |
| Polling timeout | Transaction not included in ledger | Clear timeout after N seconds |
| JSON output | `--json` flag | Full result in JSON |
| Dry run | `--dry-run` flag | Only simulates, doesn't submit |
| Explorer link | Successful execution | Correct explorer link |

### Deliverable

Full cycle: `.soro` -> Stellar network. The user can write a script, simulate it, and execute it with a single command.

---

## Backlog (post v1.0)

Ideas for the future, with no defined priority:

- **LSP (Language Server Protocol)**: autocomplete, hover docs, go-to-definition in VS Code
- **Interactive REPL**: `quasar repl --network testnet` to explore contracts
- **Batch optimization**: detect calls to the same contract and suggest contract-to-contract calls
- **Watch mode**: `quasar watch script.soro` recompiles on save
- **Plugin system**: pre/post execution hooks
- **Web playground**: compile to WASM, run in the browser

---

## Phase Summary

| Phase | Name | New Crate Deps | Output |
|-------|------|----------------|--------|
| 0 | Scaffolding | `insta` | Ready workspace |
| 1 | Lexer | none | Token stream |
| 2 | Parser + AST | none | Typed AST |
| 3 | Semantic Validation | none | Diagnostics |
| 4 | JSON Compiler | `serde`, `serde_json` | JSON IR |
| 5 | CLI | `clap`, `termcolor` | Usable binary |
| 6 | Constants | none | `const` keyword |
| 7 | XDR Compiler | `stellar-xdr`, `stellar-strkey` | Base64 XDR |
| 8 | Simulation | `soroban-client` or `reqwest` | Dry-run |
| 9 | ABI Import | `wasmparser` | `.soroabi` files |
| 10 | Type Checking | none | Type errors |
| 11 | Execution | `soroban-client` | Real transactions |
