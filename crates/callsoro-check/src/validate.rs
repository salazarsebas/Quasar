use callsoro_syntax::ast::{Call, Directive, Program, Value};
use callsoro_syntax::span::Span;
use std::collections::HashSet;
use std::fmt;

use crate::strkey::{validate_strkey, StrKeyKind};

// ---------------------------------------------------------------------------
// Diagnostic types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub span: Span,
    pub help: Option<String>,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at line {}, col {}: {}",
            self.severity, self.span.line, self.span.col, self.message
        )
    }
}

impl Diagnostic {
    pub fn error(message: impl Into<String>, span: Span) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            span,
            help: None,
        }
    }

    pub fn warning(message: impl Into<String>, span: Span) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
            span,
            help: None,
        }
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn format_with_source(&self, source: &str) -> String {
        let line_content = source.lines().nth(self.span.line - 1).unwrap_or("");
        let col = self.span.col;
        let underline_len = if self.span.end > self.span.start {
            self.span.end - self.span.start
        } else {
            1
        };

        let mut out = format!(
            "{}: {}\n --> line {}:{}\n  |\n{} | {}\n  | {}{}",
            self.severity,
            self.message,
            self.span.line,
            col,
            self.span.line,
            line_content,
            " ".repeat(col - 1),
            "^".repeat(underline_len),
        );

        if let Some(help) = &self.help {
            out.push_str(&format!("\n  = help: {}", help));
        }
        out.push('\n');
        out
    }
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

pub struct Validator;

const VALID_NETWORKS: &[&str] = &["testnet", "mainnet", "futurenet"];

impl Validator {
    pub fn validate(program: &Program) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        Self::check_directives(program, &mut diagnostics);
        Self::check_calls(program, &mut diagnostics);

        diagnostics
    }

    // -- Directive validation -----------------------------------------------

    fn check_directives(program: &Program, diags: &mut Vec<Diagnostic>) {
        let mut seen = HashSet::new();

        for directive in &program.directives {
            let name = directive.name();

            // Duplicate check
            if !seen.insert(name) {
                diags.push(Diagnostic::error(
                    format!("duplicate directive '{}'", name),
                    directive.span(),
                ));
                continue;
            }

            match directive {
                Directive::Network { value, span } => {
                    Self::check_network(value, *span, diags);
                }
                Directive::Source { value, span } => {
                    Self::check_source_address(value, *span, diags);
                }
                Directive::Fee { value, span } => {
                    Self::check_fee(*value, *span, diags);
                }
                Directive::Timeout { value, span } => {
                    Self::check_timeout(*value, *span, diags);
                }
            }
        }

        // Required directives
        let has_network = program
            .directives
            .iter()
            .any(|d| matches!(d, Directive::Network { .. }));
        let has_source = program
            .directives
            .iter()
            .any(|d| matches!(d, Directive::Source { .. }));

        let fallback_span = Span::new(0, 0, 1, 1);

        if !has_network {
            diags.push(
                Diagnostic::error("missing required directive 'network'", fallback_span)
                    .with_help("add `network testnet` or `network mainnet` at the top of the file"),
            );
        }
        if !has_source {
            diags.push(
                Diagnostic::error("missing required directive 'source'", fallback_span).with_help(
                    "add `source G...` with your Stellar account address at the top of the file",
                ),
            );
        }
    }

    fn check_network(value: &str, span: Span, diags: &mut Vec<Diagnostic>) {
        if !VALID_NETWORKS.contains(&value) {
            // Allow network passphrase strings (they contain spaces typically)
            if !value.contains(' ') {
                diags.push(
                    Diagnostic::error(
                        format!(
                            "unknown network '{}' (expected 'testnet', 'mainnet', 'futurenet', or a network passphrase)",
                            value
                        ),
                        span,
                    )
                    .with_help("use 'testnet', 'mainnet', 'futurenet', or a full network passphrase string"),
                );
            }
        }
    }

    fn check_source_address(address: &str, span: Span, diags: &mut Vec<Diagnostic>) {
        match validate_strkey(address) {
            Ok(StrKeyKind::AccountId) => {} // correct
            Ok(StrKeyKind::Contract) => {
                diags.push(
                    Diagnostic::error(
                        "source must be an account address (G...), got a contract address (C...)",
                        span,
                    )
                    .with_help("the source directive requires a Stellar account (starts with G)"),
                );
            }
            Err(e) => {
                diags.push(
                    Diagnostic::error(format!("invalid source address: {}", e), span).with_help(
                        "addresses start with G (accounts) or C (contracts) and are 56 characters with a CRC16 checksum",
                    ),
                );
            }
        }
    }

    fn check_fee(value: u64, span: Span, diags: &mut Vec<Diagnostic>) {
        if value < 100 {
            diags.push(
                Diagnostic::warning(
                    format!(
                        "fee {} stroops is unusually low (minimum base fee is 100)",
                        value
                    ),
                    span,
                )
                .with_help("the minimum base fee on Stellar is 100 stroops"),
            );
        } else if value > 10_000_000 {
            diags.push(
                Diagnostic::warning(format!("fee {} stroops is unusually high", value), span)
                    .with_help("fees above 10,000,000 stroops (1 XLM) may indicate an error"),
            );
        }
    }

    fn check_timeout(value: u64, span: Span, diags: &mut Vec<Diagnostic>) {
        if value < 10 {
            diags.push(
                Diagnostic::warning(
                    format!("timeout {} seconds is unusually low", value),
                    span,
                )
                .with_help("a timeout below 10 seconds may cause the transaction to expire before submission"),
            );
        } else if value > 300 {
            diags.push(
                Diagnostic::warning(format!("timeout {} seconds is unusually high", value), span)
                    .with_help(
                        "a timeout above 300 seconds (5 minutes) may allow stale transactions",
                    ),
            );
        }
    }

    // -- Call validation ----------------------------------------------------

    fn check_calls(program: &Program, diags: &mut Vec<Diagnostic>) {
        if program.calls.is_empty() {
            let fallback_span = Span::new(0, 0, 1, 1);
            diags.push(Diagnostic::warning(
                "script has no call statements",
                fallback_span,
            ));
        }

        for call in &program.calls {
            Self::check_call(call, diags);
        }
    }

    fn check_call(call: &Call, diags: &mut Vec<Diagnostic>) {
        // Contract address must be C...
        match validate_strkey(&call.contract) {
            Ok(StrKeyKind::Contract) => {} // correct
            Ok(StrKeyKind::AccountId) => {
                diags.push(
                    Diagnostic::error(
                        "expected contract address (C...), got account address (G...)",
                        call.span,
                    )
                    .with_help("contract addresses start with C, account addresses start with G"),
                );
            }
            Err(e) => {
                diags.push(
                    Diagnostic::error(format!("invalid contract address: {}", e), call.span)
                        .with_help(
                            "contract addresses start with C and are 56 characters with a CRC16 checksum",
                        ),
                );
            }
        }

        // Validate each argument value
        for arg in &call.args {
            Self::check_value(arg, diags);
        }
    }

    // -- Value validation ---------------------------------------------------

    fn check_value(value: &Value, diags: &mut Vec<Diagnostic>) {
        match value {
            Value::U128(s, span) => Self::check_u128(s, *span, diags),
            Value::I128(s, span) => Self::check_i128(s, *span, diags),
            Value::U256(s, span) => Self::check_u256(s, *span, diags),
            Value::I256(s, span) => Self::check_i256(s, *span, diags),
            Value::Bytes(s, span) => Self::check_bytes(s, *span, diags),
            Value::Symbol(s, span) => Self::check_symbol(s, *span, diags),
            Value::Address(s, span) => Self::check_address(s, *span, diags),
            Value::Vec(items, _) => {
                for item in items {
                    Self::check_value(item, diags);
                }
            }
            Value::Map(entries, _) => {
                for entry in entries {
                    Self::check_value(&entry.key, diags);
                    Self::check_value(&entry.value, diags);
                }
            }
            // Bool, U32, I32, U64, I64, String are already validated at parse time
            _ => {}
        }
    }

    fn check_u128(s: &str, span: Span, diags: &mut Vec<Diagnostic>) {
        if s.parse::<u128>().is_err() {
            diags.push(
                Diagnostic::error(format!("'{}' is not a valid u128 value", s), span).with_help(
                    "u128 values must be between 0 and 340282366920938463463374607431768211455",
                ),
            );
        }
    }

    fn check_i128(s: &str, span: Span, diags: &mut Vec<Diagnostic>) {
        if s.parse::<i128>().is_err() {
            diags.push(
                Diagnostic::error(format!("'{}' is not a valid i128 value", s), span).with_help(
                    "i128 values must be between -170141183460469231731687303715884105728 and 170141183460469231731687303715884105727",
                ),
            );
        }
    }

    fn check_u256(s: &str, span: Span, diags: &mut Vec<Diagnostic>) {
        // u256 doesn't have a native Rust type; validate it's a non-negative integer
        // that fits in 256 bits (max: 2^256 - 1)
        if s.starts_with('-') {
            diags.push(
                Diagnostic::error("u256 value cannot be negative", span)
                    .with_help("u256 values must be non-negative"),
            );
            return;
        }
        // Check it's composed of digits only
        if !s.chars().all(|c| c.is_ascii_digit()) || s.is_empty() {
            diags.push(
                Diagnostic::error(format!("'{}' is not a valid u256 value", s), span)
                    .with_help("u256 values must be non-negative integers"),
            );
            return;
        }
        // Check range: must be <= 2^256 - 1
        let max_u256 =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        if !fits_in_decimal_range(s, max_u256) {
            diags.push(
                Diagnostic::error("value exceeds u256 range", span)
                    .with_help("u256 max is 2^256 - 1"),
            );
        }
    }

    fn check_i256(s: &str, span: Span, diags: &mut Vec<Diagnostic>) {
        // i256 doesn't have a native Rust type; validate it's an integer in [-2^255, 2^255 - 1]
        let (is_negative, digits) = if let Some(stripped) = s.strip_prefix('-') {
            (true, stripped)
        } else {
            (false, s)
        };

        if !digits.chars().all(|c| c.is_ascii_digit()) || digits.is_empty() {
            diags.push(
                Diagnostic::error(format!("'{}' is not a valid i256 value", s), span)
                    .with_help("i256 values must be integers"),
            );
            return;
        }

        let max_positive =
            "57896044618658097711785492504343953926634992332820282019728792003956564819967";
        let max_negative =
            "57896044618658097711785492504343953926634992332820282019728792003956564819968";

        let limit = if is_negative {
            max_negative
        } else {
            max_positive
        };

        if !fits_in_decimal_range(digits, limit) {
            diags.push(
                Diagnostic::error("value exceeds i256 range", span)
                    .with_help("i256 range is -2^255 to 2^255 - 1"),
            );
        }
    }

    fn check_bytes(s: &str, span: Span, diags: &mut Vec<Diagnostic>) {
        let hex = if let Some(stripped) = s.strip_prefix("0x") {
            stripped
        } else {
            diags.push(
                Diagnostic::error("bytes value must start with '0x'", span)
                    .with_help("hex byte strings must begin with 0x, e.g. bytes(\"0xdeadbeef\")"),
            );
            return;
        };

        if hex.is_empty() {
            // 0x alone is valid (empty bytes)
            return;
        }

        if hex.len() % 2 != 0 {
            diags.push(
                Diagnostic::error("hex bytes must have even length", span)
                    .with_help("each byte is two hex digits; pad with a leading zero if needed"),
            );
        }

        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            diags.push(
                Diagnostic::error("invalid hex characters in bytes value", span)
                    .with_help("hex strings may only contain 0-9 and a-f/A-F"),
            );
        }
    }

    fn check_symbol(s: &str, span: Span, diags: &mut Vec<Diagnostic>) {
        if s.len() > 32 {
            diags.push(
                Diagnostic::error(
                    format!("symbol '{}' exceeds 32 characters ({} chars)", s, s.len()),
                    span,
                )
                .with_help("Soroban symbols must be at most 32 characters"),
            );
        }

        if let Some(ch) = s
            .chars()
            .find(|c| !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_'))
        {
            diags.push(
                Diagnostic::error(
                    format!("invalid symbol character '{}'", ch),
                    span,
                )
                .with_help("symbols may only contain letters (a-z, A-Z), digits (0-9), and underscores (_)"),
            );
        }
    }

    fn check_address(s: &str, span: Span, diags: &mut Vec<Diagnostic>) {
        if let Err(e) = validate_strkey(s) {
            diags.push(
                Diagnostic::error(format!("invalid address: {}", e), span).with_help(
                    "addresses start with G (accounts) or C (contracts) and are 56 characters with a CRC16 checksum",
                ),
            );
        }
    }
}

/// Compare two non-negative decimal number strings: returns true if `value` <= `max`.
fn fits_in_decimal_range(value: &str, max: &str) -> bool {
    let value = value.trim_start_matches('0');
    let max = max.trim_start_matches('0');

    if value.is_empty() {
        return true; // zero always fits
    }

    match value.len().cmp(&max.len()) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => value <= max,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use callsoro_syntax::ast::{Call, Directive, MapEntry, Program, Value};
    use callsoro_syntax::span::Span;

    // Valid addresses with correct CRC16 checksums (generated from deterministic payloads).
    const ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
    // Bad checksum: valid base32, starts with G, 56 chars, but wrong CRC16
    const BAD_CHECKSUM: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn sp(line: usize, col: usize, start: usize, end: usize) -> Span {
        Span::new(start, end, line, col)
    }

    /// Helper to create a valid minimal program.
    fn valid_program() -> Program {
        Program {
            directives: vec![
                Directive::Network {
                    value: "testnet".to_string(),
                    span: sp(1, 1, 0, 15),
                },
                Directive::Source {
                    value: ACCOUNT.to_string(),
                    span: sp(2, 1, 16, 80),
                },
            ],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "transfer".to_string(),
                args: vec![],
                span: sp(3, 1, 81, 150),
            }],
        }
    }

    // -- Valid scripts -------------------------------------------------------

    #[test]
    fn valid_complete_script() {
        let program = valid_program();
        let diags = Validator::validate(&program);
        assert!(
            diags.is_empty(),
            "expected no diagnostics, got: {:?}",
            diags
        );
    }

    #[test]
    fn valid_with_all_types() {
        let s = sp(1, 1, 0, 10);
        let program = Program {
            directives: vec![
                Directive::Network {
                    value: "testnet".to_string(),
                    span: s,
                },
                Directive::Source {
                    value: ACCOUNT.to_string(),
                    span: s,
                },
            ],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "test".to_string(),
                args: vec![
                    Value::Bool(true, s),
                    Value::U32(42, s),
                    Value::I32(-1, s),
                    Value::U64(1_000_000, s),
                    Value::I64(-1, s),
                    Value::U128("340282366920938463463374607431768211455".to_string(), s),
                    Value::I128("-170141183460469231731687303715884105728".to_string(), s),
                    Value::U256("0".to_string(), s),
                    Value::I256("0".to_string(), s),
                    Value::String("hello".to_string(), s),
                    Value::Symbol("transfer".to_string(), s),
                    Value::Bytes("0xdeadbeef".to_string(), s),
                    Value::Address(ACCOUNT.to_string(), s),
                    Value::Address(CONTRACT.to_string(), s),
                    Value::Vec(vec![Value::U32(1, s)], s),
                    Value::Map(
                        vec![MapEntry {
                            key: Value::Symbol("a".to_string(), s),
                            value: Value::U32(1, s),
                        }],
                        s,
                    ),
                ],
                span: s,
            }],
        };
        let diags = Validator::validate(&program);
        assert!(
            diags.is_empty(),
            "expected no diagnostics, got: {:?}",
            diags
        );
    }

    // -- Missing directives --------------------------------------------------

    #[test]
    fn missing_network() {
        let program = Program {
            directives: vec![Directive::Source {
                value: ACCOUNT.to_string(),
                span: sp(1, 1, 0, 10),
            }],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "test".to_string(),
                args: vec![],
                span: sp(2, 1, 11, 80),
            }],
        };
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].severity, Severity::Error);
        assert!(diags[0]
            .message
            .contains("missing required directive 'network'"));
    }

    #[test]
    fn missing_source() {
        let program = Program {
            directives: vec![Directive::Network {
                value: "testnet".to_string(),
                span: sp(1, 1, 0, 15),
            }],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "test".to_string(),
                args: vec![],
                span: sp(2, 1, 16, 80),
            }],
        };
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0]
            .message
            .contains("missing required directive 'source'"));
    }

    // -- Duplicate directives ------------------------------------------------

    #[test]
    fn duplicate_network() {
        let mut program = valid_program();
        program.directives.push(Directive::Network {
            value: "mainnet".to_string(),
            span: sp(5, 1, 200, 215),
        });
        let diags = Validator::validate(&program);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("duplicate directive 'network'"));
    }

    #[test]
    fn duplicate_source() {
        let mut program = valid_program();
        program.directives.push(Directive::Source {
            value: ACCOUNT.to_string(),
            span: sp(5, 1, 200, 260),
        });
        let diags = Validator::validate(&program);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("duplicate directive 'source'"));
    }

    // -- Invalid network -----------------------------------------------------

    #[test]
    fn invalid_network() {
        let program = Program {
            directives: vec![
                Directive::Network {
                    value: "devnet".to_string(),
                    span: sp(1, 1, 0, 14),
                },
                Directive::Source {
                    value: ACCOUNT.to_string(),
                    span: sp(2, 1, 15, 80),
                },
            ],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "test".to_string(),
                args: vec![],
                span: sp(3, 1, 81, 150),
            }],
        };
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("unknown network 'devnet'"));
    }

    #[test]
    fn valid_network_passphrase() {
        let program = Program {
            directives: vec![
                Directive::Network {
                    value: "Test SDF Network ; September 2015".to_string(),
                    span: sp(1, 1, 0, 40),
                },
                Directive::Source {
                    value: ACCOUNT.to_string(),
                    span: sp(2, 1, 41, 105),
                },
            ],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "test".to_string(),
                args: vec![],
                span: sp(3, 1, 106, 170),
            }],
        };
        let diags = Validator::validate(&program);
        assert!(
            diags.is_empty(),
            "passphrase should be accepted: {:?}",
            diags
        );
    }

    // -- Source address validation --------------------------------------------

    #[test]
    fn source_is_contract_address() {
        let program = Program {
            directives: vec![
                Directive::Network {
                    value: "testnet".to_string(),
                    span: sp(1, 1, 0, 15),
                },
                Directive::Source {
                    value: CONTRACT.to_string(),
                    span: sp(2, 1, 16, 80),
                },
            ],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "test".to_string(),
                args: vec![],
                span: sp(3, 1, 81, 150),
            }],
        };
        let diags = Validator::validate(&program);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0]
            .message
            .contains("source must be an account address"));
    }

    #[test]
    fn source_bad_checksum() {
        let program = Program {
            directives: vec![
                Directive::Network {
                    value: "testnet".to_string(),
                    span: sp(1, 1, 0, 15),
                },
                Directive::Source {
                    value: BAD_CHECKSUM.to_string(),
                    span: sp(2, 1, 16, 80),
                },
            ],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "test".to_string(),
                args: vec![],
                span: sp(3, 1, 81, 150),
            }],
        };
        let diags = Validator::validate(&program);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("invalid source address"));
    }

    // -- Contract address validation -----------------------------------------

    #[test]
    fn contract_is_account_address() {
        let program = Program {
            directives: vec![
                Directive::Network {
                    value: "testnet".to_string(),
                    span: sp(1, 1, 0, 15),
                },
                Directive::Source {
                    value: ACCOUNT.to_string(),
                    span: sp(2, 1, 16, 80),
                },
            ],
            calls: vec![Call {
                contract: ACCOUNT.to_string(),
                method: "transfer".to_string(),
                args: vec![],
                span: sp(3, 1, 81, 150),
            }],
        };
        let diags = Validator::validate(&program);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0]
            .message
            .contains("expected contract address (C...), got account address (G...)"));
    }

    // -- Fee and timeout warnings --------------------------------------------

    #[test]
    fn fee_too_low() {
        let mut program = valid_program();
        program.directives.push(Directive::Fee {
            value: 50,
            span: sp(3, 1, 81, 87),
        });
        let diags = Validator::validate(&program);
        let warnings: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("unusually low"));
    }

    #[test]
    fn fee_too_high() {
        let mut program = valid_program();
        program.directives.push(Directive::Fee {
            value: 50_000_000,
            span: sp(3, 1, 81, 95),
        });
        let diags = Validator::validate(&program);
        let warnings: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("unusually high"));
    }

    #[test]
    fn timeout_too_low() {
        let mut program = valid_program();
        program.directives.push(Directive::Timeout {
            value: 5,
            span: sp(3, 1, 81, 90),
        });
        let diags = Validator::validate(&program);
        let warnings: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("unusually low"));
    }

    #[test]
    fn timeout_too_high() {
        let mut program = valid_program();
        program.directives.push(Directive::Timeout {
            value: 600,
            span: sp(3, 1, 81, 92),
        });
        let diags = Validator::validate(&program);
        let warnings: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("unusually high"));
    }

    // -- No calls warning ----------------------------------------------------

    #[test]
    fn no_calls_warning() {
        let program = Program {
            directives: vec![
                Directive::Network {
                    value: "testnet".to_string(),
                    span: sp(1, 1, 0, 15),
                },
                Directive::Source {
                    value: ACCOUNT.to_string(),
                    span: sp(2, 1, 16, 80),
                },
            ],
            calls: vec![],
        };
        let diags = Validator::validate(&program);
        let warnings: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("no call statements"));
    }

    // -- u128 / i128 validation ----------------------------------------------

    #[test]
    fn valid_u128() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::U128(
            "340282366920938463463374607431768211455".to_string(),
            s,
        ));
        let diags = Validator::validate(&program);
        assert!(diags.is_empty());
    }

    #[test]
    fn invalid_u128_overflow() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::U128(
            "340282366920938463463374607431768211456".to_string(),
            s,
        ));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("not a valid u128"));
    }

    #[test]
    fn invalid_u128_not_a_number() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::U128("abc".to_string(), s));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("not a valid u128"));
    }

    #[test]
    fn valid_i128() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::I128(
            "-170141183460469231731687303715884105728".to_string(),
            s,
        ));
        let diags = Validator::validate(&program);
        assert!(diags.is_empty());
    }

    #[test]
    fn invalid_i128() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::I128("abc".to_string(), s));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("not a valid i128"));
    }

    // -- u256 / i256 validation ----------------------------------------------

    #[test]
    fn valid_u256_zero() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::U256("0".to_string(), s));
        let diags = Validator::validate(&program);
        assert!(diags.is_empty());
    }

    #[test]
    fn valid_u256_max() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::U256(
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
                .to_string(),
            s,
        ));
        let diags = Validator::validate(&program);
        assert!(diags.is_empty());
    }

    #[test]
    fn invalid_u256_overflow() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::U256(
            "115792089237316195423570985008687907853269984665640564039457584007913129639936"
                .to_string(),
            s,
        ));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("exceeds u256 range"));
    }

    #[test]
    fn invalid_u256_negative() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::U256("-1".to_string(), s));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("cannot be negative"));
    }

    #[test]
    fn valid_i256() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::I256("0".to_string(), s));
        let diags = Validator::validate(&program);
        assert!(diags.is_empty());
    }

    #[test]
    fn invalid_i256_overflow() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::I256(
            "57896044618658097711785492504343953926634992332820282019728792003956564819968"
                .to_string(),
            s,
        ));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("exceeds i256 range"));
    }

    // -- Bytes validation ----------------------------------------------------

    #[test]
    fn valid_bytes() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Bytes("0xdeadbeef".to_string(), s));
        let diags = Validator::validate(&program);
        assert!(diags.is_empty());
    }

    #[test]
    fn valid_empty_bytes() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Bytes("0x".to_string(), s));
        let diags = Validator::validate(&program);
        assert!(diags.is_empty());
    }

    #[test]
    fn bytes_missing_prefix() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Bytes("deadbeef".to_string(), s));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("must start with '0x'"));
    }

    #[test]
    fn bytes_odd_length() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Bytes("0xabc".to_string(), s));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("even length"));
    }

    #[test]
    fn bytes_invalid_hex() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Bytes("0xZZZZ".to_string(), s));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("invalid hex characters"));
    }

    // -- Symbol validation ---------------------------------------------------

    #[test]
    fn valid_symbol() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Symbol("transfer".to_string(), s));
        let diags = Validator::validate(&program);
        assert!(diags.is_empty());
    }

    #[test]
    fn symbol_too_long() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::Symbol("a".repeat(33), s));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("exceeds 32 characters"));
    }

    #[test]
    fn symbol_invalid_char() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Symbol("a]b".to_string(), s));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("invalid symbol character"));
    }

    // -- Address validation --------------------------------------------------

    #[test]
    fn valid_address_account() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Address(ACCOUNT.to_string(), s));
        let diags = Validator::validate(&program);
        assert!(diags.is_empty());
    }

    #[test]
    fn valid_address_contract() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Address(CONTRACT.to_string(), s));
        let diags = Validator::validate(&program);
        assert!(diags.is_empty());
    }

    #[test]
    fn invalid_address_bad_checksum() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Address(BAD_CHECKSUM.to_string(), s));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("invalid address"));
    }

    // -- Nested validation ---------------------------------------------------

    #[test]
    fn nested_vec_validates_children() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0]
            .args
            .push(Value::Vec(vec![Value::U128("abc".to_string(), s)], s));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("not a valid u128"));
    }

    #[test]
    fn nested_map_validates_keys_and_values() {
        let s = sp(1, 1, 0, 10);
        let mut program = valid_program();
        program.calls[0].args.push(Value::Map(
            vec![MapEntry {
                key: Value::Symbol("a]b".to_string(), s),
                value: Value::Bytes("0xZZ".to_string(), s),
            }],
            s,
        ));
        let diags = Validator::validate(&program);
        assert_eq!(diags.len(), 2); // invalid symbol + invalid hex
    }

    // -- Diagnostic formatting -----------------------------------------------

    #[test]
    fn diagnostic_format_with_source() {
        let source =
            "network testnet\nsource  GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let diag = Diagnostic::error(
            "invalid source address: invalid CRC16 checksum",
            sp(2, 9, 25, 81),
        )
        .with_help("addresses start with G (accounts) or C (contracts)");
        let formatted = diag.format_with_source(source);
        assert!(formatted.contains("error:"));
        assert!(formatted.contains("invalid source address"));
        assert!(formatted.contains("help:"));
    }

    // -- fits_in_decimal_range helper ----------------------------------------

    #[test]
    fn decimal_range_basic() {
        assert!(fits_in_decimal_range("0", "255"));
        assert!(fits_in_decimal_range("255", "255"));
        assert!(!fits_in_decimal_range("256", "255"));
        assert!(fits_in_decimal_range("100", "1000"));
        assert!(!fits_in_decimal_range("1001", "1000"));
    }

    #[test]
    fn decimal_range_leading_zeros() {
        assert!(fits_in_decimal_range("000", "255"));
        assert!(fits_in_decimal_range("00255", "255"));
    }
}
