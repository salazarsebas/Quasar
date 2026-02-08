//! Compile-time type checking of interface calls against imported ABIs.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use callsoro_syntax::ast::{Program, Value};
use callsoro_syntax::span::Span;

// ---------------------------------------------------------------------------
// Minimal ABI types (duplicated from callsoro-exec to avoid heavy deps)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ContractAbi {
    pub contract_id: String,
    pub functions: Vec<AbiFunction>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbiFunction {
    pub name: String,
    pub inputs: Vec<AbiFunctionInput>,
    pub outputs: Vec<AbiTypeRef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbiFunctionInput {
    pub name: String,
    pub type_ref: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbiTypeRef {
    pub type_ref: String,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeCheckError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for TypeCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "type error at line {}, col {}: {}",
            self.span.line, self.span.col, self.message
        )
    }
}

impl TypeCheckError {
    pub fn format_with_source(&self, source: &str) -> String {
        let line_content = source.lines().nth(self.span.line - 1).unwrap_or("");
        let col = self.span.col;
        let underline_len = if self.span.end > self.span.start {
            self.span.end - self.span.start
        } else {
            1
        };

        format!(
            "type error: {}\n --> line {}:{}\n  |\n{} | {}\n  | {}{}\n",
            self.message,
            self.span.line,
            col,
            self.span.line,
            line_content,
            " ".repeat(col - 1),
            "^".repeat(underline_len),
        )
    }
}

// ---------------------------------------------------------------------------
// TypeChecker
// ---------------------------------------------------------------------------

pub struct TypeChecker {
    abis: HashMap<String, ContractAbi>,
}

impl TypeChecker {
    pub fn new() -> Self {
        TypeChecker {
            abis: HashMap::new(),
        }
    }

    /// Get the loaded ABI map (for passing to the compiler).
    pub fn abis(&self) -> &HashMap<String, ContractAbi> {
        &self.abis
    }

    /// Load an ABI file and register it under the given alias.
    pub fn load_abi(
        &mut self,
        alias: &str,
        path: &str,
        base_dir: &Path,
    ) -> Result<(), TypeCheckError> {
        let full_path = base_dir.join(path);
        let content = std::fs::read_to_string(&full_path).map_err(|e| TypeCheckError {
            message: format!("cannot read ABI file '{}': {}", full_path.display(), e),
            span: Span::new(0, 0, 1, 1),
        })?;

        let abi: ContractAbi = serde_json::from_str(&content).map_err(|e| TypeCheckError {
            message: format!("invalid ABI file '{}': {}", path, e),
            span: Span::new(0, 0, 1, 1),
        })?;

        self.abis.insert(alias.to_string(), abi);
        Ok(())
    }

    /// Load an ABI directly (for testing without filesystem).
    pub fn load_abi_direct(&mut self, alias: &str, abi: ContractAbi) {
        self.abis.insert(alias.to_string(), abi);
    }

    /// Check all interface calls in the program against loaded ABIs.
    pub fn check_program(&self, program: &Program) -> Vec<TypeCheckError> {
        let mut errors = Vec::new();

        for call in &program.calls {
            let alias = match &call.interface {
                Some(a) => a,
                None => continue, // Traditional calls are not type-checked
            };

            let abi = match self.abis.get(alias) {
                Some(a) => a,
                None => {
                    errors.push(TypeCheckError {
                        message: format!("unknown interface '{}'", alias),
                        span: call.span,
                    });
                    continue;
                }
            };

            // Find the method
            let func = abi.functions.iter().find(|f| f.name == call.method);
            match func {
                None => {
                    let suggestion = suggest_method(&call.method, &abi.functions);
                    let msg = if let Some(s) = suggestion {
                        format!(
                            "method '{}' not found in interface '{}'; did you mean '{}'?",
                            call.method, alias, s
                        )
                    } else {
                        format!(
                            "method '{}' not found in interface '{}'",
                            call.method, alias
                        )
                    };
                    errors.push(TypeCheckError {
                        message: msg,
                        span: call.span,
                    });
                }
                Some(func) => {
                    // Check arity
                    let expected = func.inputs.len();
                    let actual = call.args.len();
                    if expected != actual {
                        errors.push(TypeCheckError {
                            message: format!(
                                "method '{}' expects {} argument{}, got {}",
                                call.method,
                                expected,
                                if expected == 1 { "" } else { "s" },
                                actual
                            ),
                            span: call.span,
                        });
                    } else {
                        // Check type compatibility for each argument
                        for (i, (arg, input)) in
                            call.args.iter().zip(func.inputs.iter()).enumerate()
                        {
                            if !is_type_compatible(arg, &input.type_ref) {
                                errors.push(TypeCheckError {
                                    message: format!(
                                        "argument {} ('{}') expects type '{}', got {}",
                                        i + 1,
                                        input.name,
                                        input.type_ref,
                                        value_type_name(arg)
                                    ),
                                    span: arg.span(),
                                });
                            }
                        }
                    }
                }
            }
        }

        errors
    }
}

impl Default for TypeChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Type compatibility
// ---------------------------------------------------------------------------

fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Bool(_, _) => "bool",
        Value::U32(_, _) => "u32",
        Value::I32(_, _) => "i32",
        Value::U64(_, _) => "u64",
        Value::I64(_, _) => "i64",
        Value::U128(_, _) => "u128",
        Value::I128(_, _) => "i128",
        Value::U256(_, _) => "u256",
        Value::I256(_, _) => "i256",
        Value::String(_, _) => "string",
        Value::Symbol(_, _) => "symbol",
        Value::Bytes(_, _) => "bytes",
        Value::Address(_, _) => "address",
        Value::Vec(_, _) => "vec",
        Value::Map(_, _) => "map",
        Value::Ident(_, _) => "unknown",
    }
}

fn is_type_compatible(value: &Value, expected: &str) -> bool {
    // Generic `val` type accepts anything
    if expected == "val" {
        return true;
    }

    match value {
        Value::Bool(_, _) => expected == "bool",
        Value::U32(_, _) => matches!(
            expected,
            "u32" | "i32" | "u64" | "i64" | "u128" | "i128" | "u256" | "i256"
        ),
        Value::I32(_, _) => matches!(
            expected,
            "i32" | "i64" | "i128" | "i256" | "u32" | "u64" | "u128" | "u256"
        ),
        Value::U64(_, _) => matches!(
            expected,
            "u64" | "i64" | "u128" | "i128" | "u256" | "i256" | "u32" | "i32"
        ),
        Value::I64(_, _) => matches!(
            expected,
            "i64" | "i128" | "i256" | "u64" | "u128" | "u256" | "u32" | "i32"
        ),
        Value::U128(_, _) => matches!(
            expected,
            "u128" | "i128" | "u256" | "i256" | "u32" | "i32" | "u64" | "i64"
        ),
        Value::I128(_, _) => matches!(
            expected,
            "i128" | "i256" | "u128" | "u256" | "u32" | "i32" | "u64" | "i64"
        ),
        Value::U256(_, _) => matches!(
            expected,
            "u256" | "i256" | "u128" | "i128" | "u32" | "i32" | "u64" | "i64"
        ),
        Value::I256(_, _) => matches!(
            expected,
            "i256" | "u256" | "u128" | "i128" | "u32" | "i32" | "u64" | "i64"
        ),
        Value::String(_, _) => matches!(expected, "string" | "symbol" | "bytes"),
        Value::Symbol(_, _) => matches!(expected, "symbol" | "string"),
        Value::Bytes(_, _) => matches!(expected, "bytes" | "string"),
        Value::Address(_, _) => expected == "address",
        Value::Vec(_, _) => expected.starts_with("vec"),
        Value::Map(_, _) => expected.starts_with("map"),
        // Unknown types (unresolved idents, UDTs) — skip checking
        Value::Ident(_, _) => true,
    }
}

// ---------------------------------------------------------------------------
// Edit distance for suggestions
// ---------------------------------------------------------------------------

fn edit_distance(a: &str, b: &str) -> usize {
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];

    for (i, row) in dp.iter_mut().enumerate().take(m + 1) {
        row[0] = i;
    }
    for (j, val) in dp[0].iter_mut().enumerate().take(n + 1) {
        *val = j;
    }

    for (i, ca) in a.chars().enumerate() {
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            dp[i + 1][j + 1] = (dp[i][j + 1] + 1)
                .min(dp[i + 1][j] + 1)
                .min(dp[i][j] + cost);
        }
    }

    dp[m][n]
}

fn suggest_method(name: &str, functions: &[AbiFunction]) -> Option<String> {
    let mut best: Option<(usize, &str)> = None;

    for func in functions {
        let dist = edit_distance(name, &func.name);
        // Only suggest if reasonably close (at most half the length, minimum 3)
        let threshold = name.len().max(3) / 2 + 1;
        if dist <= threshold && (best.is_none() || dist < best.unwrap().0) {
            best = Some((dist, &func.name));
        }
    }

    best.map(|(_, name)| name.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use callsoro_syntax::ast::{Call, Directive, Program, UseDecl};
    use callsoro_syntax::span::Span;

    const ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    fn sp() -> Span {
        Span::new(0, 10, 1, 1)
    }

    fn token_abi() -> ContractAbi {
        ContractAbi {
            contract_id: CONTRACT.to_string(),
            functions: vec![
                AbiFunction {
                    name: "transfer".to_string(),
                    inputs: vec![
                        AbiFunctionInput {
                            name: "from".to_string(),
                            type_ref: "address".to_string(),
                        },
                        AbiFunctionInput {
                            name: "to".to_string(),
                            type_ref: "address".to_string(),
                        },
                        AbiFunctionInput {
                            name: "amount".to_string(),
                            type_ref: "i128".to_string(),
                        },
                    ],
                    outputs: vec![AbiTypeRef {
                        type_ref: "void".to_string(),
                    }],
                },
                AbiFunction {
                    name: "balance".to_string(),
                    inputs: vec![AbiFunctionInput {
                        name: "id".to_string(),
                        type_ref: "address".to_string(),
                    }],
                    outputs: vec![AbiTypeRef {
                        type_ref: "i128".to_string(),
                    }],
                },
            ],
        }
    }

    fn program_with_interface_call(method: &str, args: Vec<Value>) -> Program {
        Program {
            uses: vec![UseDecl {
                path: "token.soroabi".to_string(),
                alias: "Token".to_string(),
                span: sp(),
            }],
            consts: vec![],
            directives: vec![
                Directive::Network {
                    value: "testnet".to_string(),
                    span: sp(),
                },
                Directive::Source {
                    value: ACCOUNT.to_string(),
                    span: sp(),
                },
            ],
            calls: vec![Call {
                contract: "_".to_string(),
                method: method.to_string(),
                args,
                interface: Some("Token".to_string()),
                span: sp(),
            }],
        }
    }

    #[test]
    fn check_valid_interface_call() {
        let mut checker = TypeChecker::new();
        checker.load_abi_direct("Token", token_abi());

        let program = program_with_interface_call(
            "transfer",
            vec![
                Value::Address(ACCOUNT.to_string(), sp()),
                Value::Address(ACCOUNT.to_string(), sp()),
                Value::I128("1000".to_string(), sp()),
            ],
        );

        let errors = checker.check_program(&program);
        assert!(errors.is_empty(), "expected no errors, got: {:?}", errors);
    }

    #[test]
    fn check_unknown_method() {
        let mut checker = TypeChecker::new();
        checker.load_abi_direct("Token", token_abi());

        let program = program_with_interface_call("trasfer", vec![]);

        let errors = checker.check_program(&program);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("not found"));
        assert!(errors[0].message.contains("did you mean 'transfer'"));
    }

    #[test]
    fn check_completely_unknown_method() {
        let mut checker = TypeChecker::new();
        checker.load_abi_direct("Token", token_abi());

        let program = program_with_interface_call("zzzzzzzzzzzzz", vec![]);

        let errors = checker.check_program(&program);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("not found"));
        assert!(!errors[0].message.contains("did you mean"));
    }

    #[test]
    fn check_wrong_arity() {
        let mut checker = TypeChecker::new();
        checker.load_abi_direct("Token", token_abi());

        let program = program_with_interface_call(
            "transfer",
            vec![
                Value::Address(ACCOUNT.to_string(), sp()),
                Value::Address(ACCOUNT.to_string(), sp()),
            ],
        );

        let errors = checker.check_program(&program);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("expects 3 arguments, got 2"));
    }

    #[test]
    fn check_type_mismatch() {
        let mut checker = TypeChecker::new();
        checker.load_abi_direct("Token", token_abi());

        let program = program_with_interface_call(
            "transfer",
            vec![
                Value::Bool(true, sp()), // should be address
                Value::Address(ACCOUNT.to_string(), sp()),
                Value::I128("1000".to_string(), sp()),
            ],
        );

        let errors = checker.check_program(&program);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("expects type 'address'"));
        assert!(errors[0].message.contains("got bool"));
    }

    #[test]
    fn check_unknown_interface() {
        let checker = TypeChecker::new();

        let program = Program {
            uses: vec![],
            consts: vec![],
            directives: vec![],
            calls: vec![Call {
                contract: "_".to_string(),
                method: "transfer".to_string(),
                args: vec![],
                interface: Some("Foo".to_string()),
                span: sp(),
            }],
        };

        let errors = checker.check_program(&program);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("unknown interface 'Foo'"));
    }

    #[test]
    fn check_non_interface_call_skipped() {
        let checker = TypeChecker::new();

        let program = Program {
            uses: vec![],
            consts: vec![],
            directives: vec![],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "transfer".to_string(),
                args: vec![],
                interface: None,
                span: sp(),
            }],
        };

        let errors = checker.check_program(&program);
        assert!(errors.is_empty());
    }

    #[test]
    fn edit_distance_basic() {
        assert_eq!(edit_distance("", ""), 0);
        assert_eq!(edit_distance("abc", "abc"), 0);
        assert_eq!(edit_distance("abc", "abd"), 1);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("transfer", "trasfer"), 1);
    }

    #[test]
    fn load_abi_file_not_found() {
        let mut checker = TypeChecker::new();
        let result = checker.load_abi("Token", "nonexistent.soroabi", Path::new("."));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cannot read ABI file"));
    }

    #[test]
    fn load_abi_invalid_json() {
        let dir = std::env::temp_dir();
        let path = dir.join("bad_abi.soroabi");
        std::fs::write(&path, "not json").unwrap();

        let mut checker = TypeChecker::new();
        let result = checker.load_abi("Token", "bad_abi.soroabi", &dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("invalid ABI file"));

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn load_abi_from_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_token.soroabi");
        let abi_json = serde_json::to_string(&serde_json::json!({
            "contract_id": CONTRACT,
            "functions": [{
                "name": "transfer",
                "inputs": [{"name": "to", "type_ref": "address"}],
                "outputs": [{"type_ref": "void"}]
            }]
        }))
        .unwrap();
        std::fs::write(&path, &abi_json).unwrap();

        let mut checker = TypeChecker::new();
        let result = checker.load_abi("Token", "test_token.soroabi", &dir);
        assert!(result.is_ok());
        assert!(checker.abis.contains_key("Token"));
        assert_eq!(checker.abis["Token"].functions[0].name, "transfer");

        std::fs::remove_file(path).ok();
    }
}
