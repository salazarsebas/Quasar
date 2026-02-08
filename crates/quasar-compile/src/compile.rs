use std::collections::HashMap;

use quasar_syntax::ast::{Directive, Program, Value};

use crate::ir::{IrCall, IrMapEntry, IrSigning, IrValue, JsonIR};

const DEFAULT_FEE: u64 = 100_000;
const DEFAULT_TIMEOUT: u64 = 30;

/// Compile a validated AST into the JSON IR.
pub struct Compiler;

impl Compiler {
    /// Compile a program without interface resolution (backwards-compatible).
    pub fn compile(program: &Program) -> JsonIR {
        Self::compile_with_abis(program, None)
    }

    /// Compile a program, resolving interface call contract IDs from the ABI map.
    ///
    /// The `abis` map keys are interface aliases (e.g. "Token") and values are
    /// contract IDs (e.g. "CAAA...").
    pub fn compile_with_abis(program: &Program, abis: Option<&HashMap<String, String>>) -> JsonIR {
        let network = Self::extract_network(program);
        let network_passphrase = Self::resolve_passphrase(&network);
        let source = Self::extract_source(program);
        let fee = Self::extract_fee(program);
        let timeout = Self::extract_timeout(program);

        let calls = program
            .calls
            .iter()
            .map(|c| Self::compile_call(c, abis))
            .collect();

        JsonIR {
            version: 1,
            network,
            network_passphrase,
            calls,
            signing: IrSigning {
                source,
                fee_stroops: fee,
                timeout_seconds: timeout,
            },
        }
    }

    fn extract_network(program: &Program) -> String {
        program
            .directives
            .iter()
            .find_map(|d| match d {
                Directive::Network { value, .. } => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    fn extract_source(program: &Program) -> String {
        program
            .directives
            .iter()
            .find_map(|d| match d {
                Directive::Source { value, .. } => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    fn extract_fee(program: &Program) -> u64 {
        program
            .directives
            .iter()
            .find_map(|d| match d {
                Directive::Fee { value, .. } => Some(*value),
                _ => None,
            })
            .unwrap_or(DEFAULT_FEE)
    }

    fn extract_timeout(program: &Program) -> u64 {
        program
            .directives
            .iter()
            .find_map(|d| match d {
                Directive::Timeout { value, .. } => Some(*value),
                _ => None,
            })
            .unwrap_or(DEFAULT_TIMEOUT)
    }

    fn resolve_passphrase(network: &str) -> String {
        match network {
            "testnet" => "Test SDF Network ; September 2015".to_string(),
            "mainnet" => "Public Global Stellar Network ; September 2015".to_string(),
            "futurenet" => "Test SDF Future Network ; October 2022".to_string(),
            // If the user provided a full passphrase string, use it directly
            other => other.to_string(),
        }
    }

    fn compile_call(
        call: &quasar_syntax::ast::Call,
        abis: Option<&HashMap<String, String>>,
    ) -> IrCall {
        // Resolve interface placeholder "_" to real contract ID from ABI map
        let contract = if let Some(alias) = &call.interface {
            abis.and_then(|m| m.get(alias))
                .cloned()
                .unwrap_or_else(|| call.contract.clone())
        } else {
            call.contract.clone()
        };

        IrCall {
            contract,
            method: call.method.clone(),
            args: call.args.iter().map(Self::compile_value).collect(),
        }
    }

    fn compile_value(value: &Value) -> IrValue {
        match value {
            Value::Bool(v, _) => IrValue::Bool(*v),
            Value::U32(v, _) => IrValue::U32(*v),
            Value::I32(v, _) => IrValue::I32(*v),
            Value::U64(v, _) => IrValue::U64(*v),
            Value::I64(v, _) => IrValue::I64(*v),
            Value::U128(v, _) => IrValue::U128(v.clone()),
            Value::I128(v, _) => IrValue::I128(v.clone()),
            Value::U256(v, _) => IrValue::U256(v.clone()),
            Value::I256(v, _) => IrValue::I256(v.clone()),
            Value::String(v, _) => IrValue::String(v.clone()),
            Value::Symbol(v, _) => IrValue::Symbol(v.clone()),
            Value::Bytes(v, _) => IrValue::Bytes(v.clone()),
            Value::Address(v, _) => IrValue::Address(v.clone()),
            Value::Vec(items, _) => IrValue::Vec(items.iter().map(Self::compile_value).collect()),
            Value::Map(entries, _) => IrValue::Map(
                entries
                    .iter()
                    .map(|e| IrMapEntry {
                        key: Self::compile_value(&e.key),
                        value: Self::compile_value(&e.value),
                    })
                    .collect(),
            ),
            Value::Ident(name, _) => {
                unreachable!("unresolved const reference '{}' reached the compiler", name)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quasar_syntax::ast::{Call, Directive, MapEntry, Program, Value};
    use quasar_syntax::span::Span;

    use crate::ir::{IrMapEntry, IrValue};

    const ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    fn sp() -> Span {
        Span::new(0, 1, 1, 1)
    }

    fn full_program() -> Program {
        Program {
            uses: vec![],
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
                Directive::Fee {
                    value: 100_000,
                    span: sp(),
                },
                Directive::Timeout {
                    value: 60,
                    span: sp(),
                },
            ],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "transfer".to_string(),
                args: vec![
                    Value::Address(ACCOUNT.to_string(), sp()),
                    Value::I128("10000000".to_string(), sp()),
                ],
                interface: None,
                span: sp(),
            }],
        }
    }

    // -- Basic compilation ---------------------------------------------------

    #[test]
    fn compile_minimal() {
        let program = Program {
            uses: vec![],
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
                contract: CONTRACT.to_string(),
                method: "transfer".to_string(),
                args: vec![],
                interface: None,
                span: sp(),
            }],
        };
        let ir = Compiler::compile(&program);
        assert_eq!(ir.version, 1);
        assert_eq!(ir.network, "testnet");
        assert_eq!(ir.network_passphrase, "Test SDF Network ; September 2015");
        assert_eq!(ir.calls.len(), 1);
        assert_eq!(ir.calls[0].contract, CONTRACT);
        assert_eq!(ir.calls[0].method, "transfer");
        assert!(ir.calls[0].args.is_empty());
        assert_eq!(ir.signing.source, ACCOUNT);
        assert_eq!(ir.signing.fee_stroops, 100_000); // default
        assert_eq!(ir.signing.timeout_seconds, 30); // default
    }

    #[test]
    fn compile_with_explicit_fee_and_timeout() {
        let ir = Compiler::compile(&full_program());
        assert_eq!(ir.signing.fee_stroops, 100_000);
        assert_eq!(ir.signing.timeout_seconds, 60);
    }

    #[test]
    fn version_field_is_1() {
        let ir = Compiler::compile(&full_program());
        assert_eq!(ir.version, 1);
    }

    // -- Network passphrase --------------------------------------------------

    #[test]
    fn passphrase_testnet() {
        let ir = Compiler::compile(&full_program());
        assert_eq!(ir.network_passphrase, "Test SDF Network ; September 2015");
    }

    #[test]
    fn passphrase_mainnet() {
        let mut program = full_program();
        program.directives[0] = Directive::Network {
            value: "mainnet".to_string(),
            span: sp(),
        };
        let ir = Compiler::compile(&program);
        assert_eq!(
            ir.network_passphrase,
            "Public Global Stellar Network ; September 2015"
        );
    }

    #[test]
    fn passphrase_futurenet() {
        let mut program = full_program();
        program.directives[0] = Directive::Network {
            value: "futurenet".to_string(),
            span: sp(),
        };
        let ir = Compiler::compile(&program);
        assert_eq!(
            ir.network_passphrase,
            "Test SDF Future Network ; October 2022"
        );
    }

    #[test]
    fn passphrase_custom() {
        let passphrase = "My Custom Network ; January 2025";
        let mut program = full_program();
        program.directives[0] = Directive::Network {
            value: passphrase.to_string(),
            span: sp(),
        };
        let ir = Compiler::compile(&program);
        assert_eq!(ir.network_passphrase, passphrase);
    }

    // -- Default fee and timeout ---------------------------------------------

    #[test]
    fn defaults_without_fee_or_timeout() {
        let program = Program {
            uses: vec![],
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
            calls: vec![],
        };
        let ir = Compiler::compile(&program);
        assert_eq!(ir.signing.fee_stroops, 100_000);
        assert_eq!(ir.signing.timeout_seconds, 30);
    }

    // -- Multiple calls ------------------------------------------------------

    #[test]
    fn compile_multiple_calls() {
        let program = Program {
            uses: vec![],
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
            calls: vec![
                Call {
                    contract: CONTRACT.to_string(),
                    method: "approve".to_string(),
                    args: vec![Value::U32(1, sp())],
                    interface: None,
                    span: sp(),
                },
                Call {
                    contract: CONTRACT.to_string(),
                    method: "transfer".to_string(),
                    args: vec![Value::U32(2, sp())],
                    interface: None,
                    span: sp(),
                },
            ],
        };
        let ir = Compiler::compile(&program);
        assert_eq!(ir.calls.len(), 2);
        assert_eq!(ir.calls[0].method, "approve");
        assert_eq!(ir.calls[1].method, "transfer");
    }

    // -- Value compilation ---------------------------------------------------

    #[test]
    fn compile_all_value_types() {
        let s = sp();
        let program = Program {
            uses: vec![],
            consts: vec![],
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
                    Value::Bool(false, s),
                    Value::U32(42, s),
                    Value::I32(-7, s),
                    Value::U64(999, s),
                    Value::I64(-999, s),
                    Value::U128("123456".to_string(), s),
                    Value::I128("-123456".to_string(), s),
                    Value::U256("0".to_string(), s),
                    Value::I256("-1".to_string(), s),
                    Value::String("hello".to_string(), s),
                    Value::Symbol("transfer".to_string(), s),
                    Value::Bytes("0xdeadbeef".to_string(), s),
                    Value::Address(ACCOUNT.to_string(), s),
                ],
                interface: None,
                span: s,
            }],
        };
        let ir = Compiler::compile(&program);
        let args = &ir.calls[0].args;

        assert_eq!(args[0], IrValue::Bool(true));
        assert_eq!(args[1], IrValue::Bool(false));
        assert_eq!(args[2], IrValue::U32(42));
        assert_eq!(args[3], IrValue::I32(-7));
        assert_eq!(args[4], IrValue::U64(999));
        assert_eq!(args[5], IrValue::I64(-999));
        assert_eq!(args[6], IrValue::U128("123456".to_string()));
        assert_eq!(args[7], IrValue::I128("-123456".to_string()));
        assert_eq!(args[8], IrValue::U256("0".to_string()));
        assert_eq!(args[9], IrValue::I256("-1".to_string()));
        assert_eq!(args[10], IrValue::String("hello".to_string()));
        assert_eq!(args[11], IrValue::Symbol("transfer".to_string()));
        assert_eq!(args[12], IrValue::Bytes("0xdeadbeef".to_string()));
        assert_eq!(args[13], IrValue::Address(ACCOUNT.to_string()));
    }

    #[test]
    fn compile_vec() {
        let s = sp();
        let program = Program {
            uses: vec![],
            consts: vec![],
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
                args: vec![Value::Vec(
                    vec![Value::U32(1, s), Value::U32(2, s), Value::U32(3, s)],
                    s,
                )],
                interface: None,
                span: s,
            }],
        };
        let ir = Compiler::compile(&program);
        assert_eq!(
            ir.calls[0].args[0],
            IrValue::Vec(vec![IrValue::U32(1), IrValue::U32(2), IrValue::U32(3)])
        );
    }

    #[test]
    fn compile_nested_vec() {
        let s = sp();
        let program = Program {
            uses: vec![],
            consts: vec![],
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
                args: vec![Value::Vec(
                    vec![Value::U32(1, s), Value::Vec(vec![Value::U32(2, s)], s)],
                    s,
                )],
                interface: None,
                span: s,
            }],
        };
        let ir = Compiler::compile(&program);
        assert_eq!(
            ir.calls[0].args[0],
            IrValue::Vec(vec![IrValue::U32(1), IrValue::Vec(vec![IrValue::U32(2)])])
        );
    }

    #[test]
    fn compile_map() {
        let s = sp();
        let program = Program {
            uses: vec![],
            consts: vec![],
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
                args: vec![Value::Map(
                    vec![MapEntry {
                        key: Value::Symbol("x".to_string(), s),
                        value: Value::I128("1".to_string(), s),
                    }],
                    s,
                )],
                interface: None,
                span: s,
            }],
        };
        let ir = Compiler::compile(&program);
        assert_eq!(
            ir.calls[0].args[0],
            IrValue::Map(vec![IrMapEntry {
                key: IrValue::Symbol("x".to_string()),
                value: IrValue::I128("1".to_string()),
            }])
        );
    }

    // -- Interface call compilation ------------------------------------------

    #[test]
    fn compile_interface_call_resolves_contract() {
        let s = sp();
        let program = Program {
            uses: vec![],
            consts: vec![],
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
                contract: "_".to_string(),
                method: "transfer".to_string(),
                args: vec![Value::I128("1000".to_string(), s)],
                interface: Some("Token".to_string()),
                span: s,
            }],
        };

        let mut abis = HashMap::new();
        abis.insert("Token".to_string(), CONTRACT.to_string());

        let ir = Compiler::compile_with_abis(&program, Some(&abis));
        assert_eq!(ir.calls[0].contract, CONTRACT);
        assert_eq!(ir.calls[0].method, "transfer");
    }

    #[test]
    fn compile_interface_call_without_abis_keeps_placeholder() {
        let s = sp();
        let program = Program {
            uses: vec![],
            consts: vec![],
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
                contract: "_".to_string(),
                method: "transfer".to_string(),
                args: vec![],
                interface: Some("Token".to_string()),
                span: s,
            }],
        };

        let ir = Compiler::compile(&program);
        assert_eq!(ir.calls[0].contract, "_");
    }

    #[test]
    fn compile_traditional_call_ignores_abis() {
        let s = sp();
        let program = Program {
            uses: vec![],
            consts: vec![],
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
                method: "transfer".to_string(),
                args: vec![],
                interface: None,
                span: s,
            }],
        };

        let mut abis = HashMap::new();
        abis.insert("Token".to_string(), "SOME_OTHER_CONTRACT".to_string());

        let ir = Compiler::compile_with_abis(&program, Some(&abis));
        assert_eq!(ir.calls[0].contract, CONTRACT);
    }

    // -- JSON serialization --------------------------------------------------

    #[test]
    fn json_output_is_valid() {
        let ir = Compiler::compile(&full_program());
        let json = serde_json::to_string_pretty(&ir).unwrap();
        // Verify it round-trips
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn json_is_deterministic() {
        let ir = Compiler::compile(&full_program());
        let json1 = serde_json::to_string_pretty(&ir).unwrap();
        let json2 = serde_json::to_string_pretty(&ir).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn json_tagged_format() {
        let s = sp();
        let program = Program {
            uses: vec![],
            consts: vec![],
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
                    Value::I128("42".to_string(), s),
                    Value::Address(ACCOUNT.to_string(), s),
                ],
                interface: None,
                span: s,
            }],
        };
        let ir = Compiler::compile(&program);
        let json = serde_json::to_string(&ir).unwrap();

        // Verify tagged format
        assert!(json.contains(r#""type":"bool","value":true"#));
        assert!(json.contains(r#""type":"i128","value":"42""#));
        assert!(json.contains(r#""type":"address","value":""#));
    }

    // -- Roundtrip integration tests (lex -> parse -> compile -> JSON) --------

    fn compile_source(source: &str) -> JsonIR {
        let tokens = quasar_syntax::lexer::Lexer::tokenize(source).unwrap();
        let program = quasar_syntax::parser::Parser::parse(&tokens).unwrap();
        Compiler::compile(&program)
    }

    #[test]
    fn roundtrip_transfer_fixture() {
        let source = include_str!("../../../tests/fixtures/transfer.soro");
        let ir = compile_source(source);
        let json = serde_json::to_string_pretty(&ir).unwrap();
        insta::assert_snapshot!("roundtrip_transfer", json);
    }

    #[test]
    fn roundtrip_minimal_fixture() {
        let source = include_str!("../../../tests/fixtures/minimal.soro");
        let ir = compile_source(source);
        let json = serde_json::to_string_pretty(&ir).unwrap();
        insta::assert_snapshot!("roundtrip_minimal", json);
    }

    #[test]
    fn roundtrip_all_types_fixture() {
        let source = include_str!("../../../tests/fixtures/all_types.soro");
        let ir = compile_source(source);
        let json = serde_json::to_string_pretty(&ir).unwrap();
        insta::assert_snapshot!("roundtrip_all_types", json);
    }

    #[test]
    fn roundtrip_multi_call_fixture() {
        let source = include_str!("../../../tests/fixtures/multi_call.soro");
        let ir = compile_source(source);
        let json = serde_json::to_string_pretty(&ir).unwrap();
        insta::assert_snapshot!("roundtrip_multi_call", json);
    }

    #[test]
    fn roundtrip_transfer_matches_expected() {
        let source = include_str!("../../../tests/fixtures/transfer.soro");
        let expected_json = include_str!("../../../tests/fixtures/transfer.expected.json");
        let ir = compile_source(source);
        let actual_json = serde_json::to_string_pretty(&ir).unwrap();

        // Parse both as serde_json::Value for structural comparison
        let actual: serde_json::Value = serde_json::from_str(&actual_json).unwrap();
        let expected: serde_json::Value = serde_json::from_str(expected_json).unwrap();
        assert_eq!(actual, expected);
    }
}
