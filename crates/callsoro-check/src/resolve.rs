use std::collections::{HashMap, HashSet};

use callsoro_syntax::ast::{ConstDecl, ConstValue, Program, Value};

use crate::validate::Diagnostic;

/// Resolves `const` references in the AST, substituting names with their values.
///
/// Returns diagnostics for:
/// - Duplicate const names (error)
/// - Undefined name references (error)
/// - Const references in directive positions (error)
/// - Unused consts (warning)
pub struct Resolver;

impl Resolver {
    pub fn resolve(program: &mut Program) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        // Collect const definitions
        let mut consts: HashMap<String, &ConstDecl> = HashMap::new();
        for decl in &program.consts {
            if consts.contains_key(&decl.name) {
                diagnostics.push(Diagnostic::error(
                    format!("duplicate const '{}'", decl.name),
                    decl.span,
                ));
            } else {
                consts.insert(decl.name.clone(), decl);
            }
        }

        // Track usage
        let mut used: HashSet<String> = HashSet::new();

        // Check source directive for const refs
        for directive in &program.directives {
            if let callsoro_syntax::ast::Directive::Source { value, span } = directive {
                if consts.contains_key(value.as_str()) {
                    diagnostics.push(
                        Diagnostic::error(
                            format!(
                                "const references in directives are not supported; use the value of '{}' directly",
                                value
                            ),
                            *span,
                        )
                        .with_help("expand the const value inline in the source directive"),
                    );
                }
            }
        }

        // Resolve contract references and arguments in calls
        for call in &mut program.calls {
            // Interface calls use "_" placeholder — skip contract resolution
            if call.interface.is_some() {
                // Only resolve arguments, not the contract placeholder
            } else if let Some(decl) = consts.get(call.contract.as_str()) {
                match &decl.value {
                    ConstValue::String(s, _) => {
                        call.contract = s.clone();
                        used.insert(decl.name.clone());
                    }
                    ConstValue::Typed(_) => {
                        diagnostics.push(
                            Diagnostic::error(
                                format!(
                                    "const '{}' is a typed value, not a string; cannot be used as contract ID",
                                    call.contract
                                ),
                                call.span,
                            )
                            .with_help("contract IDs require a string const: const name = \"C...\""),
                        );
                    }
                }
            } else if is_const_name(&call.contract) {
                diagnostics.push(Diagnostic::error(
                    format!("undefined name '{}'", call.contract),
                    call.span,
                ));
            }

            // Resolve arguments
            for arg in &mut call.args {
                Self::resolve_value(arg, &consts, &mut used, &mut diagnostics);
            }
        }

        // Check for unused consts (warning)
        for decl in &program.consts {
            if !used.contains(&decl.name) {
                diagnostics.push(Diagnostic::warning(
                    format!("const '{}' is never used", decl.name),
                    decl.span,
                ));
            }
        }

        diagnostics
    }

    fn resolve_value(
        value: &mut Value,
        consts: &HashMap<String, &ConstDecl>,
        used: &mut HashSet<String>,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        match value {
            Value::Ident(ref name, span) => {
                let name = name.clone();
                let span = *span;
                if let Some(decl) = consts.get(name.as_str()) {
                    match &decl.value {
                        ConstValue::Typed(v) => {
                            *value = v.clone();
                            used.insert(name);
                        }
                        ConstValue::String(_, _) => {
                            diagnostics.push(
                                Diagnostic::error(
                                    format!(
                                        "const '{}' is a string const, not a typed value; cannot be used as argument",
                                        name
                                    ),
                                    span,
                                )
                                .with_help("argument positions require typed const values: const name = i128(\"...\")"),
                            );
                        }
                    }
                } else {
                    diagnostics.push(Diagnostic::error(
                        format!("undefined name '{}'", name),
                        span,
                    ));
                }
            }
            Value::Vec(items, _) => {
                for item in items {
                    Self::resolve_value(item, consts, used, diagnostics);
                }
            }
            Value::Map(entries, _) => {
                for entry in entries {
                    Self::resolve_value(&mut entry.key, consts, used, diagnostics);
                    Self::resolve_value(&mut entry.value, consts, used, diagnostics);
                }
            }
            _ => {} // Concrete values need no resolution
        }
    }
}

/// Check if a string looks like a const name (lowercase snake_case) rather than
/// an address (starts with uppercase C/G).
fn is_const_name(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;
    use callsoro_syntax::ast::{Call, ConstDecl, ConstValue, Directive, Program, Value};
    use callsoro_syntax::span::Span;

    const ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    fn sp() -> Span {
        Span::new(0, 10, 1, 1)
    }

    fn base_program() -> Program {
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
            ],
            calls: vec![Call {
                contract: CONTRACT.to_string(),
                method: "transfer".to_string(),
                args: vec![],
                interface: None,
                span: sp(),
            }],
        }
    }

    #[test]
    fn no_consts_no_diagnostics() {
        let mut program = base_program();
        let diags = Resolver::resolve(&mut program);
        assert!(diags.is_empty());
    }

    #[test]
    fn string_const_resolves_contract() {
        let mut program = base_program();
        program.consts.push(ConstDecl {
            name: "token".to_string(),
            value: ConstValue::String(CONTRACT.to_string(), sp()),
            span: sp(),
        });
        program.calls[0].contract = "token".to_string();

        let diags = Resolver::resolve(&mut program);
        assert!(diags.is_empty(), "got: {:?}", diags);
        assert_eq!(program.calls[0].contract, CONTRACT);
    }

    #[test]
    fn value_const_resolves_arg() {
        let mut program = base_program();
        program.consts.push(ConstDecl {
            name: "amount".to_string(),
            value: ConstValue::Typed(Value::I128("10000000".to_string(), sp())),
            span: sp(),
        });
        program.calls[0]
            .args
            .push(Value::Ident("amount".to_string(), sp()));

        let diags = Resolver::resolve(&mut program);
        assert!(diags.is_empty(), "got: {:?}", diags);
        match &program.calls[0].args[0] {
            Value::I128(v, _) => assert_eq!(v, "10000000"),
            other => panic!("expected I128, got: {:?}", other),
        }
    }

    #[test]
    fn duplicate_const_error() {
        let mut program = base_program();
        program.consts.push(ConstDecl {
            name: "x".to_string(),
            value: ConstValue::String("a".to_string(), sp()),
            span: sp(),
        });
        program.consts.push(ConstDecl {
            name: "x".to_string(),
            value: ConstValue::String("b".to_string(), sp()),
            span: sp(),
        });

        let diags = Resolver::resolve(&mut program);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("duplicate const 'x'"));
    }

    #[test]
    fn undefined_name_in_arg() {
        let mut program = base_program();
        program.calls[0]
            .args
            .push(Value::Ident("missing".to_string(), sp()));

        let diags = Resolver::resolve(&mut program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("undefined name 'missing'"));
    }

    #[test]
    fn undefined_name_in_contract() {
        let mut program = base_program();
        program.calls[0].contract = "token".to_string();

        let diags = Resolver::resolve(&mut program);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("undefined name 'token'"));
    }

    #[test]
    fn unused_const_warning() {
        let mut program = base_program();
        program.consts.push(ConstDecl {
            name: "unused".to_string(),
            value: ConstValue::String("something".to_string(), sp()),
            span: sp(),
        });

        let diags = Resolver::resolve(&mut program);
        let warnings: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("const 'unused' is never used"));
    }

    #[test]
    fn const_in_source_directive_error() {
        let mut program = base_program();
        program.consts.push(ConstDecl {
            name: "s".to_string(),
            value: ConstValue::String(ACCOUNT.to_string(), sp()),
            span: sp(),
        });
        program.directives[1] = Directive::Source {
            value: "s".to_string(),
            span: sp(),
        };

        let diags = Resolver::resolve(&mut program);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("const references in directives")),
            "got: {:?}",
            errors
        );
    }

    #[test]
    fn typed_const_in_contract_position_error() {
        let mut program = base_program();
        program.consts.push(ConstDecl {
            name: "sender".to_string(),
            value: ConstValue::Typed(Value::Address(ACCOUNT.to_string(), sp())),
            span: sp(),
        });
        program.calls[0].contract = "sender".to_string();

        let diags = Resolver::resolve(&mut program);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("typed value"));
    }

    #[test]
    fn string_const_in_arg_position_error() {
        let mut program = base_program();
        program.consts.push(ConstDecl {
            name: "token".to_string(),
            value: ConstValue::String(CONTRACT.to_string(), sp()),
            span: sp(),
        });
        program.calls[0]
            .args
            .push(Value::Ident("token".to_string(), sp()));

        let diags = Resolver::resolve(&mut program);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("string const"));
    }

    #[test]
    fn identical_output_with_and_without_consts() {
        // Without consts
        let mut program_a = base_program();
        program_a.calls[0]
            .args
            .push(Value::I128("10000000".to_string(), sp()));
        let diags = Resolver::resolve(&mut program_a);
        assert!(diags.is_empty());

        // With consts
        let mut program_b = base_program();
        program_b.consts.push(ConstDecl {
            name: "amount".to_string(),
            value: ConstValue::Typed(Value::I128("10000000".to_string(), sp())),
            span: sp(),
        });
        program_b.calls[0]
            .args
            .push(Value::Ident("amount".to_string(), sp()));
        let diags = Resolver::resolve(&mut program_b);
        assert!(diags.is_empty());

        // Both should produce same IR
        let ir_a = callsoro_compile::Compiler::compile(&program_a);
        let ir_b = callsoro_compile::Compiler::compile(&program_b);
        assert_eq!(
            serde_json::to_string(&ir_a).unwrap(),
            serde_json::to_string(&ir_b).unwrap()
        );
    }

    #[test]
    fn resolve_in_nested_vec() {
        let mut program = base_program();
        program.consts.push(ConstDecl {
            name: "val".to_string(),
            value: ConstValue::Typed(Value::U32(42, sp())),
            span: sp(),
        });
        program.calls[0].args.push(Value::Vec(
            vec![Value::Ident("val".to_string(), sp())],
            sp(),
        ));

        let diags = Resolver::resolve(&mut program);
        assert!(diags.is_empty(), "got: {:?}", diags);
        match &program.calls[0].args[0] {
            Value::Vec(items, _) => match &items[0] {
                Value::U32(v, _) => assert_eq!(*v, 42),
                other => panic!("expected U32, got: {:?}", other),
            },
            other => panic!("expected Vec, got: {:?}", other),
        }
    }

    #[test]
    fn interface_call_skips_contract_resolution() {
        let mut program = base_program();
        // An interface call has contract="_" and interface=Some(...)
        program.calls[0].contract = "_".to_string();
        program.calls[0].interface = Some("Token".to_string());

        let diags = Resolver::resolve(&mut program);
        assert!(diags.is_empty(), "got: {:?}", diags);
        // The "_" placeholder should remain untouched
        assert_eq!(program.calls[0].contract, "_");
    }

    #[test]
    fn resolve_in_map_value() {
        let mut program = base_program();
        program.consts.push(ConstDecl {
            name: "val".to_string(),
            value: ConstValue::Typed(Value::U32(42, sp())),
            span: sp(),
        });
        program.calls[0].args.push(Value::Map(
            vec![callsoro_syntax::ast::MapEntry {
                key: Value::Symbol("k".to_string(), sp()),
                value: Value::Ident("val".to_string(), sp()),
            }],
            sp(),
        ));

        let diags = Resolver::resolve(&mut program);
        assert!(diags.is_empty(), "got: {:?}", diags);
    }
}
