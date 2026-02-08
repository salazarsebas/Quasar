use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process;

use callsoro_check::{Diagnostic, Resolver, Severity, TypeCheckError, TypeChecker, Validator};
use callsoro_compile::{Compiler, JsonIR, XdrCompiler};
use callsoro_exec::{
    AbiImporter, ExecutionOutcome, ExecutionResult, Executor, ExecutorConfig, Simulator,
};
use callsoro_syntax::ast::{Call, ConstDecl, ConstValue, Directive, MapEntry, Program, Value};
use callsoro_syntax::lexer::Lexer;
use callsoro_syntax::parser::Parser;
use clap::{Parser as ClapParser, Subcommand};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(ClapParser)]
#[command(name = "callsoro", about = "CallSoro DSL compiler for Soroban")]
#[command(version)]
struct Cli {
    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile a .soro file to JSON IR
    Compile {
        /// Input .soro file
        file: String,
        /// Output file (default: stdout)
        #[arg(short)]
        o: Option<String>,
    },
    /// Compile a .soro file to base64 XDR (one line per call)
    Xdr {
        /// Input .soro file
        file: String,
        /// Output file (default: stdout)
        #[arg(short)]
        o: Option<String>,
    },
    /// Simulate a .soro file against Soroban RPC
    Simulate {
        /// Input .soro file
        file: String,
        /// RPC endpoint URL (overrides CALLSORO_RPC_URL env and network default)
        #[arg(long)]
        rpc_url: Option<String>,
        /// Output raw JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Validate a .soro file (errors + warnings)
    Check {
        /// Input .soro file
        file: String,
    },
    /// Format a .soro file
    Fmt {
        /// Input .soro file
        file: String,
        /// Overwrite the file in-place
        #[arg(long)]
        write: bool,
    },
    /// Import a deployed contract's ABI from the network
    Import {
        /// Contract address (C...)
        contract_id: String,
        /// Network name (testnet, mainnet, futurenet)
        #[arg(long, default_value = "testnet")]
        network: String,
        /// RPC endpoint URL (overrides network default)
        #[arg(long)]
        rpc_url: Option<String>,
        /// Output file (default: stdout)
        #[arg(short)]
        o: Option<String>,
    },
    /// Execute a .soro script: simulate, sign, and submit transactions
    Run {
        /// Input .soro file
        file: String,
        /// Stellar secret key (S...)
        #[arg(long)]
        secret_key: Option<String>,
        /// Environment variable to read secret key from (default: SORO_SECRET_KEY)
        #[arg(long, default_value = "SORO_SECRET_KEY")]
        env: String,
        /// RPC endpoint URL (overrides CALLSORO_RPC_URL env and network default)
        #[arg(long)]
        rpc_url: Option<String>,
        /// Simulate only, don't submit
        #[arg(long)]
        dry_run: bool,
        /// Output full result in JSON
        #[arg(long)]
        json: bool,
        /// Skip mainnet confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Print compiler version
    Version,
}

// ---------------------------------------------------------------------------
// ANSI helpers
// ---------------------------------------------------------------------------

struct Colors {
    red: &'static str,
    yellow: &'static str,
    cyan: &'static str,
    bold: &'static str,
    reset: &'static str,
}

const COLORS_ON: Colors = Colors {
    red: "\x1b[31m",
    yellow: "\x1b[33m",
    cyan: "\x1b[36m",
    bold: "\x1b[1m",
    reset: "\x1b[0m",
};

const COLORS_OFF: Colors = Colors {
    red: "",
    yellow: "",
    cyan: "",
    bold: "",
    reset: "",
};

fn choose_colors(no_color: bool) -> &'static Colors {
    if no_color {
        &COLORS_OFF
    } else {
        &COLORS_ON
    }
}

// ---------------------------------------------------------------------------
// Colored diagnostic formatting
// ---------------------------------------------------------------------------

fn format_diagnostic(diag: &Diagnostic, source: &str, path: &str, c: &Colors) -> String {
    let line_content = source.lines().nth(diag.span.line - 1).unwrap_or("");
    let col = diag.span.col;
    let underline_len = if diag.span.end > diag.span.start {
        diag.span.end - diag.span.start
    } else {
        1
    };

    let (severity_color, severity_label) = match diag.severity {
        Severity::Error => (c.red, "error"),
        Severity::Warning => (c.yellow, "warning"),
    };

    let mut out = format!(
        "{}{}{}{}: {}\n {} {}-->{} {}:{}:{}\n  |\n{} | {}\n  | {}{}{}{}",
        severity_color,
        c.bold,
        severity_label,
        c.reset,
        diag.message,
        "",
        c.cyan,
        c.reset,
        path,
        diag.span.line,
        col,
        diag.span.line,
        line_content,
        " ".repeat(col - 1),
        severity_color,
        "^".repeat(underline_len),
        c.reset,
    );

    if let Some(help) = &diag.help {
        out.push_str(&format!("\n  = help: {}", help));
    }
    out.push('\n');
    out
}

fn format_lex_error(
    msg: &str,
    span: &callsoro_syntax::span::Span,
    source: &str,
    path: &str,
    c: &Colors,
) -> String {
    let line_content = source.lines().nth(span.line - 1).unwrap_or("");
    let col = span.col;
    let underline_len = if span.end > span.start {
        span.end - span.start
    } else {
        1
    };

    format!(
        "{}{}error{}: {}\n {}-->{} {}:{}:{}\n  |\n{} | {}\n  | {}{}{}{}",
        c.red,
        c.bold,
        c.reset,
        msg,
        c.cyan,
        c.reset,
        path,
        span.line,
        col,
        span.line,
        line_content,
        " ".repeat(col - 1),
        c.red,
        "^".repeat(underline_len),
        c.reset,
    )
}

fn format_type_error(err: &TypeCheckError, source: &str, path: &str, c: &Colors) -> String {
    let line_content = source.lines().nth(err.span.line - 1).unwrap_or("");
    let col = err.span.col;
    let underline_len = if err.span.end > err.span.start {
        err.span.end - err.span.start
    } else {
        1
    };

    format!(
        "{}{}type error{}: {}\n {}-->{} {}:{}:{}\n  |\n{} | {}\n  | {}{}{}{}\n",
        c.red,
        c.bold,
        c.reset,
        err.message,
        c.cyan,
        c.reset,
        path,
        err.span.line,
        col,
        err.span.line,
        line_content,
        " ".repeat(col - 1),
        c.red,
        "^".repeat(underline_len),
        c.reset,
    )
}

// ---------------------------------------------------------------------------
// Pipeline helpers
// ---------------------------------------------------------------------------

enum PipelineResult {
    Compiled(JsonIR),
    Errors,
}

fn run_pipeline(source: &str, path: &str, c: &Colors) -> PipelineResult {
    let base_dir = Path::new(path).parent().unwrap_or_else(|| Path::new("."));

    // Lex
    let tokens = match Lexer::tokenize(source) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}", format_lex_error(&e.message, &e.span, source, path, c));
            return PipelineResult::Errors;
        }
    };

    // Parse
    let mut program = match Parser::parse(&tokens) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", format_lex_error(&e.message, &e.span, source, path, c));
            return PipelineResult::Errors;
        }
    };

    // Resolve consts
    let resolve_diags = Resolver::resolve(&mut program);
    let resolve_has_errors = resolve_diags.iter().any(|d| d.severity == Severity::Error);
    for diag in &resolve_diags {
        eprintln!("{}", format_diagnostic(diag, source, path, c));
    }
    if resolve_has_errors {
        return PipelineResult::Errors;
    }

    // Validate
    let diagnostics = Validator::validate(&program);
    let has_errors = diagnostics.iter().any(|d| d.severity == Severity::Error);

    for diag in &diagnostics {
        eprintln!("{}", format_diagnostic(diag, source, path, c));
    }

    if has_errors {
        return PipelineResult::Errors;
    }

    // Type-check interface calls
    let mut checker = TypeChecker::new();
    for use_decl in &program.uses {
        if let Err(e) = checker.load_abi(&use_decl.alias, &use_decl.path, base_dir) {
            eprintln!("{}", format_type_error(&e, source, path, c));
            return PipelineResult::Errors;
        }
    }

    let type_errors = checker.check_program(&program);
    if !type_errors.is_empty() {
        for err in &type_errors {
            eprintln!("{}", format_type_error(err, source, path, c));
        }
        return PipelineResult::Errors;
    }

    // Build ABI contract ID map for compiler
    let abi_map: HashMap<String, String> = checker
        .abis()
        .iter()
        .map(|(alias, abi)| (alias.clone(), abi.contract_id.clone()))
        .collect();

    // Compile
    let abis = if abi_map.is_empty() {
        None
    } else {
        Some(&abi_map)
    };
    let ir = Compiler::compile_with_abis(&program, abis);
    PipelineResult::Compiled(ir)
}

// ---------------------------------------------------------------------------
// Formatter
// ---------------------------------------------------------------------------

fn format_program(program: &Program) -> String {
    let mut out = String::new();

    // Use declarations
    for u in &program.uses {
        out.push_str(&format!("use \"{}\" as {}\n", u.path, u.alias));
    }
    if !program.uses.is_empty() {
        out.push('\n');
    }

    // Const declarations
    for c in &program.consts {
        format_const(c, &mut out);
    }
    if !program.consts.is_empty() {
        out.push('\n');
    }

    // Directives
    for directive in &program.directives {
        match directive {
            Directive::Network { value, .. } => {
                out.push_str(&format!("network {}\n", value));
            }
            Directive::Source { value, .. } => {
                out.push_str(&format!("source  {}\n", value));
            }
            Directive::Fee { value, .. } => {
                out.push_str(&format!("fee     {}\n", value));
            }
            Directive::Timeout { value, .. } => {
                out.push_str(&format!("timeout {}\n", value));
            }
        }
    }

    // Calls
    for call in &program.calls {
        out.push('\n');
        format_call(call, &mut out);
    }

    out
}

fn format_const(decl: &ConstDecl, out: &mut String) {
    out.push_str(&format!("const {} = ", decl.name));
    match &decl.value {
        ConstValue::String(s, _) => out.push_str(&format!("\"{}\"", s)),
        ConstValue::Typed(v) => format_value(v, out, 0),
    }
    out.push('\n');
}

fn format_call(call: &Call, out: &mut String) {
    if let Some(alias) = &call.interface {
        out.push_str(&format!("call {}.{}(", alias, call.method));
    } else {
        out.push_str(&format!("call {} {}(", call.contract, call.method));
    }
    if call.args.is_empty() {
        out.push_str(")\n");
    } else if call.args.len() == 1 {
        format_value(&call.args[0], out, 0);
        out.push_str(")\n");
    } else {
        out.push('\n');
        for (i, arg) in call.args.iter().enumerate() {
            out.push_str("  ");
            format_value(arg, out, 1);
            if i < call.args.len() - 1 {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str(")\n");
    }
}

fn format_value(value: &Value, out: &mut String, _depth: usize) {
    match value {
        Value::Bool(v, _) => out.push_str(&format!("bool({})", v)),
        Value::U32(v, _) => out.push_str(&format!("u32({})", v)),
        Value::I32(v, _) => out.push_str(&format!("i32({})", v)),
        Value::U64(v, _) => out.push_str(&format!("u64({})", v)),
        Value::I64(v, _) => out.push_str(&format!("i64({})", v)),
        Value::U128(v, _) => out.push_str(&format!("u128(\"{}\")", v)),
        Value::I128(v, _) => out.push_str(&format!("i128(\"{}\")", v)),
        Value::U256(v, _) => out.push_str(&format!("u256(\"{}\")", v)),
        Value::I256(v, _) => out.push_str(&format!("i256(\"{}\")", v)),
        Value::String(v, _) => out.push_str(&format!("string(\"{}\")", v)),
        Value::Symbol(v, _) => out.push_str(&format!("symbol(\"{}\")", v)),
        Value::Bytes(v, _) => out.push_str(&format!("bytes(\"{}\")", v)),
        Value::Address(v, _) => out.push_str(&format!("address(\"{}\")", v)),
        Value::Vec(items, _) => {
            out.push_str("vec(");
            for (i, item) in items.iter().enumerate() {
                format_value(item, out, 0);
                if i < items.len() - 1 {
                    out.push_str(", ");
                }
            }
            out.push(')');
        }
        Value::Map(entries, _) => {
            out.push_str("map(");
            for (i, entry) in entries.iter().enumerate() {
                format_map_entry(entry, out);
                if i < entries.len() - 1 {
                    out.push_str(", ");
                }
            }
            out.push(')');
        }
        Value::Ident(name, _) => out.push_str(name),
    }
}

fn format_map_entry(entry: &MapEntry, out: &mut String) {
    format_value(&entry.key, out, 0);
    out.push_str(" => ");
    format_value(&entry.value, out, 0);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    let c = choose_colors(cli.no_color);

    match cli.command {
        Commands::Compile { file, o } => {
            let source = read_file(&file, c);
            match run_pipeline(&source, &file, c) {
                PipelineResult::Compiled(ir) => {
                    let json =
                        serde_json::to_string_pretty(&ir).expect("JSON serialization failed");
                    if let Some(output_path) = o {
                        fs::write(&output_path, &json).unwrap_or_else(|e| {
                            eprintln!(
                                "{}{}error{}: cannot write {}: {}",
                                c.red, c.bold, c.reset, output_path, e
                            );
                            process::exit(1);
                        });
                    } else {
                        println!("{}", json);
                    }
                }
                PipelineResult::Errors => process::exit(1),
            }
        }

        Commands::Xdr { file, o } => {
            let source = read_file(&file, c);
            match run_pipeline(&source, &file, c) {
                PipelineResult::Compiled(ir) => {
                    let transactions = match XdrCompiler::compile(&ir) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                            process::exit(1);
                        }
                    };
                    let mut output = String::new();
                    for (i, tx) in transactions.iter().enumerate() {
                        match XdrCompiler::to_xdr_base64(&tx.invoke_args) {
                            Ok(b64) => {
                                if i > 0 {
                                    output.push('\n');
                                }
                                output.push_str(&b64);
                            }
                            Err(e) => {
                                eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                                process::exit(1);
                            }
                        }
                    }
                    if let Some(output_path) = o {
                        fs::write(&output_path, &output).unwrap_or_else(|e| {
                            eprintln!(
                                "{}{}error{}: cannot write {}: {}",
                                c.red, c.bold, c.reset, output_path, e
                            );
                            process::exit(1);
                        });
                    } else {
                        println!("{}", output);
                    }
                }
                PipelineResult::Errors => process::exit(1),
            }
        }

        Commands::Simulate {
            file,
            rpc_url,
            json,
        } => {
            let source = read_file(&file, c);
            match run_pipeline(&source, &file, c) {
                PipelineResult::Compiled(ir) => {
                    let transactions = match XdrCompiler::compile(&ir) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                            process::exit(1);
                        }
                    };

                    let url = match callsoro_exec::simulator::resolve_rpc_url(
                        rpc_url.as_deref(),
                        &ir.network,
                    ) {
                        Ok(u) => u,
                        Err(e) => {
                            eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                            process::exit(1);
                        }
                    };

                    let simulator = Simulator::new(&url);
                    let results = match simulator.simulate(&transactions, &ir) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                            process::exit(1);
                        }
                    };

                    if json {
                        let json_out = serde_json::to_string_pretty(&results)
                            .expect("JSON serialization failed");
                        println!("{}", json_out);
                    } else {
                        for result in &results {
                            print!(
                                "{}",
                                callsoro_exec::simulator::format_human_result(
                                    result,
                                    results.len(),
                                    ir.signing.fee_stroops as u32,
                                )
                            );
                        }
                    }
                }
                PipelineResult::Errors => process::exit(1),
            }
        }

        Commands::Check { file } => {
            let source = read_file(&file, c);
            let base_dir = Path::new(&file).parent().unwrap_or_else(|| Path::new("."));

            // Lex
            let tokens = match Lexer::tokenize(&source) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!(
                        "{}",
                        format_lex_error(&e.message, &e.span, &source, &file, c)
                    );
                    process::exit(1);
                }
            };

            // Parse
            let mut program = match Parser::parse(&tokens) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "{}",
                        format_lex_error(&e.message, &e.span, &source, &file, c)
                    );
                    process::exit(1);
                }
            };

            // Resolve consts
            let resolve_diags = Resolver::resolve(&mut program);

            // Validate
            let validate_diags = Validator::validate(&program);

            let all_diags: Vec<_> = resolve_diags.iter().chain(validate_diags.iter()).collect();
            let has_errors = all_diags.iter().any(|d| d.severity == Severity::Error);

            if !all_diags.is_empty() {
                for diag in &all_diags {
                    eprintln!("{}", format_diagnostic(diag, &source, &file, c));
                }
            }

            if has_errors {
                process::exit(1);
            }

            // Type-check interface calls
            let mut checker = TypeChecker::new();
            for use_decl in &program.uses {
                if let Err(e) = checker.load_abi(&use_decl.alias, &use_decl.path, base_dir) {
                    eprintln!("{}", format_type_error(&e, &source, &file, c));
                    process::exit(1);
                }
            }

            let type_errors = checker.check_program(&program);
            if !type_errors.is_empty() {
                for err in &type_errors {
                    eprintln!("{}", format_type_error(err, &source, &file, c));
                }
                process::exit(1);
            }

            if all_diags.is_empty() && type_errors.is_empty() {
                eprintln!("No errors found.");
            }
        }

        Commands::Fmt { file, write } => {
            let source = read_file(&file, c);

            // Lex
            let tokens = match Lexer::tokenize(&source) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!(
                        "{}",
                        format_lex_error(&e.message, &e.span, &source, &file, c)
                    );
                    process::exit(1);
                }
            };

            // Parse
            let program = match Parser::parse(&tokens) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "{}",
                        format_lex_error(&e.message, &e.span, &source, &file, c)
                    );
                    process::exit(1);
                }
            };

            let formatted = format_program(&program);

            if write {
                fs::write(&file, &formatted).unwrap_or_else(|e| {
                    eprintln!(
                        "{}{}error{}: cannot write {}: {}",
                        c.red, c.bold, c.reset, file, e
                    );
                    process::exit(1);
                });
            } else {
                print!("{}", formatted);
            }
        }

        Commands::Import {
            contract_id,
            network,
            rpc_url,
            o,
        } => {
            let url = match callsoro_exec::simulator::resolve_rpc_url(rpc_url.as_deref(), &network)
            {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                    process::exit(1);
                }
            };

            let importer = AbiImporter::new(&url);
            let abi = match importer.import(&contract_id) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                    process::exit(1);
                }
            };

            let json = serde_json::to_string_pretty(&abi).expect("JSON serialization failed");
            if let Some(output_path) = o {
                fs::write(&output_path, &json).unwrap_or_else(|e| {
                    eprintln!(
                        "{}{}error{}: cannot write {}: {}",
                        c.red, c.bold, c.reset, output_path, e
                    );
                    process::exit(1);
                });
            } else {
                println!("{}", json);
            }
        }

        Commands::Run {
            file,
            secret_key,
            env,
            rpc_url,
            dry_run,
            json,
            yes,
        } => {
            let source = read_file(&file, c);
            match run_pipeline(&source, &file, c) {
                PipelineResult::Compiled(ir) => {
                    // 1. Resolve secret key
                    let sk = resolve_secret_key(secret_key.as_deref(), &env, c);

                    // 2. Validate secret key format early
                    if let Err(e) = callsoro_exec::decode_secret_key(&sk) {
                        eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                        process::exit(1);
                    }

                    // 3. Compile to XDR
                    let transactions = match XdrCompiler::compile(&ir) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                            process::exit(1);
                        }
                    };

                    // 4. Resolve RPC URL
                    let url = match callsoro_exec::simulator::resolve_rpc_url(
                        rpc_url.as_deref(),
                        &ir.network,
                    ) {
                        Ok(u) => u,
                        Err(e) => {
                            eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                            process::exit(1);
                        }
                    };

                    // 5. Mainnet confirmation
                    if ir.network == "mainnet"
                        && !yes
                        && !dry_run
                        && !confirm_mainnet_execution(&ir, c)
                    {
                        eprintln!("Cancelled.");
                        process::exit(0);
                    }

                    // 6. Execute
                    let config = ExecutorConfig {
                        secret_key: sk,
                        dry_run,
                        ..Default::default()
                    };
                    let executor = Executor::new(&url, config);

                    match executor.execute(&transactions, &ir) {
                        Ok(results) => {
                            if json {
                                let json_out = serde_json::to_string_pretty(&results)
                                    .expect("JSON serialization failed");
                                println!("{}", json_out);
                            } else {
                                for result in &results {
                                    print!(
                                        "{}",
                                        format_execution_result(
                                            result,
                                            results.len(),
                                            &ir.network,
                                            c
                                        )
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("{}{}error{}: {}", c.red, c.bold, c.reset, e);
                            process::exit(1);
                        }
                    }
                }
                PipelineResult::Errors => process::exit(1),
            }
        }

        Commands::Version => {
            println!("callsoro v{}", env!("CARGO_PKG_VERSION"));
        }
    }
}

/// Resolve secret key from --secret-key flag or environment variable.
fn resolve_secret_key(explicit: Option<&str>, env_var: &str, c: &Colors) -> String {
    if let Some(sk) = explicit {
        eprintln!(
            "{}warning{}: passing secret keys via CLI arguments may expose them in shell history",
            c.yellow, c.reset
        );
        return sk.to_string();
    }

    match std::env::var(env_var) {
        Ok(sk) if !sk.is_empty() => sk,
        _ => {
            eprintln!(
                "{}{}error{}: no secret key provided. Use --secret-key SK... or set {}",
                c.red, c.bold, c.reset, env_var
            );
            process::exit(1);
        }
    }
}

/// Interactive mainnet confirmation prompt.
fn confirm_mainnet_execution(ir: &JsonIR, c: &Colors) -> bool {
    let count = ir.calls.len();
    let fee_per_tx = ir.signing.fee_stroops;
    let total_fee = fee_per_tx * count as u64;
    let xlm = total_fee as f64 / 10_000_000.0;

    eprintln!(
        "\n{}WARNING{}: This will submit {} transaction(s) to {}MAINNET{}",
        c.yellow, c.reset, count, c.bold, c.reset
    );
    eprintln!("Estimated base fee: {} stroops ({:.7} XLM)", total_fee, xlm);
    eprint!("Continue? [y/N] ");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap_or(0);
    input.trim().eq_ignore_ascii_case("y")
}

/// Format a single execution result for human-readable output.
fn format_execution_result(
    result: &ExecutionResult,
    total_calls: usize,
    network: &str,
    c: &Colors,
) -> String {
    let contract_short = if result.contract.len() > 10 {
        format!(
            "{}...{}",
            &result.contract[..4],
            &result.contract[result.contract.len() - 4..]
        )
    } else {
        result.contract.clone()
    };

    let mut out = format!(
        "Executing call {}/{}: {}.{}()\n",
        result.call_index + 1,
        total_calls,
        contract_short,
        result.method
    );

    match &result.outcome {
        ExecutionOutcome::Success {
            tx_hash,
            ledger,
            fee_charged,
            return_value,
        } => {
            out.push_str(&format!(
                "  Simulating...    {}OK{} (fee: {} stroops)\n",
                c.bold, c.reset, fee_charged
            ));
            out.push_str(&format!("  Signing...       {}OK{}\n", c.bold, c.reset));
            let hash_short = if tx_hash.len() > 8 {
                &tx_hash[..8]
            } else {
                tx_hash
            };
            out.push_str(&format!(
                "  Submitting...    {}OK{} (hash: {}...)\n",
                c.bold, c.reset, hash_short
            ));
            out.push_str(&format!(
                "  Waiting...       {}SUCCESS{} (ledger: {})\n",
                c.bold, c.reset, ledger
            ));
            let ret = return_value.as_deref().unwrap_or("void");
            out.push_str(&format!("  Return value:    {}\n", ret));
            out.push_str(&format!("\n  Transaction: {}\n", tx_hash));

            let explorer_net = match network {
                "testnet" => "testnet",
                "mainnet" => "public",
                other => other,
            };
            out.push_str(&format!(
                "  Explorer:    https://stellar.expert/explorer/{}/tx/{}\n",
                explorer_net, tx_hash
            ));
        }
        ExecutionOutcome::Failed { tx_hash, error } => {
            out.push_str(&format!("  Status:     {}FAILED{}\n", c.red, c.reset));
            out.push_str(&format!("  Error:      {}\n", error));
            if let Some(hash) = tx_hash {
                out.push_str(&format!("  Hash:       {}\n", hash));
            }
        }
        ExecutionOutcome::Simulated { fee, return_value } => {
            out.push_str(&format!(
                "  Simulating...    {}OK{} (fee: {} stroops)\n",
                c.bold, c.reset, fee
            ));
            let ret = return_value.as_deref().unwrap_or("void");
            out.push_str(&format!("  Return value:    {}\n", ret));
            out.push_str("  (dry-run mode: transaction not submitted)\n");
        }
    }

    out
}

fn read_file(path: &str, c: &Colors) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!(
            "{}{}error{}: cannot read {}: {}",
            c.red, c.bold, c.reset, path, e
        );
        process::exit(1);
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    fn cargo_bin() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop(); // crates/
        path.pop(); // project root
        path.push("target");
        path.push("debug");
        path.push("callsoro");
        path
    }

    fn fixtures_dir() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("tests");
        path.push("fixtures");
        path
    }

    fn build_binary() {
        let status = Command::new("cargo")
            .args(["build", "--bin", "callsoro"])
            .status()
            .expect("failed to build");
        assert!(status.success(), "cargo build failed");
    }

    // ---- Compile ----

    #[test]
    fn compile_valid_stdout() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "compile",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output.status.success(), "exit code was not 0");
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout is not valid JSON");
        assert_eq!(json["version"], 1);
        assert_eq!(json["network"], "testnet");
    }

    #[test]
    fn compile_output_file() {
        build_binary();
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let tmp_path = tmp.path().to_str().unwrap().to_string();
        let output = Command::new(cargo_bin())
            .args([
                "compile",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
                "-o",
                &tmp_path,
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output.status.success(), "exit code was not 0");
        let contents = std::fs::read_to_string(&tmp_path).expect("cannot read output file");
        let json: serde_json::Value =
            serde_json::from_str(&contents).expect("output file is not valid JSON");
        assert_eq!(json["version"], 1);
    }

    #[test]
    fn compile_matches_expected() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "compile",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output.status.success());
        let actual: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout is not valid JSON");
        let expected_str =
            std::fs::read_to_string(fixtures_dir().join("transfer.expected.json")).unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(&expected_str).expect("expected file is not valid JSON");
        assert_eq!(actual, expected);
    }

    #[test]
    fn compile_with_error_exits_1() {
        build_binary();
        let tmp = write_temp_soro("network badnet\nsource GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\ncall CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4 foo()");
        let output = Command::new(cargo_bin())
            .args(["compile", tmp.path().to_str().unwrap()])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "should have exit code 1");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("error"), "stderr should contain error");
    }

    // ---- Check ----

    #[test]
    fn check_valid() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "check",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output.status.success(), "exit code was not 0");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("No errors found"),
            "should say no errors: {}",
            stderr
        );
    }

    #[test]
    fn check_with_warnings() {
        build_binary();
        // fee 50 triggers low-fee warning
        let tmp = write_temp_soro("network testnet\nsource GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\nfee 50\ncall CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4 foo()");
        let output = Command::new(cargo_bin())
            .args(["check", tmp.path().to_str().unwrap()])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output.status.success(), "warnings-only should exit 0");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("warning"), "stderr should contain warning");
    }

    #[test]
    fn check_with_errors() {
        build_binary();
        let tmp = write_temp_soro("network badnet\nsource GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\ncall CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4 foo()");
        let output = Command::new(cargo_bin())
            .args(["check", tmp.path().to_str().unwrap()])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "errors should exit 1");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("error"), "stderr should contain error");
    }

    // ---- Fmt ----

    #[test]
    fn fmt_idempotent() {
        build_binary();
        let fixture = fixtures_dir().join("transfer.soro");
        let output1 = Command::new(cargo_bin())
            .args(["fmt", fixture.to_str().unwrap()])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output1.status.success());

        // Write first output to temp, then fmt again
        let tmp = write_temp_soro(&String::from_utf8_lossy(&output1.stdout));
        let output2 = Command::new(cargo_bin())
            .args(["fmt", tmp.path().to_str().unwrap()])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output2.status.success());
        assert_eq!(output1.stdout, output2.stdout, "fmt should be idempotent");
    }

    #[test]
    fn fmt_write_in_place() {
        build_binary();
        let original = std::fs::read_to_string(fixtures_dir().join("transfer.soro")).unwrap();
        let tmp = write_temp_soro(&original);
        let output = Command::new(cargo_bin())
            .args(["fmt", tmp.path().to_str().unwrap(), "--write"])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output.status.success());
        let written = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(!written.is_empty(), "file should not be empty");
        assert!(
            written.starts_with("network"),
            "should start with network directive"
        );
    }

    // ---- File not found ----

    #[test]
    fn file_not_found() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args(["compile", "nonexistent.soro"])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "should exit 1");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("error") && stderr.contains("cannot read"),
            "stderr: {}",
            stderr
        );
    }

    // ---- Pipe friendly ----

    #[test]
    fn pipe_friendly_json() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "compile",
                fixtures_dir().join("minimal.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output.status.success());
        let _: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("output should be parseable JSON");
    }

    // ---- Version ----

    #[test]
    fn version_command() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args(["version"])
            .output()
            .expect("failed to run");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("callsoro v"), "stdout: {}", stdout);
    }

    // ---- All fixtures compile ----

    #[test]
    fn all_fixtures_compile() {
        build_binary();
        for name in &[
            "transfer.soro",
            "minimal.soro",
            "all_types.soro",
            "multi_call.soro",
            "with_consts.soro",
            "interface_call.soro",
        ] {
            let output = Command::new(cargo_bin())
                .args(["compile", fixtures_dir().join(name).to_str().unwrap()])
                .arg("--no-color")
                .output()
                .unwrap_or_else(|e| panic!("failed to run for {}: {}", name, e));
            assert!(
                output.status.success(),
                "{} failed: {}",
                name,
                String::from_utf8_lossy(&output.stderr)
            );
            let _: serde_json::Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|e| panic!("{} produced invalid JSON: {}", name, e));
        }
    }

    // ---- XDR ----

    #[test]
    fn xdr_produces_valid_base64() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "xdr",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output.status.success(), "exit code was not 0");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let b64 = stdout.trim();
        assert!(!b64.is_empty(), "xdr output should not be empty");
        // Verify it's valid base64 by decoding it back
        use stellar_xdr::curr::{InvokeContractArgs, Limits, ReadXdr};
        let decoded = InvokeContractArgs::from_xdr_base64(b64, Limits::none());
        assert!(decoded.is_ok(), "should be valid XDR base64: {:?}", decoded);
    }

    #[test]
    fn xdr_output_file() {
        build_binary();
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let tmp_path = tmp.path().to_str().unwrap().to_string();
        let output = Command::new(cargo_bin())
            .args([
                "xdr",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
                "-o",
                &tmp_path,
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output.status.success(), "exit code was not 0");
        let contents = std::fs::read_to_string(&tmp_path).expect("cannot read output file");
        assert!(!contents.is_empty(), "output file should not be empty");
    }

    #[test]
    fn xdr_multi_call() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "xdr",
                fixtures_dir().join("multi_call.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output.status.success(), "exit code was not 0");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<_> = stdout.trim().lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "multi_call.soro has 2 calls, expect 2 XDR lines"
        );
    }

    #[test]
    fn xdr_all_fixtures() {
        build_binary();
        for name in &[
            "transfer.soro",
            "minimal.soro",
            "all_types.soro",
            "multi_call.soro",
            "with_consts.soro",
        ] {
            let output = Command::new(cargo_bin())
                .args(["xdr", fixtures_dir().join(name).to_str().unwrap()])
                .arg("--no-color")
                .output()
                .unwrap_or_else(|e| panic!("failed to run for {}: {}", name, e));
            assert!(
                output.status.success(),
                "{} failed: {}",
                name,
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                !stdout.trim().is_empty(),
                "{} produced empty xdr output",
                name
            );
        }
    }

    // ---- Consts ----

    #[test]
    fn consts_produce_identical_output() {
        build_binary();
        // Compile transfer.soro (no consts)
        let output_no_consts = Command::new(cargo_bin())
            .args([
                "compile",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output_no_consts.status.success());

        // Compile with_consts.soro (uses consts, should produce same JSON)
        let output_with_consts = Command::new(cargo_bin())
            .args([
                "compile",
                fixtures_dir().join("with_consts.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(output_with_consts.status.success());

        let json_a: serde_json::Value = serde_json::from_slice(&output_no_consts.stdout).unwrap();
        let json_b: serde_json::Value = serde_json::from_slice(&output_with_consts.stdout).unwrap();
        assert_eq!(
            json_a, json_b,
            "const expansion should produce identical JSON"
        );
    }

    #[test]
    fn undefined_const_exits_1() {
        build_binary();
        let tmp = write_temp_soro(
            "network testnet\nsource GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\ncall CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4 f(missing)",
        );
        let output = Command::new(cargo_bin())
            .args(["compile", tmp.path().to_str().unwrap()])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("undefined name 'missing'"),
            "stderr: {}",
            stderr
        );
    }

    // ---- Simulate ----

    #[test]
    fn simulate_help_shows_subcommand() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args(["simulate", "--help"])
            .output()
            .expect("failed to run");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--rpc-url"), "stdout: {}", stdout);
        assert!(stdout.contains("--json"), "stdout: {}", stdout);
    }

    #[test]
    fn simulate_unreachable_rpc_exits_1() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "simulate",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
                "--rpc-url",
                "http://127.0.0.1:1",
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "should exit 1 on unreachable RPC");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("error"),
            "stderr should contain error: {}",
            stderr
        );
    }

    #[test]
    fn simulate_json_flag_accepted() {
        build_binary();
        // This will fail at the network layer but --json should be accepted as a flag
        let output = Command::new(cargo_bin())
            .args([
                "simulate",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
                "--rpc-url",
                "http://127.0.0.1:1",
                "--json",
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        // Exit 1 because unreachable, but the flag was accepted (no "unknown flag" error)
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument"),
            "should accept --json flag: {}",
            stderr
        );
    }

    #[test]
    fn simulate_missing_rpc_url_uses_default() {
        build_binary();
        // transfer.soro uses testnet, so it should use the default testnet URL
        // The call will fail (we're not on testnet) but it should attempt the connection
        let output = Command::new(cargo_bin())
            .args([
                "simulate",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .env_remove("CALLSORO_RPC_URL")
            .output()
            .expect("failed to run");
        // It will fail (network) but NOT with "no default RPC URL" error
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("no default RPC URL"),
            "should resolve default testnet URL: {}",
            stderr
        );
    }

    // ---- Import ----

    #[test]
    fn import_help_shows_subcommand() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args(["import", "--help"])
            .output()
            .expect("failed to run");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--network"), "stdout: {}", stdout);
        assert!(stdout.contains("--rpc-url"), "stdout: {}", stdout);
    }

    #[test]
    fn import_unreachable_rpc_exits_1() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "import",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
                "--rpc-url",
                "http://127.0.0.1:1",
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "should exit 1 on unreachable RPC");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("error"),
            "stderr should contain error: {}",
            stderr
        );
    }

    #[test]
    fn import_invalid_contract_id_exits_1() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args(["import", "INVALID", "--rpc-url", "http://127.0.0.1:1"])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "should exit 1 on invalid ID");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("invalid contract ID"),
            "stderr should mention invalid contract ID: {}",
            stderr
        );
    }

    // ---- Interface calls ----

    #[test]
    fn compile_interface_call_succeeds() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "compile",
                fixtures_dir().join("interface_call.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(
            output.status.success(),
            "exit code was not 0: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout is not valid JSON");
        assert_eq!(json["version"], 1);
        // The "_" placeholder should be resolved to the contract ID from the ABI
        assert_eq!(
            json["calls"][0]["contract"],
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        );
        assert_eq!(json["calls"][0]["method"], "transfer");
    }

    #[test]
    fn compile_unknown_method_fails() {
        build_binary();
        let tmp = write_temp_soro_with_abi(
            "use \"token.soroabi\" as Token\nnetwork testnet\nsource GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\ncall Token.trasfer()",
        );
        let output = Command::new(cargo_bin())
            .args(["compile", tmp.path().to_str().unwrap()])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "should exit 1");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not found") && stderr.contains("did you mean 'transfer'"),
            "stderr: {}",
            stderr
        );
    }

    #[test]
    fn compile_missing_abi_file_fails() {
        build_binary();
        let tmp = write_temp_soro(
            "use \"nonexistent.soroabi\" as Token\nnetwork testnet\nsource GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\ncall Token.transfer()",
        );
        let output = Command::new(cargo_bin())
            .args(["compile", tmp.path().to_str().unwrap()])
            .arg("--no-color")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "should exit 1");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("cannot read ABI file"),
            "stderr: {}",
            stderr
        );
    }

    // ---- Run ----

    #[test]
    fn run_help_shows_subcommand() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args(["run", "--help"])
            .output()
            .expect("failed to run");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--secret-key"), "stdout: {}", stdout);
        assert!(stdout.contains("--dry-run"), "stdout: {}", stdout);
        assert!(stdout.contains("--json"), "stdout: {}", stdout);
        assert!(stdout.contains("--yes"), "stdout: {}", stdout);
        assert!(stdout.contains("--env"), "stdout: {}", stdout);
    }

    #[test]
    fn run_missing_secret_key_exits_1() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "run",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
            ])
            .arg("--no-color")
            .env_remove("SORO_SECRET_KEY")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "should exit 1 without secret key");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("no secret key provided"),
            "stderr: {}",
            stderr
        );
    }

    #[test]
    fn run_invalid_secret_key_exits_1() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "run",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
                "--secret-key",
                "INVALID_KEY",
            ])
            .arg("--no-color")
            .env_remove("SORO_SECRET_KEY")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "should exit 1 on invalid key");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("invalid secret key"), "stderr: {}", stderr);
    }

    #[test]
    fn run_secret_key_from_env_accepted() {
        build_binary();
        // Use a valid-format secret key (won't actually work on-chain but parses correctly)
        let sk = stellar_strkey::Strkey::PrivateKeyEd25519(stellar_strkey::ed25519::PrivateKey(
            [1u8; 32],
        ));
        let sk_str: String = {
            let h = sk.to_string();
            String::from(h.as_str())
        };
        let output = Command::new(cargo_bin())
            .args([
                "run",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
                "--rpc-url",
                "http://127.0.0.1:1",
            ])
            .arg("--no-color")
            .env("SORO_SECRET_KEY", &sk_str)
            .output()
            .expect("failed to run");
        // Will fail at network layer, but should NOT fail with "no secret key" or "invalid secret key"
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("no secret key provided"),
            "should pick up env var: {}",
            stderr
        );
        assert!(
            !stderr.contains("invalid secret key"),
            "env key should be valid: {}",
            stderr
        );
    }

    #[test]
    fn run_dry_run_flag_accepted() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "run",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
                "--secret-key",
                "INVALID",
                "--dry-run",
            ])
            .arg("--no-color")
            .env_remove("SORO_SECRET_KEY")
            .output()
            .expect("failed to run");
        // Will fail on invalid key, but --dry-run should be accepted (no "unexpected argument")
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument"),
            "should accept --dry-run: {}",
            stderr
        );
    }

    #[test]
    fn run_json_flag_accepted() {
        build_binary();
        let output = Command::new(cargo_bin())
            .args([
                "run",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
                "--secret-key",
                "INVALID",
                "--json",
            ])
            .arg("--no-color")
            .env_remove("SORO_SECRET_KEY")
            .output()
            .expect("failed to run");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument"),
            "should accept --json: {}",
            stderr
        );
    }

    #[test]
    fn run_unreachable_rpc_exits_1() {
        build_binary();
        let sk = stellar_strkey::Strkey::PrivateKeyEd25519(stellar_strkey::ed25519::PrivateKey(
            [1u8; 32],
        ));
        let sk_str: String = {
            let h = sk.to_string();
            String::from(h.as_str())
        };
        let output = Command::new(cargo_bin())
            .args([
                "run",
                fixtures_dir().join("transfer.soro").to_str().unwrap(),
                "--secret-key",
                &sk_str,
                "--rpc-url",
                "http://127.0.0.1:1",
            ])
            .arg("--no-color")
            .env_remove("SORO_SECRET_KEY")
            .output()
            .expect("failed to run");
        assert!(!output.status.success(), "should exit 1 on unreachable RPC");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("error"),
            "stderr should contain error: {}",
            stderr
        );
    }

    // ---- Helper ----

    fn write_temp_soro(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut tmp = tempfile::Builder::new()
            .suffix(".soro")
            .tempfile()
            .expect("failed to create temp");
        tmp.write_all(content.as_bytes()).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    /// Write a temp .soro file and copy token.soroabi next to it.
    fn write_temp_soro_with_abi(content: &str) -> tempfile::NamedTempFile {
        let tmp = write_temp_soro(content);
        let abi_src = fixtures_dir().join("token.soroabi");
        let abi_dst = tmp.path().parent().unwrap().join("token.soroabi");
        std::fs::copy(&abi_src, &abi_dst).expect("failed to copy token.soroabi");
        tmp
    }
}
