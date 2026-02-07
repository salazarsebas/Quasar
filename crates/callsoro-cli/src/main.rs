use std::fs;
use std::process;

use callsoro_check::{Diagnostic, Resolver, Severity, Validator};
use callsoro_compile::{Compiler, JsonIR, XdrCompiler};
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

// ---------------------------------------------------------------------------
// Pipeline helpers
// ---------------------------------------------------------------------------

enum PipelineResult {
    Compiled(JsonIR),
    Errors,
}

fn run_pipeline(source: &str, path: &str, c: &Colors) -> PipelineResult {
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

    // Compile
    let ir = Compiler::compile(&program);
    PipelineResult::Compiled(ir)
}

// ---------------------------------------------------------------------------
// Formatter
// ---------------------------------------------------------------------------

fn format_program(program: &Program) -> String {
    let mut out = String::new();

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
    out.push_str(&format!("call {} {}(", call.contract, call.method));
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

        Commands::Check { file } => {
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

            if all_diags.is_empty() {
                eprintln!("No errors found.");
            } else {
                for diag in &all_diags {
                    eprintln!("{}", format_diagnostic(diag, &source, &file, c));
                }
            }

            if has_errors {
                process::exit(1);
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

        Commands::Version => {
            println!("callsoro v{}", env!("CARGO_PKG_VERSION"));
        }
    }
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
}
