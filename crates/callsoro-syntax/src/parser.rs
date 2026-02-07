use crate::ast::{Call, ConstDecl, ConstValue, Directive, MapEntry, Program, Value};
use crate::lexer::{Token, TokenKind};
use crate::span::Span;
use std::fmt;

/// An error encountered during parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub span: Span,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "error at line {}, col {}: {}",
            self.span.line, self.span.col, self.message
        )
    }
}

impl ParseError {
    pub fn format_with_source(&self, source: &str) -> String {
        let line_content = source.lines().nth(self.span.line - 1).unwrap_or("");
        let col = self.span.col;
        let underline_len = if self.span.end > self.span.start {
            self.span.end - self.span.start
        } else {
            1
        };

        format!(
            "error: {}\n --> line {}:{}\n  |\n{} | {}\n  | {}{}\n",
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

/// Recursive descent parser for `.soro` scripts.
pub struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    /// Parse the full token stream into a `Program`.
    pub fn parse(tokens: &[Token]) -> Result<Program, ParseError> {
        let mut parser = Parser::new(tokens);
        parser.parse_program()
    }

    // ── Helpers ─────────────────────────────────────────────────────

    fn peek(&self) -> &TokenKind {
        self.tokens
            .get(self.pos)
            .map(|t| &t.kind)
            .unwrap_or(&TokenKind::Eof)
    }

    fn current_span(&self) -> Span {
        self.tokens
            .get(self.pos)
            .map(|t| t.span)
            .unwrap_or(Span::new(0, 0, 1, 1))
    }

    fn advance(&mut self) -> &Token {
        let token = &self.tokens[self.pos];
        self.pos += 1;
        token
    }

    fn skip_newlines(&mut self) {
        while self.peek() == &TokenKind::Newline {
            self.advance();
        }
    }

    fn expect(&mut self, expected: &TokenKind) -> Result<&Token, ParseError> {
        // Skip newlines before checking (allows multiline constructs)
        if !matches!(expected, TokenKind::Newline) {
            self.skip_newlines();
        }

        let span = self.current_span();
        let actual = self.peek().clone();
        if &actual == expected {
            Ok(self.advance())
        } else {
            Err(ParseError {
                message: format!("expected '{}' but found '{}'", expected, actual),
                span,
            })
        }
    }

    fn expect_ident(&mut self) -> Result<(String, Span), ParseError> {
        self.skip_newlines();
        let span = self.current_span();
        match self.peek().clone() {
            TokenKind::Ident(name) => {
                self.advance();
                Ok((name, span))
            }
            other => Err(ParseError {
                message: format!("expected identifier but found '{}'", other),
                span,
            }),
        }
    }

    fn expect_string(&mut self) -> Result<(String, Span), ParseError> {
        self.skip_newlines();
        let span = self.current_span();
        match self.peek().clone() {
            TokenKind::String(s) => {
                let token = self.advance();
                Ok((s, token.span))
            }
            other => Err(ParseError {
                message: format!("expected string but found '{}'", other),
                span,
            }),
        }
    }

    fn expect_number(&mut self) -> Result<(String, Span), ParseError> {
        self.skip_newlines();
        let span = self.current_span();
        match self.peek().clone() {
            TokenKind::Number(n) => {
                self.advance();
                Ok((n, span))
            }
            other => Err(ParseError {
                message: format!("expected number but found '{}'", other),
                span,
            }),
        }
    }

    // ── Program ─────────────────────────────────────────────────────

    fn parse_program(&mut self) -> Result<Program, ParseError> {
        let mut consts = Vec::new();
        let mut directives = Vec::new();
        let mut calls = Vec::new();

        self.skip_newlines();

        // Parse const declarations (must come first)
        while self.peek() == &TokenKind::Const {
            consts.push(self.parse_const()?);
            self.skip_newlines();
        }

        while self.peek() != &TokenKind::Eof {
            match self.peek() {
                TokenKind::Network => directives.push(self.parse_network()?),
                TokenKind::Source => directives.push(self.parse_source()?),
                TokenKind::Fee => directives.push(self.parse_fee()?),
                TokenKind::Timeout => directives.push(self.parse_timeout()?),
                TokenKind::Call => calls.push(self.parse_call()?),
                TokenKind::Const => {
                    return Err(ParseError {
                        message: "'const' declarations must appear before directives and calls"
                            .to_string(),
                        span: self.current_span(),
                    });
                }
                other => {
                    return Err(ParseError {
                        message: format!(
                            "expected 'network', 'source', 'fee', 'timeout', or 'call' but found '{}'",
                            other
                        ),
                        span: self.current_span(),
                    });
                }
            }
            self.skip_newlines();
        }

        Ok(Program {
            consts,
            directives,
            calls,
        })
    }

    // ── Directives ──────────────────────────────────────────────────

    fn parse_network(&mut self) -> Result<Directive, ParseError> {
        let start = self.current_span();
        self.advance(); // consume 'network'
        let (value, end) = self.expect_ident_or_string()?;
        Ok(Directive::Network {
            value,
            span: Span::new(start.start, end.end, start.line, start.col),
        })
    }

    fn parse_source(&mut self) -> Result<Directive, ParseError> {
        let start = self.current_span();
        self.advance(); // consume 'source'
        let (value, end) = self.expect_ident()?;
        Ok(Directive::Source {
            value,
            span: Span::new(start.start, end.end, start.line, start.col),
        })
    }

    fn parse_fee(&mut self) -> Result<Directive, ParseError> {
        let start = self.current_span();
        self.advance(); // consume 'fee'
        let (num_str, end) = self.expect_number()?;
        let value = num_str.parse::<u64>().map_err(|_| ParseError {
            message: format!(
                "invalid fee value '{}' (must be a positive integer)",
                num_str
            ),
            span: end,
        })?;
        Ok(Directive::Fee {
            value,
            span: Span::new(start.start, end.end, start.line, start.col),
        })
    }

    fn parse_timeout(&mut self) -> Result<Directive, ParseError> {
        let start = self.current_span();
        self.advance(); // consume 'timeout'
        let (num_str, end) = self.expect_number()?;
        let value = num_str.parse::<u64>().map_err(|_| ParseError {
            message: format!(
                "invalid timeout value '{}' (must be a positive integer)",
                num_str
            ),
            span: end,
        })?;
        Ok(Directive::Timeout {
            value,
            span: Span::new(start.start, end.end, start.line, start.col),
        })
    }

    /// Accept either an identifier or a string for the network directive value.
    /// `network testnet` or `network "Custom Passphrase"`
    fn expect_ident_or_string(&mut self) -> Result<(String, Span), ParseError> {
        self.skip_newlines();
        let span = self.current_span();
        match self.peek().clone() {
            TokenKind::Ident(s) => {
                self.advance();
                Ok((s, span))
            }
            TokenKind::String(s) => {
                let token = self.advance();
                Ok((s, token.span))
            }
            other => Err(ParseError {
                message: format!(
                    "expected network name or passphrase string but found '{}'",
                    other
                ),
                span,
            }),
        }
    }

    // ── Const ────────────────────────────────────────────────────────

    fn parse_const(&mut self) -> Result<ConstDecl, ParseError> {
        let start = self.current_span();
        self.advance(); // consume 'const'
        let (name, _) = self.expect_ident()?;
        self.expect(&TokenKind::Eq)?;

        // Value: either a bare string or a typed value
        self.skip_newlines();
        let value = if matches!(self.peek(), TokenKind::String(_)) {
            let (s, s_span) = self.expect_string()?;
            ConstValue::String(s, s_span)
        } else {
            ConstValue::Typed(self.parse_value()?)
        };

        let end = value.span();
        Ok(ConstDecl {
            name,
            value,
            span: Span::new(start.start, end.end, start.line, start.col),
        })
    }

    // ── Call ─────────────────────────────────────────────────────────

    fn parse_call(&mut self) -> Result<Call, ParseError> {
        let start = self.current_span();
        self.advance(); // consume 'call'

        let (contract, _) = self.expect_ident()?;
        let (method, _) = self.expect_ident()?;

        self.expect(&TokenKind::LParen)?;
        let args = self.parse_arg_list()?;
        let end_token = self.expect(&TokenKind::RParen)?;

        Ok(Call {
            contract,
            method,
            args,
            span: Span::new(start.start, end_token.span.end, start.line, start.col),
        })
    }

    /// Parse a comma-separated list of values. Allows trailing commas and newlines.
    fn parse_arg_list(&mut self) -> Result<Vec<Value>, ParseError> {
        let mut args = Vec::new();

        self.skip_newlines();

        // Empty arg list
        if self.peek() == &TokenKind::RParen {
            return Ok(args);
        }

        args.push(self.parse_value()?);

        loop {
            self.skip_newlines();
            if self.peek() == &TokenKind::Comma {
                self.advance(); // consume comma
                self.skip_newlines();
                // Allow trailing comma before )
                if self.peek() == &TokenKind::RParen {
                    break;
                }
                args.push(self.parse_value()?);
            } else {
                break;
            }
        }

        Ok(args)
    }

    // ── Values ──────────────────────────────────────────────────────

    fn parse_value(&mut self) -> Result<Value, ParseError> {
        self.skip_newlines();
        let span = self.current_span();

        match self.peek().clone() {
            TokenKind::Ident(name) => {
                self.advance();
                match name.as_str() {
                    "bool" => self.parse_bool(span),
                    "u32" => self.parse_u32(span),
                    "i32" => self.parse_i32(span),
                    "u64" => self.parse_u64(span),
                    "i64" => self.parse_i64(span),
                    "u128" => self.parse_string_value(span, "u128"),
                    "i128" => self.parse_string_value(span, "i128"),
                    "u256" => self.parse_string_value(span, "u256"),
                    "i256" => self.parse_string_value(span, "i256"),
                    "string" => self.parse_string_value(span, "string"),
                    "symbol" => self.parse_string_value(span, "symbol"),
                    "bytes" => self.parse_string_value(span, "bytes"),
                    "address" => self.parse_string_value(span, "address"),
                    "vec" => self.parse_vec(span),
                    "map" => self.parse_map(span),
                    _ => Ok(Value::Ident(name, span)),
                }
            }
            other => Err(ParseError {
                message: format!("expected value type but found '{}'", other),
                span,
            }),
        }
    }

    fn parse_bool(&mut self, start: Span) -> Result<Value, ParseError> {
        self.expect(&TokenKind::LParen)?;
        self.skip_newlines();

        let value = match self.peek() {
            TokenKind::True => {
                self.advance();
                true
            }
            TokenKind::False => {
                self.advance();
                false
            }
            other => {
                return Err(ParseError {
                    message: format!("expected 'true' or 'false' but found '{}'", other),
                    span: self.current_span(),
                });
            }
        };

        let end = self.expect(&TokenKind::RParen)?;
        Ok(Value::Bool(
            value,
            Span::new(start.start, end.span.end, start.line, start.col),
        ))
    }

    fn parse_u32(&mut self, start: Span) -> Result<Value, ParseError> {
        self.expect(&TokenKind::LParen)?;
        let (num_str, num_span) = self.expect_number()?;
        let value = num_str.parse::<u32>().map_err(|_| ParseError {
            message: format!("'{}' is not a valid u32 (0..4294967295)", num_str),
            span: num_span,
        })?;
        let end = self.expect(&TokenKind::RParen)?;
        Ok(Value::U32(
            value,
            Span::new(start.start, end.span.end, start.line, start.col),
        ))
    }

    fn parse_i32(&mut self, start: Span) -> Result<Value, ParseError> {
        self.expect(&TokenKind::LParen)?;
        self.skip_newlines();

        let negative = if self.peek() == &TokenKind::Minus {
            self.advance();
            true
        } else {
            false
        };

        let (num_str, num_span) = self.expect_number()?;
        let full = if negative {
            format!("-{}", num_str)
        } else {
            num_str.clone()
        };

        let value = full.parse::<i32>().map_err(|_| ParseError {
            message: format!("'{}' is not a valid i32 (-2147483648..2147483647)", full),
            span: num_span,
        })?;
        let end = self.expect(&TokenKind::RParen)?;
        Ok(Value::I32(
            value,
            Span::new(start.start, end.span.end, start.line, start.col),
        ))
    }

    fn parse_u64(&mut self, start: Span) -> Result<Value, ParseError> {
        self.expect(&TokenKind::LParen)?;
        let (num_str, num_span) = self.expect_number()?;
        let value = num_str.parse::<u64>().map_err(|_| ParseError {
            message: format!("'{}' is not a valid u64 (0..18446744073709551615)", num_str),
            span: num_span,
        })?;
        let end = self.expect(&TokenKind::RParen)?;
        Ok(Value::U64(
            value,
            Span::new(start.start, end.span.end, start.line, start.col),
        ))
    }

    fn parse_i64(&mut self, start: Span) -> Result<Value, ParseError> {
        self.expect(&TokenKind::LParen)?;
        self.skip_newlines();

        let negative = if self.peek() == &TokenKind::Minus {
            self.advance();
            true
        } else {
            false
        };

        let (num_str, num_span) = self.expect_number()?;
        let full = if negative {
            format!("-{}", num_str)
        } else {
            num_str.clone()
        };

        let value = full.parse::<i64>().map_err(|_| ParseError {
            message: format!("'{}' is not a valid i64", full),
            span: num_span,
        })?;
        let end = self.expect(&TokenKind::RParen)?;
        Ok(Value::I64(
            value,
            Span::new(start.start, end.span.end, start.line, start.col),
        ))
    }

    /// Parse types that take a single string argument:
    /// `i128("...")`, `u128("...")`, `string("...")`, `symbol("...")`,
    /// `bytes("...")`, `address("...")`, `u256("...")`, `i256("...")`
    fn parse_string_value(&mut self, start: Span, type_name: &str) -> Result<Value, ParseError> {
        self.expect(&TokenKind::LParen)?;
        let (s, _) = self.expect_string()?;
        let end = self.expect(&TokenKind::RParen)?;
        let span = Span::new(start.start, end.span.end, start.line, start.col);

        Ok(match type_name {
            "u128" => Value::U128(s, span),
            "i128" => Value::I128(s, span),
            "u256" => Value::U256(s, span),
            "i256" => Value::I256(s, span),
            "string" => Value::String(s, span),
            "symbol" => Value::Symbol(s, span),
            "bytes" => Value::Bytes(s, span),
            "address" => Value::Address(s, span),
            _ => unreachable!(),
        })
    }

    fn parse_vec(&mut self, start: Span) -> Result<Value, ParseError> {
        self.expect(&TokenKind::LParen)?;
        let elements = self.parse_arg_list()?;
        let end = self.expect(&TokenKind::RParen)?;
        Ok(Value::Vec(
            elements,
            Span::new(start.start, end.span.end, start.line, start.col),
        ))
    }

    fn parse_map(&mut self, start: Span) -> Result<Value, ParseError> {
        self.expect(&TokenKind::LParen)?;
        let entries = self.parse_map_entries()?;
        let end = self.expect(&TokenKind::RParen)?;
        Ok(Value::Map(
            entries,
            Span::new(start.start, end.span.end, start.line, start.col),
        ))
    }

    fn parse_map_entries(&mut self) -> Result<Vec<MapEntry>, ParseError> {
        let mut entries = Vec::new();

        self.skip_newlines();

        // Empty map
        if self.peek() == &TokenKind::RParen {
            return Ok(entries);
        }

        entries.push(self.parse_map_entry()?);

        loop {
            self.skip_newlines();
            if self.peek() == &TokenKind::Comma {
                self.advance();
                self.skip_newlines();
                if self.peek() == &TokenKind::RParen {
                    break;
                }
                entries.push(self.parse_map_entry()?);
            } else {
                break;
            }
        }

        Ok(entries)
    }

    fn parse_map_entry(&mut self) -> Result<MapEntry, ParseError> {
        let key = self.parse_value()?;
        self.expect(&TokenKind::Arrow)?;
        let value = self.parse_value()?;
        Ok(MapEntry { key, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;

    /// Helper: lex + parse in one step.
    fn parse(source: &str) -> Result<Program, ParseError> {
        let tokens = Lexer::tokenize(source).expect("lexer should not fail");
        Parser::parse(&tokens)
    }

    // ── Directives ──────────────────────────────────────────────────

    #[test]
    fn minimal_program() {
        let prog = parse("network testnet").unwrap();
        assert_eq!(prog.directives.len(), 1);
        assert_eq!(prog.calls.len(), 0);
        match &prog.directives[0] {
            Directive::Network { value, .. } => assert_eq!(value, "testnet"),
            _ => panic!("expected Network directive"),
        }
    }

    #[test]
    fn all_directives() {
        let prog = parse("network testnet\nsource GABC\nfee 100000\ntimeout 60").unwrap();
        assert_eq!(prog.directives.len(), 4);
        match &prog.directives[0] {
            Directive::Network { value, .. } => assert_eq!(value, "testnet"),
            _ => panic!("expected Network"),
        }
        match &prog.directives[1] {
            Directive::Source { value, .. } => assert_eq!(value, "GABC"),
            _ => panic!("expected Source"),
        }
        match &prog.directives[2] {
            Directive::Fee { value, .. } => assert_eq!(*value, 100000),
            _ => panic!("expected Fee"),
        }
        match &prog.directives[3] {
            Directive::Timeout { value, .. } => assert_eq!(*value, 60),
            _ => panic!("expected Timeout"),
        }
    }

    #[test]
    fn network_with_passphrase_string() {
        let prog = parse(r#"network "Test SDF Network ; September 2015""#).unwrap();
        match &prog.directives[0] {
            Directive::Network { value, .. } => {
                assert_eq!(value, "Test SDF Network ; September 2015")
            }
            _ => panic!("expected Network"),
        }
    }

    // ── Const declarations ──────────────────────────────────────────

    #[test]
    fn const_string() {
        let prog = parse("const token = \"CABC\"\ncall CABC f()").unwrap();
        assert_eq!(prog.consts.len(), 1);
        assert_eq!(prog.consts[0].name, "token");
        match &prog.consts[0].value {
            ConstValue::String(s, _) => assert_eq!(s, "CABC"),
            other => panic!("expected String, got {:?}", other),
        }
    }

    #[test]
    fn const_typed_value() {
        let prog = parse("const amount = i128(\"10000000\")\ncall CABC f(amount)").unwrap();
        assert_eq!(prog.consts.len(), 1);
        assert_eq!(prog.consts[0].name, "amount");
        match &prog.consts[0].value {
            ConstValue::Typed(Value::I128(v, _)) => assert_eq!(v, "10000000"),
            other => panic!("expected Typed(I128), got {:?}", other),
        }
    }

    #[test]
    fn const_multiple() {
        let prog =
            parse("const a = \"X\"\nconst b = u32(1)\nnetwork testnet\ncall CABC f()").unwrap();
        assert_eq!(prog.consts.len(), 2);
        assert_eq!(prog.consts[0].name, "a");
        assert_eq!(prog.consts[1].name, "b");
    }

    #[test]
    fn const_after_directive_error() {
        let err = parse("network testnet\nconst x = \"y\"").unwrap_err();
        assert!(err
            .message
            .contains("'const' declarations must appear before"));
    }

    // ── Single call ─────────────────────────────────────────────────

    #[test]
    fn call_no_args() {
        let prog = parse("call CABC method()").unwrap();
        assert_eq!(prog.calls.len(), 1);
        assert_eq!(prog.calls[0].contract, "CABC");
        assert_eq!(prog.calls[0].method, "method");
        assert!(prog.calls[0].args.is_empty());
    }

    #[test]
    fn call_single_arg() {
        let prog = parse(r#"call CABC transfer(address("GABC"))"#).unwrap();
        assert_eq!(prog.calls[0].args.len(), 1);
        match &prog.calls[0].args[0] {
            Value::Address(s, _) => assert_eq!(s, "GABC"),
            other => panic!("expected Address, got {:?}", other),
        }
    }

    #[test]
    fn call_multiple_args() {
        let src = r#"call CABC transfer(address("GA"), address("GB"), i128("100"))"#;
        let prog = parse(src).unwrap();
        assert_eq!(prog.calls[0].args.len(), 3);
    }

    #[test]
    fn call_multiline() {
        let src = "call CABC transfer(\n  u32(1),\n  u32(2)\n)";
        let prog = parse(src).unwrap();
        assert_eq!(prog.calls[0].args.len(), 2);
    }

    #[test]
    fn call_trailing_comma() {
        let src = "call CABC f(u32(1), u32(2),)";
        let prog = parse(src).unwrap();
        assert_eq!(prog.calls[0].args.len(), 2);
    }

    // ── Multiple calls ──────────────────────────────────────────────

    #[test]
    fn multiple_calls() {
        let src = "call CA f()\ncall CB g()";
        let prog = parse(src).unwrap();
        assert_eq!(prog.calls.len(), 2);
        assert_eq!(prog.calls[0].contract, "CA");
        assert_eq!(prog.calls[1].contract, "CB");
    }

    // ── Value types ─────────────────────────────────────────────────

    #[test]
    fn value_bool() {
        let prog = parse("call C f(bool(true), bool(false))").unwrap();
        match &prog.calls[0].args[0] {
            Value::Bool(v, _) => assert!(*v),
            other => panic!("expected Bool(true), got {:?}", other),
        }
        match &prog.calls[0].args[1] {
            Value::Bool(v, _) => assert!(!*v),
            other => panic!("expected Bool(false), got {:?}", other),
        }
    }

    #[test]
    fn value_u32() {
        let prog = parse("call C f(u32(42))").unwrap();
        match &prog.calls[0].args[0] {
            Value::U32(v, _) => assert_eq!(*v, 42),
            other => panic!("expected U32, got {:?}", other),
        }
    }

    #[test]
    fn value_i32_negative() {
        let prog = parse("call C f(i32(-1))").unwrap();
        match &prog.calls[0].args[0] {
            Value::I32(v, _) => assert_eq!(*v, -1),
            other => panic!("expected I32, got {:?}", other),
        }
    }

    #[test]
    fn value_i32_positive() {
        let prog = parse("call C f(i32(100))").unwrap();
        match &prog.calls[0].args[0] {
            Value::I32(v, _) => assert_eq!(*v, 100),
            other => panic!("expected I32, got {:?}", other),
        }
    }

    #[test]
    fn value_u64() {
        let prog = parse("call C f(u64(18446744073709551615))").unwrap();
        match &prog.calls[0].args[0] {
            Value::U64(v, _) => assert_eq!(*v, u64::MAX),
            other => panic!("expected U64, got {:?}", other),
        }
    }

    #[test]
    fn value_i64_negative() {
        let prog = parse("call C f(i64(-9223372036854775808))").unwrap();
        match &prog.calls[0].args[0] {
            Value::I64(v, _) => assert_eq!(*v, i64::MIN),
            other => panic!("expected I64, got {:?}", other),
        }
    }

    #[test]
    fn value_u128() {
        let prog = parse(r#"call C f(u128("340282366920938463463374607431768211455"))"#).unwrap();
        match &prog.calls[0].args[0] {
            Value::U128(v, _) => assert_eq!(v, "340282366920938463463374607431768211455"),
            other => panic!("expected U128, got {:?}", other),
        }
    }

    #[test]
    fn value_i128() {
        let prog = parse(r#"call C f(i128("-170141183460469231731687303715884105728"))"#).unwrap();
        match &prog.calls[0].args[0] {
            Value::I128(v, _) => assert_eq!(v, "-170141183460469231731687303715884105728"),
            other => panic!("expected I128, got {:?}", other),
        }
    }

    #[test]
    fn value_string() {
        let prog = parse(r#"call C f(string("hello world"))"#).unwrap();
        match &prog.calls[0].args[0] {
            Value::String(v, _) => assert_eq!(v, "hello world"),
            other => panic!("expected String, got {:?}", other),
        }
    }

    #[test]
    fn value_symbol() {
        let prog = parse(r#"call C f(symbol("transfer"))"#).unwrap();
        match &prog.calls[0].args[0] {
            Value::Symbol(v, _) => assert_eq!(v, "transfer"),
            other => panic!("expected Symbol, got {:?}", other),
        }
    }

    #[test]
    fn value_bytes() {
        let prog = parse(r#"call C f(bytes("0xdeadbeef"))"#).unwrap();
        match &prog.calls[0].args[0] {
            Value::Bytes(v, _) => assert_eq!(v, "0xdeadbeef"),
            other => panic!("expected Bytes, got {:?}", other),
        }
    }

    #[test]
    fn value_address() {
        let prog = parse(r#"call C f(address("GB3MR"))"#).unwrap();
        match &prog.calls[0].args[0] {
            Value::Address(v, _) => assert_eq!(v, "GB3MR"),
            other => panic!("expected Address, got {:?}", other),
        }
    }

    #[test]
    fn value_vec() {
        let prog = parse("call C f(vec(u32(1), u32(2), u32(3)))").unwrap();
        match &prog.calls[0].args[0] {
            Value::Vec(elements, _) => {
                assert_eq!(elements.len(), 3);
                match &elements[0] {
                    Value::U32(v, _) => assert_eq!(*v, 1),
                    other => panic!("expected U32, got {:?}", other),
                }
            }
            other => panic!("expected Vec, got {:?}", other),
        }
    }

    #[test]
    fn value_vec_nested() {
        let prog = parse("call C f(vec(vec(u32(1))))").unwrap();
        match &prog.calls[0].args[0] {
            Value::Vec(outer, _) => match &outer[0] {
                Value::Vec(inner, _) => {
                    assert_eq!(inner.len(), 1);
                }
                other => panic!("expected inner Vec, got {:?}", other),
            },
            other => panic!("expected outer Vec, got {:?}", other),
        }
    }

    #[test]
    fn value_vec_empty() {
        let prog = parse("call C f(vec())").unwrap();
        match &prog.calls[0].args[0] {
            Value::Vec(elements, _) => assert!(elements.is_empty()),
            other => panic!("expected Vec, got {:?}", other),
        }
    }

    #[test]
    fn value_map() {
        let prog = parse(r#"call C f(map(symbol("name") => string("CallSoro")))"#).unwrap();
        match &prog.calls[0].args[0] {
            Value::Map(entries, _) => {
                assert_eq!(entries.len(), 1);
                match &entries[0].key {
                    Value::Symbol(k, _) => assert_eq!(k, "name"),
                    other => panic!("expected Symbol key, got {:?}", other),
                }
                match &entries[0].value {
                    Value::String(v, _) => assert_eq!(v, "CallSoro"),
                    other => panic!("expected String value, got {:?}", other),
                }
            }
            other => panic!("expected Map, got {:?}", other),
        }
    }

    #[test]
    fn value_map_empty() {
        let prog = parse("call C f(map())").unwrap();
        match &prog.calls[0].args[0] {
            Value::Map(entries, _) => assert!(entries.is_empty()),
            other => panic!("expected Map, got {:?}", other),
        }
    }

    #[test]
    fn value_map_multiple_entries() {
        let src = r#"call C f(map(symbol("a") => u32(1), symbol("b") => u32(2)))"#;
        let prog = parse(src).unwrap();
        match &prog.calls[0].args[0] {
            Value::Map(entries, _) => assert_eq!(entries.len(), 2),
            other => panic!("expected Map, got {:?}", other),
        }
    }

    // ── Error cases ─────────────────────────────────────────────────

    #[test]
    fn error_missing_rparen() {
        let err = parse("call C f(u32(1)").unwrap_err();
        assert!(err.message.contains("expected ')'"));
    }

    #[test]
    fn bare_ident_in_arg_position() {
        // Bare identifiers are now parsed as Value::Ident (const references)
        let prog = parse("call C f(amount)").unwrap();
        match &prog.calls[0].args[0] {
            Value::Ident(name, _) => assert_eq!(name, "amount"),
            other => panic!("expected Ident, got {:?}", other),
        }
    }

    #[test]
    fn error_unexpected_token() {
        let err = parse("42").unwrap_err();
        assert!(err.message.contains("expected"));
    }

    #[test]
    fn error_u32_overflow() {
        let err = parse("call C f(u32(5000000000))").unwrap_err();
        assert!(err.message.contains("not a valid u32"));
    }

    #[test]
    fn error_i32_overflow() {
        let err = parse("call C f(i32(3000000000))").unwrap_err();
        assert!(err.message.contains("not a valid i32"));
    }

    #[test]
    fn error_bool_invalid() {
        let err = parse("call C f(bool(42))").unwrap_err();
        assert!(err.message.contains("'true' or 'false'"));
    }

    #[test]
    fn error_missing_arrow_in_map() {
        let err = parse(r#"call C f(map(symbol("a") u32(1)))"#).unwrap_err();
        assert!(err.message.contains("expected '=>'"));
    }

    #[test]
    fn error_missing_method() {
        let err = parse("call CABC (u32(1))").unwrap_err();
        assert!(err.message.contains("expected identifier"));
    }

    // ── Span accuracy ───────────────────────────────────────────────

    #[test]
    fn call_span_covers_full_range() {
        let prog = parse("call CABC method(u32(1))").unwrap();
        let call = &prog.calls[0];
        assert_eq!(call.span.start, 0);
        assert_eq!(call.span.end, 24);
    }

    #[test]
    fn error_has_correct_position() {
        let err = parse("network testnet\ncall C f(foo(1))").unwrap_err();
        assert_eq!(err.span.line, 2);
    }

    // ── Snapshot tests ──────────────────────────────────────────────

    #[test]
    fn snapshot_transfer_fixture() {
        let source = include_str!("../../../tests/fixtures/transfer.soro");
        let prog = parse(source).unwrap();
        insta::assert_debug_snapshot!(prog);
    }

    #[test]
    fn snapshot_all_types_fixture() {
        let source = include_str!("../../../tests/fixtures/all_types.soro");
        let prog = parse(source).unwrap();
        insta::assert_debug_snapshot!(prog);
    }

    #[test]
    fn snapshot_multi_call_fixture() {
        let source = include_str!("../../../tests/fixtures/multi_call.soro");
        let prog = parse(source).unwrap();
        insta::assert_debug_snapshot!(prog);
    }

    #[test]
    fn snapshot_minimal_fixture() {
        let source = include_str!("../../../tests/fixtures/minimal.soro");
        let prog = parse(source).unwrap();
        insta::assert_debug_snapshot!(prog);
    }
}
