use crate::span::Span;
use std::fmt;

/// The kind of a lexical token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    // Keywords
    Network,
    Source,
    Fee,
    Timeout,
    Call,
    True,
    False,
    Const,
    Use,

    // Literals
    Ident(String),
    String(String),
    Number(String),

    // Punctuation
    LParen,
    RParen,
    Comma,
    Arrow, // =>
    Dot,
    Minus,
    Eq, // = (for const assignments)

    // Structural
    Newline,
    Eof,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKind::Network => write!(f, "network"),
            TokenKind::Source => write!(f, "source"),
            TokenKind::Fee => write!(f, "fee"),
            TokenKind::Timeout => write!(f, "timeout"),
            TokenKind::Call => write!(f, "call"),
            TokenKind::True => write!(f, "true"),
            TokenKind::False => write!(f, "false"),
            TokenKind::Const => write!(f, "const"),
            TokenKind::Use => write!(f, "use"),
            TokenKind::Ident(s) => write!(f, "ident({s})"),
            TokenKind::String(s) => write!(f, "string({s:?})"),
            TokenKind::Number(s) => write!(f, "number({s})"),
            TokenKind::LParen => write!(f, "("),
            TokenKind::RParen => write!(f, ")"),
            TokenKind::Comma => write!(f, ","),
            TokenKind::Arrow => write!(f, "=>"),
            TokenKind::Dot => write!(f, "."),
            TokenKind::Minus => write!(f, "-"),
            TokenKind::Eq => write!(f, "="),
            TokenKind::Newline => write!(f, "newline"),
            TokenKind::Eof => write!(f, "EOF"),
        }
    }
}

/// A token with its kind and source span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

/// An error encountered during lexing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    pub message: String,
    pub span: Span,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "error at line {}, col {}: {}",
            self.span.line, self.span.col, self.message
        )
    }
}

impl LexError {
    /// Format the error with a source snippet showing the problematic location.
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

/// Lexer that tokenizes a `.soro` source string.
pub struct Lexer<'a> {
    source: &'a str,
    bytes: &'a [u8],
    pos: usize,
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    /// Tokenize the entire source, returning all tokens or the first error.
    pub fn tokenize(source: &str) -> Result<Vec<Token>, LexError> {
        let mut lexer = Lexer::new(source);
        let mut tokens = Vec::new();
        loop {
            let token = lexer.next_token()?;
            let is_eof = token.kind == TokenKind::Eof;
            tokens.push(token);
            if is_eof {
                break;
            }
        }
        Ok(tokens)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos + offset).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let byte = self.bytes.get(self.pos).copied()?;
        self.pos += 1;
        if byte == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(byte)
    }

    fn skip_horizontal_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\r' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn skip_line_comment(&mut self) {
        // Skip the two `/` characters
        self.advance();
        self.advance();
        // Consume until end of line (but don't consume the newline itself)
        while let Some(b) = self.peek() {
            if b == b'\n' {
                break;
            }
            self.advance();
        }
    }

    fn skip_block_comment(&mut self) -> Result<(), LexError> {
        let start_line = self.line;
        let start_col = self.col;
        let start_pos = self.pos;

        // Skip `/*`
        self.advance();
        self.advance();

        loop {
            match self.peek() {
                None => {
                    return Err(LexError {
                        message: "unterminated block comment".to_string(),
                        span: Span::new(start_pos, self.pos, start_line, start_col),
                    });
                }
                Some(b'*') if self.peek_at(1) == Some(b'/') => {
                    self.advance(); // *
                    self.advance(); // /
                    return Ok(());
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn lex_string(&mut self) -> Result<Token, LexError> {
        let start_pos = self.pos;
        let start_line = self.line;
        let start_col = self.col;

        // Skip opening quote
        self.advance();

        let mut value = String::new();

        loop {
            match self.peek() {
                None => {
                    return Err(LexError {
                        message: "unterminated string literal".to_string(),
                        span: Span::new(start_pos, self.pos, start_line, start_col),
                    });
                }
                Some(b'\n') => {
                    return Err(LexError {
                        message: "unterminated string literal (newline before closing quote)"
                            .to_string(),
                        span: Span::new(start_pos, self.pos, start_line, start_col),
                    });
                }
                Some(b'\\') => {
                    self.advance(); // consume backslash
                    match self.peek() {
                        Some(b'"') => {
                            self.advance();
                            value.push('"');
                        }
                        Some(b'\\') => {
                            self.advance();
                            value.push('\\');
                        }
                        Some(b'n') => {
                            self.advance();
                            value.push('\n');
                        }
                        Some(b't') => {
                            self.advance();
                            value.push('\t');
                        }
                        Some(c) => {
                            let esc_col = self.col;
                            self.advance();
                            return Err(LexError {
                                message: format!("unknown escape sequence '\\{}'", c as char),
                                span: Span::new(self.pos - 2, self.pos, self.line, esc_col - 1),
                            });
                        }
                        None => {
                            return Err(LexError {
                                message: "unterminated string literal (ends with backslash)"
                                    .to_string(),
                                span: Span::new(start_pos, self.pos, start_line, start_col),
                            });
                        }
                    }
                }
                Some(b'"') => {
                    self.advance(); // consume closing quote
                    return Ok(Token {
                        kind: TokenKind::String(value),
                        span: Span::new(start_pos, self.pos, start_line, start_col),
                    });
                }
                Some(_) => {
                    let ch = self.source[self.pos..].chars().next().unwrap();
                    for _ in 0..ch.len_utf8() {
                        self.advance();
                    }
                    value.push(ch);
                }
            }
        }
    }

    fn lex_number(&mut self) -> Token {
        let start_pos = self.pos;
        let start_line = self.line;
        let start_col = self.col;

        while let Some(b'0'..=b'9') = self.peek() {
            self.advance();
        }

        let text = self.source[start_pos..self.pos].to_string();
        Token {
            kind: TokenKind::Number(text),
            span: Span::new(start_pos, self.pos, start_line, start_col),
        }
    }

    fn lex_ident_or_keyword(&mut self) -> Token {
        let start_pos = self.pos;
        let start_line = self.line;
        let start_col = self.col;

        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.advance();
            } else {
                break;
            }
        }

        let text = &self.source[start_pos..self.pos];
        let kind = match text {
            "network" => TokenKind::Network,
            "source" => TokenKind::Source,
            "fee" => TokenKind::Fee,
            "timeout" => TokenKind::Timeout,
            "call" => TokenKind::Call,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "const" => TokenKind::Const,
            "use" => TokenKind::Use,
            _ => TokenKind::Ident(text.to_string()),
        };

        Token {
            kind,
            span: Span::new(start_pos, self.pos, start_line, start_col),
        }
    }

    /// Produce the next token from the source.
    pub fn next_token(&mut self) -> Result<Token, LexError> {
        // Skip horizontal whitespace and comments in a loop
        loop {
            self.skip_horizontal_whitespace();

            match (self.peek(), self.peek_at(1)) {
                // Line comment
                (Some(b'/'), Some(b'/')) => {
                    self.skip_line_comment();
                    continue;
                }
                // Block comment
                (Some(b'/'), Some(b'*')) => {
                    self.skip_block_comment()?;
                    continue;
                }
                _ => break,
            }
        }

        let start_pos = self.pos;
        let start_line = self.line;
        let start_col = self.col;

        match self.peek() {
            None => Ok(Token {
                kind: TokenKind::Eof,
                span: Span::new(start_pos, start_pos, start_line, start_col),
            }),

            Some(b'\n') => {
                self.advance();
                // Collapse consecutive newlines into one
                while self.peek() == Some(b'\n')
                    || self.peek() == Some(b'\r')
                    || self.peek() == Some(b' ')
                    || self.peek() == Some(b'\t')
                {
                    if self.peek() == Some(b'\n') {
                        self.advance();
                    } else {
                        // Skip horizontal whitespace between newlines
                        self.advance();
                    }
                }
                Ok(Token {
                    kind: TokenKind::Newline,
                    span: Span::new(start_pos, start_pos + 1, start_line, start_col),
                })
            }

            Some(b'"') => self.lex_string(),

            Some(b'0'..=b'9') => Ok(self.lex_number()),

            Some(b'a'..=b'z') | Some(b'A'..=b'Z') | Some(b'_') => Ok(self.lex_ident_or_keyword()),

            Some(b'(') => {
                self.advance();
                Ok(Token {
                    kind: TokenKind::LParen,
                    span: Span::new(start_pos, self.pos, start_line, start_col),
                })
            }

            Some(b')') => {
                self.advance();
                Ok(Token {
                    kind: TokenKind::RParen,
                    span: Span::new(start_pos, self.pos, start_line, start_col),
                })
            }

            Some(b',') => {
                self.advance();
                Ok(Token {
                    kind: TokenKind::Comma,
                    span: Span::new(start_pos, self.pos, start_line, start_col),
                })
            }

            Some(b'.') => {
                self.advance();
                Ok(Token {
                    kind: TokenKind::Dot,
                    span: Span::new(start_pos, self.pos, start_line, start_col),
                })
            }

            Some(b'-') => {
                self.advance();
                Ok(Token {
                    kind: TokenKind::Minus,
                    span: Span::new(start_pos, self.pos, start_line, start_col),
                })
            }

            Some(b'=') => {
                self.advance();
                if self.peek() == Some(b'>') {
                    self.advance();
                    Ok(Token {
                        kind: TokenKind::Arrow,
                        span: Span::new(start_pos, self.pos, start_line, start_col),
                    })
                } else {
                    Ok(Token {
                        kind: TokenKind::Eq,
                        span: Span::new(start_pos, self.pos, start_line, start_col),
                    })
                }
            }

            Some(b) => {
                self.advance();
                Err(LexError {
                    message: format!("unexpected character '{}'", b as char),
                    span: Span::new(start_pos, self.pos, start_line, start_col),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: tokenize and return only the kinds (ignoring spans).
    fn kinds(source: &str) -> Result<Vec<TokenKind>, LexError> {
        Ok(Lexer::tokenize(source)?
            .into_iter()
            .map(|t| t.kind)
            .collect())
    }

    /// Helper: tokenize and return kinds, filtering out newlines and EOF.
    fn meaningful_kinds(source: &str) -> Result<Vec<TokenKind>, LexError> {
        Ok(Lexer::tokenize(source)?
            .into_iter()
            .map(|t| t.kind)
            .filter(|k| !matches!(k, TokenKind::Newline | TokenKind::Eof))
            .collect())
    }

    // ── Keywords ────────────────────────────────────────────────────

    #[test]
    fn keywords() {
        let result =
            meaningful_kinds("network source fee timeout call true false const use").unwrap();
        assert_eq!(
            result,
            vec![
                TokenKind::Network,
                TokenKind::Source,
                TokenKind::Fee,
                TokenKind::Timeout,
                TokenKind::Call,
                TokenKind::True,
                TokenKind::False,
                TokenKind::Const,
                TokenKind::Use,
            ]
        );
    }

    #[test]
    fn keyword_vs_ident() {
        let result = meaningful_kinds("network network123 callx").unwrap();
        assert_eq!(
            result,
            vec![
                TokenKind::Network,
                TokenKind::Ident("network123".to_string()),
                TokenKind::Ident("callx".to_string()),
            ]
        );
    }

    // ── Identifiers ─────────────────────────────────────────────────

    #[test]
    fn identifiers() {
        let result = meaningful_kinds("address i128 u32 my_var _private").unwrap();
        assert_eq!(
            result,
            vec![
                TokenKind::Ident("address".to_string()),
                TokenKind::Ident("i128".to_string()),
                TokenKind::Ident("u32".to_string()),
                TokenKind::Ident("my_var".to_string()),
                TokenKind::Ident("_private".to_string()),
            ]
        );
    }

    // ── Numbers ─────────────────────────────────────────────────────

    #[test]
    fn numbers() {
        let result = meaningful_kinds("0 42 100000 18446744073709551615").unwrap();
        assert_eq!(
            result,
            vec![
                TokenKind::Number("0".to_string()),
                TokenKind::Number("42".to_string()),
                TokenKind::Number("100000".to_string()),
                TokenKind::Number("18446744073709551615".to_string()),
            ]
        );
    }

    // ── Strings ─────────────────────────────────────────────────────

    #[test]
    fn simple_string() {
        let result = meaningful_kinds(r#""hello world""#).unwrap();
        assert_eq!(result, vec![TokenKind::String("hello world".to_string())]);
    }

    #[test]
    fn string_with_escapes() {
        let result = meaningful_kinds(r#""hello \"world\" \n\t\\""#).unwrap();
        assert_eq!(
            result,
            vec![TokenKind::String("hello \"world\" \n\t\\".to_string())]
        );
    }

    #[test]
    fn empty_string() {
        let result = meaningful_kinds(r#""""#).unwrap();
        assert_eq!(result, vec![TokenKind::String(String::new())]);
    }

    #[test]
    fn unclosed_string() {
        let err = Lexer::tokenize(r#""hello"#).unwrap_err();
        assert_eq!(err.message, "unterminated string literal");
        assert_eq!(err.span.line, 1);
        assert_eq!(err.span.col, 1);
    }

    #[test]
    fn string_with_newline() {
        let err = Lexer::tokenize("\"hello\nworld\"").unwrap_err();
        assert!(err.message.contains("unterminated string literal"));
    }

    #[test]
    fn string_unknown_escape() {
        let err = Lexer::tokenize(r#""hello \x""#).unwrap_err();
        assert!(err.message.contains("unknown escape sequence"));
    }

    // ── Punctuation ─────────────────────────────────────────────────

    #[test]
    fn punctuation() {
        let result = meaningful_kinds("( ) , . - = =>").unwrap();
        assert_eq!(
            result,
            vec![
                TokenKind::LParen,
                TokenKind::RParen,
                TokenKind::Comma,
                TokenKind::Dot,
                TokenKind::Minus,
                TokenKind::Eq,
                TokenKind::Arrow,
            ]
        );
    }

    #[test]
    fn arrow_vs_eq() {
        let result = meaningful_kinds("= =>").unwrap();
        assert_eq!(result, vec![TokenKind::Eq, TokenKind::Arrow]);
    }

    // ── Comments ────────────────────────────────────────────────────

    #[test]
    fn line_comment() {
        let result = kinds("// this is ignored\nnetwork").unwrap();
        assert_eq!(
            result,
            vec![TokenKind::Newline, TokenKind::Network, TokenKind::Eof,]
        );
    }

    #[test]
    fn line_comment_at_end() {
        let result = meaningful_kinds("network // comment").unwrap();
        assert_eq!(result, vec![TokenKind::Network]);
    }

    #[test]
    fn block_comment() {
        let result = meaningful_kinds("/* skip this */call").unwrap();
        assert_eq!(result, vec![TokenKind::Call]);
    }

    #[test]
    fn block_comment_multiline() {
        let result = meaningful_kinds("/*\n  multi\n  line\n*/call").unwrap();
        assert_eq!(result, vec![TokenKind::Call]);
    }

    #[test]
    fn unterminated_block_comment() {
        let err = Lexer::tokenize("/* never closed").unwrap_err();
        assert_eq!(err.message, "unterminated block comment");
    }

    // ── Newlines ────────────────────────────────────────────────────

    #[test]
    fn newlines_collapsed() {
        let result = kinds("network\n\n\nsource").unwrap();
        assert_eq!(
            result,
            vec![
                TokenKind::Network,
                TokenKind::Newline,
                TokenKind::Source,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn no_newline_at_start() {
        // Leading newlines before first token should be collapsed
        let result = kinds("\n\nnetwork").unwrap();
        assert_eq!(
            result,
            vec![TokenKind::Newline, TokenKind::Network, TokenKind::Eof]
        );
    }

    // ── Error cases ─────────────────────────────────────────────────

    #[test]
    fn invalid_character() {
        let err = Lexer::tokenize("@").unwrap_err();
        assert_eq!(err.message, "unexpected character '@'");
        assert_eq!(err.span.line, 1);
        assert_eq!(err.span.col, 1);
    }

    #[test]
    fn invalid_character_with_position() {
        let err = Lexer::tokenize("network @").unwrap_err();
        assert_eq!(err.message, "unexpected character '@'");
        assert_eq!(err.span.line, 1);
        assert_eq!(err.span.col, 9);
    }

    // ── Full call tokenization ──────────────────────────────────────

    #[test]
    fn full_call() {
        let src = r#"call CB6ABC transfer(address("GB123"), i128("10"))"#;
        let result = meaningful_kinds(src).unwrap();
        assert_eq!(
            result,
            vec![
                TokenKind::Call,
                TokenKind::Ident("CB6ABC".to_string()),
                TokenKind::Ident("transfer".to_string()),
                TokenKind::LParen,
                TokenKind::Ident("address".to_string()),
                TokenKind::LParen,
                TokenKind::String("GB123".to_string()),
                TokenKind::RParen,
                TokenKind::Comma,
                TokenKind::Ident("i128".to_string()),
                TokenKind::LParen,
                TokenKind::String("10".to_string()),
                TokenKind::RParen,
                TokenKind::RParen,
            ]
        );
    }

    #[test]
    fn map_syntax() {
        let src = r#"map(symbol("a") => u32(1))"#;
        let result = meaningful_kinds(src).unwrap();
        assert_eq!(
            result,
            vec![
                TokenKind::Ident("map".to_string()),
                TokenKind::LParen,
                TokenKind::Ident("symbol".to_string()),
                TokenKind::LParen,
                TokenKind::String("a".to_string()),
                TokenKind::RParen,
                TokenKind::Arrow,
                TokenKind::Ident("u32".to_string()),
                TokenKind::LParen,
                TokenKind::Number("1".to_string()),
                TokenKind::RParen,
                TokenKind::RParen,
            ]
        );
    }

    #[test]
    fn negative_number_in_call() {
        let result = meaningful_kinds("i32(-1)").unwrap();
        assert_eq!(
            result,
            vec![
                TokenKind::Ident("i32".to_string()),
                TokenKind::LParen,
                TokenKind::Minus,
                TokenKind::Number("1".to_string()),
                TokenKind::RParen,
            ]
        );
    }

    // ── Span accuracy ───────────────────────────────────────────────

    #[test]
    fn span_positions() {
        let tokens = Lexer::tokenize("network testnet").unwrap();
        // "network" starts at col 1, "testnet" starts at col 9
        assert_eq!(tokens[0].span.col, 1);
        assert_eq!(tokens[0].span.start, 0);
        assert_eq!(tokens[0].span.end, 7);
        assert_eq!(tokens[1].span.col, 9);
        assert_eq!(tokens[1].span.start, 8);
        assert_eq!(tokens[1].span.end, 15);
    }

    #[test]
    fn span_multiline() {
        let tokens = Lexer::tokenize("network\nsource").unwrap();
        // "network" on line 1, newline, "source" on line 2
        assert_eq!(tokens[0].span.line, 1);
        assert_eq!(tokens[1].kind, TokenKind::Newline);
        assert_eq!(tokens[2].span.line, 2);
        assert_eq!(tokens[2].span.col, 1);
    }

    // ── Error formatting ────────────────────────────────────────────

    #[test]
    fn error_format_with_source() {
        let source = "network @bad";
        let err = Lexer::tokenize(source).unwrap_err();
        let formatted = err.format_with_source(source);
        assert!(formatted.contains("unexpected character '@'"));
        assert!(formatted.contains("line 1"));
        assert!(formatted.contains("@bad"));
    }

    // ── Snapshot tests ──────────────────────────────────────────────

    #[test]
    fn snapshot_transfer_fixture() {
        let source = include_str!("../../../tests/fixtures/transfer.soro");
        let tokens = Lexer::tokenize(source).unwrap();
        let display: Vec<String> = tokens
            .iter()
            .map(|t| format!("{}:{} {}", t.span.line, t.span.col, t.kind))
            .collect();
        insta::assert_yaml_snapshot!(display);
    }

    #[test]
    fn snapshot_all_types_fixture() {
        let source = include_str!("../../../tests/fixtures/all_types.soro");
        let tokens = Lexer::tokenize(source).unwrap();
        let display: Vec<String> = tokens
            .iter()
            .map(|t| format!("{}:{} {}", t.span.line, t.span.col, t.kind))
            .collect();
        insta::assert_yaml_snapshot!(display);
    }

    #[test]
    fn snapshot_multi_call_fixture() {
        let source = include_str!("../../../tests/fixtures/multi_call.soro");
        let tokens = Lexer::tokenize(source).unwrap();
        let display: Vec<String> = tokens
            .iter()
            .map(|t| format!("{}:{} {}", t.span.line, t.span.col, t.kind))
            .collect();
        insta::assert_yaml_snapshot!(display);
    }

    #[test]
    fn snapshot_minimal_fixture() {
        let source = include_str!("../../../tests/fixtures/minimal.soro");
        let tokens = Lexer::tokenize(source).unwrap();
        let display: Vec<String> = tokens
            .iter()
            .map(|t| format!("{}:{} {}", t.span.line, t.span.col, t.kind))
            .collect();
        insta::assert_yaml_snapshot!(display);
    }
}
