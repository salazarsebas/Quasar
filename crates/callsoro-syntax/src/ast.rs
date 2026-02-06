use crate::span::Span;

/// A complete `.soro` program.
#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub directives: Vec<Directive>,
    pub calls: Vec<Call>,
}

/// A top-level directive that configures the transaction context.
#[derive(Debug, Clone, PartialEq)]
pub enum Directive {
    Network {
        value: String,
        span: Span,
    },
    Source {
        value: String,
        span: Span,
    },
    Fee {
        /// Fee in stroops, stored as raw string to defer range validation.
        value: u64,
        span: Span,
    },
    Timeout {
        /// Timeout in seconds.
        value: u64,
        span: Span,
    },
}

impl Directive {
    pub fn span(&self) -> Span {
        match self {
            Directive::Network { span, .. }
            | Directive::Source { span, .. }
            | Directive::Fee { span, .. }
            | Directive::Timeout { span, .. } => *span,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Directive::Network { .. } => "network",
            Directive::Source { .. } => "source",
            Directive::Fee { .. } => "fee",
            Directive::Timeout { .. } => "timeout",
        }
    }
}

/// A contract method invocation.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub contract: String,
    pub method: String,
    pub args: Vec<Value>,
    pub span: Span,
}

/// A typed value that maps to a Soroban `ScVal`.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool, Span),
    U32(u32, Span),
    I32(i32, Span),
    U64(u64, Span),
    I64(i64, Span),
    /// Stored as string to avoid overflow during parsing.
    U128(String, Span),
    /// Stored as string to avoid overflow during parsing.
    I128(String, Span),
    U256(String, Span),
    I256(String, Span),
    String(String, Span),
    Symbol(String, Span),
    /// Hex string with `0x` prefix.
    Bytes(String, Span),
    /// Stellar address: `G...` (account) or `C...` (contract).
    Address(String, Span),
    Vec(Vec<Value>, Span),
    Map(Vec<MapEntry>, Span),
}

impl Value {
    pub fn span(&self) -> Span {
        match self {
            Value::Bool(_, s)
            | Value::U32(_, s)
            | Value::I32(_, s)
            | Value::U64(_, s)
            | Value::I64(_, s)
            | Value::U128(_, s)
            | Value::I128(_, s)
            | Value::U256(_, s)
            | Value::I256(_, s)
            | Value::String(_, s)
            | Value::Symbol(_, s)
            | Value::Bytes(_, s)
            | Value::Address(_, s)
            | Value::Vec(_, s)
            | Value::Map(_, s) => *s,
        }
    }
}

/// A key-value pair in a `map(...)` expression.
#[derive(Debug, Clone, PartialEq)]
pub struct MapEntry {
    pub key: Value,
    pub value: Value,
}
