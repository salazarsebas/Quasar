use serde::Serialize;

/// Top-level JSON IR output. Version 1 of the stable interface.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JsonIR {
    pub version: u32,
    pub network: String,
    pub network_passphrase: String,
    pub calls: Vec<IrCall>,
    pub signing: IrSigning,
}

/// A single contract invocation in the IR.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IrCall {
    pub contract: String,
    pub method: String,
    pub args: Vec<IrValue>,
}

/// Signing/transaction metadata.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IrSigning {
    pub source: String,
    pub fee_stroops: u64,
    pub timeout_seconds: u64,
}

/// A tagged value in the JSON IR.
///
/// Every value carries a `type` discriminator so downstream tools can
/// reconstruct the correct `ScVal` without guessing.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", content = "value")]
#[serde(rename_all = "lowercase")]
pub enum IrValue {
    Bool(bool),
    U32(u32),
    I32(i32),
    U64(u64),
    I64(i64),
    U128(String),
    I128(String),
    U256(String),
    I256(String),
    String(String),
    Symbol(String),
    Bytes(String),
    Address(String),
    Vec(Vec<IrValue>),
    Map(Vec<IrMapEntry>),
}

/// A key-value entry in a map value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IrMapEntry {
    pub key: IrValue,
    pub value: IrValue,
}
