//! ABI import: fetch a deployed contract's spec and produce a `.soroabi` JSON file.

use std::fmt;
use std::io::Cursor;

use serde::{Deserialize, Serialize};
use stellar_strkey::Strkey;
use stellar_xdr::curr::{
    ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyContractCode, LedgerKeyContractData, Limited, Limits, ReadXdr, ScAddress, ScSpecEntry,
    ScSpecTypeDef, ScSpecUdtUnionCaseV0, ScVal, WriteXdr,
};

use crate::error::SimulationError;
use crate::rpc::RpcClient;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur during ABI import.
#[derive(Debug, Clone)]
pub enum ImportError {
    /// HTTP / network failure
    Network(String),
    /// JSON-RPC error from the node
    RpcError { code: i64, message: String },
    /// Unexpected response format
    InvalidResponse(String),
    /// Contract not found on the network
    ContractNotFound(String),
    /// Contract is a SAC (Stellar Asset Contract) or otherwise non-WASM
    NotWasmContract(String),
    /// WASM binary missing `contractspecv0` custom section
    NoContractSpec,
    /// Failed to parse WASM binary
    WasmParseError(String),
    /// XDR serialization/deserialization error
    XdrError(String),
    /// Invalid contract ID (not a valid C... address)
    InvalidContractId(String),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::Network(msg) => write!(f, "network error: {}", msg),
            ImportError::RpcError { code, message } => {
                write!(f, "RPC error (code {}): {}", code, message)
            }
            ImportError::InvalidResponse(msg) => write!(f, "invalid response: {}", msg),
            ImportError::ContractNotFound(id) => write!(f, "contract not found: {}", id),
            ImportError::NotWasmContract(id) => {
                write!(f, "contract {} is not a WASM contract (possibly a SAC)", id)
            }
            ImportError::NoContractSpec => {
                write!(f, "WASM binary has no contractspecv0 section")
            }
            ImportError::WasmParseError(msg) => write!(f, "WASM parse error: {}", msg),
            ImportError::XdrError(msg) => write!(f, "XDR error: {}", msg),
            ImportError::InvalidContractId(id) => write!(f, "invalid contract ID: {}", id),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<SimulationError> for ImportError {
    fn from(e: SimulationError) -> Self {
        match e {
            SimulationError::Network(msg) => ImportError::Network(msg),
            SimulationError::RpcError { code, message } => ImportError::RpcError { code, message },
            SimulationError::InvalidResponse(msg) => ImportError::InvalidResponse(msg),
            other => ImportError::Network(other.to_string()),
        }
    }
}

impl From<stellar_xdr::curr::Error> for ImportError {
    fn from(e: stellar_xdr::curr::Error) -> Self {
        ImportError::XdrError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// .soroabi output types
// ---------------------------------------------------------------------------

/// Complete ABI description of a Soroban contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractAbi {
    pub contract_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub functions: Vec<AbiFunction>,
    pub types: Vec<AbiType>,
}

/// A contract function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbiFunction {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    pub inputs: Vec<AbiFunctionInput>,
    pub outputs: Vec<String>,
}

/// A single function parameter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbiFunctionInput {
    pub name: String,
    #[serde(rename = "type")]
    pub type_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// A user-defined type from the contract spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind")]
pub enum AbiType {
    #[serde(rename = "struct")]
    Struct {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        doc: Option<String>,
        fields: Vec<AbiField>,
    },
    #[serde(rename = "enum")]
    Enum {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        doc: Option<String>,
        variants: Vec<AbiEnumVariant>,
    },
    #[serde(rename = "union")]
    Union {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        doc: Option<String>,
        cases: Vec<AbiUnionCase>,
    },
    #[serde(rename = "error_enum")]
    ErrorEnum {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        doc: Option<String>,
        variants: Vec<AbiErrorVariant>,
    },
}

/// A struct field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbiField {
    pub name: String,
    #[serde(rename = "type")]
    pub type_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// An enum variant (name + u32 value).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbiEnumVariant {
    pub name: String,
    pub value: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// A union case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbiUnionCase {
    pub name: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_ref: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// An error enum variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbiErrorVariant {
    pub name: String,
    pub value: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

// ---------------------------------------------------------------------------
// SCSpecTypeDef → string mapping
// ---------------------------------------------------------------------------

/// Convert an `ScSpecTypeDef` into a human-readable type string.
pub fn spec_type_to_string(ty: &ScSpecTypeDef) -> String {
    match ty {
        ScSpecTypeDef::Bool => "bool".into(),
        ScSpecTypeDef::Void => "void".into(),
        ScSpecTypeDef::Error => "error".into(),
        ScSpecTypeDef::U32 => "u32".into(),
        ScSpecTypeDef::I32 => "i32".into(),
        ScSpecTypeDef::U64 => "u64".into(),
        ScSpecTypeDef::I64 => "i64".into(),
        ScSpecTypeDef::Timepoint => "timepoint".into(),
        ScSpecTypeDef::Duration => "duration".into(),
        ScSpecTypeDef::U128 => "u128".into(),
        ScSpecTypeDef::I128 => "i128".into(),
        ScSpecTypeDef::U256 => "u256".into(),
        ScSpecTypeDef::I256 => "i256".into(),
        ScSpecTypeDef::Bytes => "bytes".into(),
        ScSpecTypeDef::String => "string".into(),
        ScSpecTypeDef::Symbol => "symbol".into(),
        ScSpecTypeDef::Address => "address".into(),
        ScSpecTypeDef::Val => "val".into(),
        ScSpecTypeDef::MuxedAddress => "muxed_address".into(),
        ScSpecTypeDef::Option(inner) => {
            format!("option<{}>", spec_type_to_string(&inner.value_type))
        }
        ScSpecTypeDef::Result(inner) => {
            format!(
                "result<{}, {}>",
                spec_type_to_string(&inner.ok_type),
                spec_type_to_string(&inner.error_type)
            )
        }
        ScSpecTypeDef::Vec(inner) => {
            format!("vec<{}>", spec_type_to_string(&inner.element_type))
        }
        ScSpecTypeDef::Map(inner) => {
            format!(
                "map<{}, {}>",
                spec_type_to_string(&inner.key_type),
                spec_type_to_string(&inner.value_type)
            )
        }
        ScSpecTypeDef::Tuple(inner) => {
            let parts: Vec<String> = inner.value_types.iter().map(spec_type_to_string).collect();
            format!("tuple<{}>", parts.join(", "))
        }
        ScSpecTypeDef::BytesN(inner) => {
            format!("bytes<{}>", inner.n)
        }
        ScSpecTypeDef::Udt(inner) => inner.name.to_string(),
    }
}

// ---------------------------------------------------------------------------
// WASM parsing
// ---------------------------------------------------------------------------

/// Extract the `contractspecv0` custom section from a WASM binary.
fn extract_contract_spec_section(wasm_bytes: &[u8]) -> Result<Vec<u8>, ImportError> {
    use wasmparser::{Parser, Payload};

    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let payload =
            payload.map_err(|e| ImportError::WasmParseError(format!("WASM parse: {}", e)))?;
        if let Payload::CustomSection(reader) = payload {
            if reader.name() == "contractspecv0" {
                return Ok(reader.data().to_vec());
            }
        }
    }
    Err(ImportError::NoContractSpec)
}

/// Deserialize a sequence of concatenated `ScSpecEntry` XDR values from raw bytes.
fn parse_spec_entries(spec_bytes: &[u8]) -> Result<Vec<ScSpecEntry>, ImportError> {
    let cursor = Cursor::new(spec_bytes);
    let mut limited = Limited::new(cursor, Limits::none());
    let mut entries = Vec::new();
    while (limited.inner.position() as usize) < spec_bytes.len() {
        let entry = ScSpecEntry::read_xdr(&mut limited)
            .map_err(|e| ImportError::XdrError(format!("spec entry: {}", e)))?;
        entries.push(entry);
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Ledger key construction
// ---------------------------------------------------------------------------

/// Build the base64 XDR ledger key for a contract's instance entry.
fn build_contract_instance_ledger_key(contract_id: &str) -> Result<String, ImportError> {
    let hash_bytes = decode_contract_id(contract_id)?;
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(Hash(hash_bytes))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    key.to_xdr_base64(Limits::none())
        .map_err(|e| ImportError::XdrError(format!("instance key: {}", e)))
}

/// Build the base64 XDR ledger key for a contract code entry.
fn build_contract_code_ledger_key(hash: &Hash) -> Result<String, ImportError> {
    let key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: hash.clone() });
    key.to_xdr_base64(Limits::none())
        .map_err(|e| ImportError::XdrError(format!("code key: {}", e)))
}

/// Decode a C... contract address into its 32-byte hash.
fn decode_contract_id(contract_id: &str) -> Result<[u8; 32], ImportError> {
    match Strkey::from_string(contract_id) {
        Ok(Strkey::Contract(c)) => Ok(c.0),
        Ok(_) => Err(ImportError::InvalidContractId(format!(
            "{} is not a contract address (expected C...)",
            contract_id
        ))),
        Err(e) => Err(ImportError::InvalidContractId(format!(
            "invalid strkey {}: {}",
            contract_id, e
        ))),
    }
}

// ---------------------------------------------------------------------------
// RPC fetch helpers
// ---------------------------------------------------------------------------

/// Fetch the WASM hash from a deployed contract's instance entry.
fn fetch_wasm_hash(rpc: &RpcClient, contract_id: &str) -> Result<Hash, ImportError> {
    let key = build_contract_instance_ledger_key(contract_id)?;
    let response = rpc.get_ledger_entries(&[key])?;

    let entries = response
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ImportError::ContractNotFound(contract_id.to_string()))?;

    if entries.is_empty() {
        return Err(ImportError::ContractNotFound(contract_id.to_string()));
    }

    let xdr_b64 = entries[0]
        .get("xdr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ImportError::InvalidResponse("missing xdr in entry".to_string()))?;

    let entry_data = LedgerEntryData::from_xdr_base64(xdr_b64, Limits::none())?;

    match entry_data {
        LedgerEntryData::ContractData(data) => match data.val {
            ScVal::ContractInstance(instance) => match instance.executable {
                ContractExecutable::Wasm(hash) => Ok(hash),
                ContractExecutable::StellarAsset => {
                    Err(ImportError::NotWasmContract(contract_id.to_string()))
                }
            },
            _ => Err(ImportError::InvalidResponse(
                "contract data is not an instance entry".to_string(),
            )),
        },
        _ => Err(ImportError::InvalidResponse(
            "ledger entry is not ContractData".to_string(),
        )),
    }
}

/// Fetch the raw WASM bytes for a given code hash.
fn fetch_wasm_code(rpc: &RpcClient, hash: &Hash) -> Result<Vec<u8>, ImportError> {
    let key = build_contract_code_ledger_key(hash)?;
    let response = rpc.get_ledger_entries(&[key])?;

    let entries = response
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            ImportError::InvalidResponse("missing entries in code response".to_string())
        })?;

    if entries.is_empty() {
        return Err(ImportError::InvalidResponse(
            "no code entry found for hash".to_string(),
        ));
    }

    let xdr_b64 = entries[0]
        .get("xdr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ImportError::InvalidResponse("missing xdr in code entry".to_string()))?;

    let entry_data = LedgerEntryData::from_xdr_base64(xdr_b64, Limits::none())?;

    match entry_data {
        LedgerEntryData::ContractCode(code_entry) => Ok(code_entry.code.to_vec()),
        _ => Err(ImportError::InvalidResponse(
            "ledger entry is not ContractCode".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// SCSpecEntry → ContractAbi
// ---------------------------------------------------------------------------

/// Build a `ContractAbi` from a list of `ScSpecEntry` values.
fn build_contract_abi(contract_id: &str, entries: &[ScSpecEntry]) -> ContractAbi {
    let mut functions = Vec::new();
    let mut types = Vec::new();

    for entry in entries {
        match entry {
            ScSpecEntry::FunctionV0(f) => {
                let name = f.name.to_string();
                // Skip internal/constructor functions
                if name.starts_with("__") {
                    continue;
                }
                let doc = non_empty_doc(&f.doc.to_string());
                let inputs = f
                    .inputs
                    .iter()
                    .map(|inp| AbiFunctionInput {
                        name: inp.name.to_string(),
                        type_ref: spec_type_to_string(&inp.type_),
                        doc: non_empty_doc(&inp.doc.to_string()),
                    })
                    .collect();
                let outputs = f.outputs.iter().map(spec_type_to_string).collect();
                functions.push(AbiFunction {
                    name,
                    doc,
                    inputs,
                    outputs,
                });
            }
            ScSpecEntry::UdtStructV0(s) => {
                let fields = s
                    .fields
                    .iter()
                    .map(|field| AbiField {
                        name: field.name.to_string(),
                        type_ref: spec_type_to_string(&field.type_),
                        doc: non_empty_doc(&field.doc.to_string()),
                    })
                    .collect();
                types.push(AbiType::Struct {
                    name: s.name.to_string(),
                    doc: non_empty_doc(&s.doc.to_string()),
                    fields,
                });
            }
            ScSpecEntry::UdtEnumV0(e) => {
                let variants = e
                    .cases
                    .iter()
                    .map(|c| AbiEnumVariant {
                        name: c.name.to_string(),
                        value: c.value,
                        doc: non_empty_doc(&c.doc.to_string()),
                    })
                    .collect();
                types.push(AbiType::Enum {
                    name: e.name.to_string(),
                    doc: non_empty_doc(&e.doc.to_string()),
                    variants,
                });
            }
            ScSpecEntry::UdtUnionV0(u) => {
                let cases = u
                    .cases
                    .iter()
                    .map(|c| match c {
                        ScSpecUdtUnionCaseV0::VoidV0(v) => AbiUnionCase {
                            name: v.name.to_string(),
                            type_ref: None,
                            doc: non_empty_doc(&v.doc.to_string()),
                        },
                        ScSpecUdtUnionCaseV0::TupleV0(t) => AbiUnionCase {
                            name: t.name.to_string(),
                            type_ref: Some(t.type_.iter().map(spec_type_to_string).collect()),
                            doc: non_empty_doc(&t.doc.to_string()),
                        },
                    })
                    .collect();
                types.push(AbiType::Union {
                    name: u.name.to_string(),
                    doc: non_empty_doc(&u.doc.to_string()),
                    cases,
                });
            }
            ScSpecEntry::UdtErrorEnumV0(e) => {
                let variants = e
                    .cases
                    .iter()
                    .map(|c| AbiErrorVariant {
                        name: c.name.to_string(),
                        value: c.value,
                        doc: non_empty_doc(&c.doc.to_string()),
                    })
                    .collect();
                types.push(AbiType::ErrorEnum {
                    name: e.name.to_string(),
                    doc: non_empty_doc(&e.doc.to_string()),
                    variants,
                });
            }
            // Skip event specs — not needed for .soroabi
            _ => {}
        }
    }

    ContractAbi {
        contract_id: contract_id.to_string(),
        name: None,
        functions,
        types,
    }
}

/// Convert an empty doc string to `None`.
fn non_empty_doc(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// ---------------------------------------------------------------------------
// AbiImporter
// ---------------------------------------------------------------------------

/// Orchestrates ABI import: fetches a deployed contract's WASM from the
/// network, parses its `contractspecv0` section, and produces a `ContractAbi`.
pub struct AbiImporter {
    rpc: RpcClient,
}

impl AbiImporter {
    /// Create a new importer pointing at the given RPC URL.
    pub fn new(rpc_url: &str) -> Self {
        AbiImporter {
            rpc: RpcClient::new(rpc_url),
        }
    }

    /// Import the contract ABI from the network.
    pub fn import(&self, contract_id: &str) -> Result<ContractAbi, ImportError> {
        // 1. Validate contract ID
        decode_contract_id(contract_id)?;

        // 2. Fetch WASM hash from the contract instance
        let wasm_hash = fetch_wasm_hash(&self.rpc, contract_id)?;

        // 3. Fetch WASM code bytes
        let wasm_bytes = fetch_wasm_code(&self.rpc, &wasm_hash)?;

        // 4. Extract contractspecv0 custom section
        let spec_bytes = extract_contract_spec_section(&wasm_bytes)?;

        // 5. Parse ScSpecEntry stream
        let entries = parse_spec_entries(&spec_bytes)?;

        // 6. Build ContractAbi
        Ok(build_contract_abi(contract_id, &entries))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    // -- spec_type_to_string tests --

    #[test]
    fn spec_type_all_primitives() {
        let cases = vec![
            (ScSpecTypeDef::Bool, "bool"),
            (ScSpecTypeDef::Void, "void"),
            (ScSpecTypeDef::Error, "error"),
            (ScSpecTypeDef::U32, "u32"),
            (ScSpecTypeDef::I32, "i32"),
            (ScSpecTypeDef::U64, "u64"),
            (ScSpecTypeDef::I64, "i64"),
            (ScSpecTypeDef::Timepoint, "timepoint"),
            (ScSpecTypeDef::Duration, "duration"),
            (ScSpecTypeDef::U128, "u128"),
            (ScSpecTypeDef::I128, "i128"),
            (ScSpecTypeDef::U256, "u256"),
            (ScSpecTypeDef::I256, "i256"),
            (ScSpecTypeDef::Bytes, "bytes"),
            (ScSpecTypeDef::String, "string"),
            (ScSpecTypeDef::Symbol, "symbol"),
            (ScSpecTypeDef::Address, "address"),
            (ScSpecTypeDef::Val, "val"),
        ];
        for (ty, expected) in cases {
            assert_eq!(spec_type_to_string(&ty), expected, "failed for {:?}", ty);
        }
    }

    #[test]
    fn spec_type_option() {
        let ty = ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
            value_type: Box::new(ScSpecTypeDef::I128),
        }));
        assert_eq!(spec_type_to_string(&ty), "option<i128>");
    }

    #[test]
    fn spec_type_vec() {
        let ty = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::Address),
        }));
        assert_eq!(spec_type_to_string(&ty), "vec<address>");
    }

    #[test]
    fn spec_type_map() {
        let ty = ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
            key_type: Box::new(ScSpecTypeDef::Symbol),
            value_type: Box::new(ScSpecTypeDef::I128),
        }));
        assert_eq!(spec_type_to_string(&ty), "map<symbol, i128>");
    }

    #[test]
    fn spec_type_tuple() {
        let ty = ScSpecTypeDef::Tuple(Box::new(ScSpecTypeTuple {
            value_types: vec![
                ScSpecTypeDef::U32,
                ScSpecTypeDef::Bool,
                ScSpecTypeDef::Address,
            ]
            .try_into()
            .unwrap(),
        }));
        assert_eq!(spec_type_to_string(&ty), "tuple<u32, bool, address>");
    }

    #[test]
    fn spec_type_bytes_n() {
        let ty = ScSpecTypeDef::BytesN(ScSpecTypeBytesN { n: 32 });
        assert_eq!(spec_type_to_string(&ty), "bytes<32>");
    }

    #[test]
    fn spec_type_result() {
        let ty = ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
            ok_type: Box::new(ScSpecTypeDef::U64),
            error_type: Box::new(ScSpecTypeDef::Error),
        }));
        assert_eq!(spec_type_to_string(&ty), "result<u64, error>");
    }

    #[test]
    fn spec_type_udt() {
        let ty = ScSpecTypeDef::Udt(ScSpecTypeUdt {
            name: "TokenMetadata".try_into().unwrap(),
        });
        assert_eq!(spec_type_to_string(&ty), "TokenMetadata");
    }

    #[test]
    fn spec_type_nested() {
        // option<vec<map<symbol, u128>>>
        let ty = ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
            value_type: Box::new(ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
                element_type: Box::new(ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
                    key_type: Box::new(ScSpecTypeDef::Symbol),
                    value_type: Box::new(ScSpecTypeDef::U128),
                }))),
            }))),
        }));
        assert_eq!(spec_type_to_string(&ty), "option<vec<map<symbol, u128>>>");
    }

    // -- parse_spec_entries roundtrip --

    #[test]
    fn parse_spec_entries_roundtrip() {
        let entry = ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: "".try_into().unwrap(),
            name: "transfer".try_into().unwrap(),
            inputs: vec![
                ScSpecFunctionInputV0 {
                    doc: "".try_into().unwrap(),
                    name: "to".try_into().unwrap(),
                    type_: ScSpecTypeDef::Address,
                },
                ScSpecFunctionInputV0 {
                    doc: "".try_into().unwrap(),
                    name: "amount".try_into().unwrap(),
                    type_: ScSpecTypeDef::I128,
                },
            ]
            .try_into()
            .unwrap(),
            outputs: vec![ScSpecTypeDef::Void].try_into().unwrap(),
        });

        let xdr_bytes = entry.to_xdr(Limits::none()).unwrap();
        let parsed = parse_spec_entries(&xdr_bytes).unwrap();
        assert_eq!(parsed.len(), 1);
        match &parsed[0] {
            ScSpecEntry::FunctionV0(f) => {
                assert_eq!(f.name.to_string(), "transfer");
                assert_eq!(f.inputs.len(), 2);
            }
            other => panic!("expected FunctionV0, got {:?}", other),
        }
    }

    // -- build_contract_abi tests --

    #[test]
    fn build_abi_function() {
        let entry = ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: "Transfer tokens".try_into().unwrap(),
            name: "transfer".try_into().unwrap(),
            inputs: vec![ScSpecFunctionInputV0 {
                doc: "recipient".try_into().unwrap(),
                name: "to".try_into().unwrap(),
                type_: ScSpecTypeDef::Address,
            }]
            .try_into()
            .unwrap(),
            outputs: vec![ScSpecTypeDef::Bool].try_into().unwrap(),
        });

        let abi = build_contract_abi("CABC", &[entry]);
        assert_eq!(abi.functions.len(), 1);
        let f = &abi.functions[0];
        assert_eq!(f.name, "transfer");
        assert_eq!(f.doc, Some("Transfer tokens".to_string()));
        assert_eq!(f.inputs[0].name, "to");
        assert_eq!(f.inputs[0].type_ref, "address");
        assert_eq!(f.outputs, vec!["bool"]);
    }

    #[test]
    fn build_abi_skips_dunder_functions() {
        let entries = vec![
            ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                doc: "".try_into().unwrap(),
                name: "__constructor".try_into().unwrap(),
                inputs: [].to_vec().try_into().unwrap(),
                outputs: [].to_vec().try_into().unwrap(),
            }),
            ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                doc: "".try_into().unwrap(),
                name: "hello".try_into().unwrap(),
                inputs: [].to_vec().try_into().unwrap(),
                outputs: [].to_vec().try_into().unwrap(),
            }),
        ];

        let abi = build_contract_abi("CABC", &entries);
        assert_eq!(abi.functions.len(), 1);
        assert_eq!(abi.functions[0].name, "hello");
    }

    #[test]
    fn build_abi_struct() {
        let entry = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: "Token metadata".try_into().unwrap(),
            name: "TokenMeta".try_into().unwrap(),
            lib: "".try_into().unwrap(),
            fields: vec![
                ScSpecUdtStructFieldV0 {
                    doc: "".try_into().unwrap(),
                    name: "name".try_into().unwrap(),
                    type_: ScSpecTypeDef::String,
                },
                ScSpecUdtStructFieldV0 {
                    doc: "".try_into().unwrap(),
                    name: "decimals".try_into().unwrap(),
                    type_: ScSpecTypeDef::U32,
                },
            ]
            .try_into()
            .unwrap(),
        });

        let abi = build_contract_abi("CABC", &[entry]);
        assert_eq!(abi.types.len(), 1);
        match &abi.types[0] {
            AbiType::Struct { name, fields, .. } => {
                assert_eq!(name, "TokenMeta");
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].name, "name");
                assert_eq!(fields[0].type_ref, "string");
                assert_eq!(fields[1].name, "decimals");
                assert_eq!(fields[1].type_ref, "u32");
            }
            other => panic!("expected Struct, got {:?}", other),
        }
    }

    #[test]
    fn build_abi_enum() {
        let entry = ScSpecEntry::UdtEnumV0(ScSpecUdtEnumV0 {
            doc: "".try_into().unwrap(),
            name: "Color".try_into().unwrap(),
            lib: "".try_into().unwrap(),
            cases: vec![
                ScSpecUdtEnumCaseV0 {
                    doc: "".try_into().unwrap(),
                    name: "Red".try_into().unwrap(),
                    value: 0,
                },
                ScSpecUdtEnumCaseV0 {
                    doc: "".try_into().unwrap(),
                    name: "Green".try_into().unwrap(),
                    value: 1,
                },
            ]
            .try_into()
            .unwrap(),
        });

        let abi = build_contract_abi("CABC", &[entry]);
        assert_eq!(abi.types.len(), 1);
        match &abi.types[0] {
            AbiType::Enum { name, variants, .. } => {
                assert_eq!(name, "Color");
                assert_eq!(variants.len(), 2);
                assert_eq!(variants[0].name, "Red");
                assert_eq!(variants[0].value, 0);
                assert_eq!(variants[1].name, "Green");
                assert_eq!(variants[1].value, 1);
            }
            other => panic!("expected Enum, got {:?}", other),
        }
    }

    // -- WASM extraction --

    #[test]
    fn extract_spec_from_mock_wasm() {
        // Build a minimal WASM binary with a contractspecv0 custom section.
        // Minimal valid WASM: magic + version + custom section
        let spec_data = b"hello-spec";
        let section_name = b"contractspecv0";
        let name_len = section_name.len();
        let content_len = name_len + spec_data.len();

        let mut wasm = vec![];
        // WASM magic
        wasm.extend_from_slice(b"\x00asm");
        // WASM version 1
        wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // Custom section (id = 0)
        wasm.push(0x00);
        // Section size (LEB128)
        wasm.push((content_len + 1) as u8); // +1 for name length byte
                                            // Name length (LEB128)
        wasm.push(name_len as u8);
        // Name
        wasm.extend_from_slice(section_name);
        // Data
        wasm.extend_from_slice(spec_data);

        let extracted = extract_contract_spec_section(&wasm).unwrap();
        assert_eq!(extracted, spec_data);
    }

    #[test]
    fn extract_spec_missing_section() {
        // Minimal valid WASM with no custom sections
        let wasm = b"\x00asm\x01\x00\x00\x00";
        let err = extract_contract_spec_section(wasm).unwrap_err();
        match err {
            ImportError::NoContractSpec => {}
            other => panic!("expected NoContractSpec, got {:?}", other),
        }
    }

    // -- Ledger key construction --

    #[test]
    fn build_instance_key_valid() {
        // All-zeros contract address
        let contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
        let key_b64 = build_contract_instance_ledger_key(contract_id).unwrap();
        // Should be valid base64 that decodes to a LedgerKey
        let key = LedgerKey::from_xdr_base64(&key_b64, Limits::none()).unwrap();
        match key {
            LedgerKey::ContractData(data) => {
                assert_eq!(data.key, ScVal::LedgerKeyContractInstance);
                assert_eq!(data.durability, ContractDataDurability::Persistent);
            }
            other => panic!("expected ContractData, got {:?}", other),
        }
    }

    #[test]
    fn build_instance_key_invalid_g_address() {
        let err = build_contract_instance_ledger_key(
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        )
        .unwrap_err();
        match err {
            ImportError::InvalidContractId(msg) => {
                assert!(msg.contains("not a contract"), "msg: {}", msg);
            }
            other => panic!("expected InvalidContractId, got {:?}", other),
        }
    }

    #[test]
    fn build_code_key_valid() {
        let hash = Hash([0u8; 32]);
        let key_b64 = build_contract_code_ledger_key(&hash).unwrap();
        let key = LedgerKey::from_xdr_base64(&key_b64, Limits::none()).unwrap();
        match key {
            LedgerKey::ContractCode(code) => {
                assert_eq!(code.hash, Hash([0u8; 32]));
            }
            other => panic!("expected ContractCode, got {:?}", other),
        }
    }

    // -- decode_contract_id --

    #[test]
    fn decode_valid_contract_id() {
        let contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
        let bytes = decode_contract_id(contract_id).unwrap();
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn decode_invalid_contract_id() {
        let err = decode_contract_id("INVALID").unwrap_err();
        match err {
            ImportError::InvalidContractId(_) => {}
            other => panic!("expected InvalidContractId, got {:?}", other),
        }
    }
}
