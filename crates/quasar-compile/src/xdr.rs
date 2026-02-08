//! XDR compiler: converts JSON IR into Stellar XDR types.
//!
//! Produces `InvokeContractArgs` for each call, serializable to base64 XDR.

use std::fmt;

use stellar_strkey::Strkey;
use stellar_xdr::curr::{
    AccountId, ContractId, Hash, Int128Parts, Int256Parts, InvokeContractArgs, Limits, PublicKey,
    ScAddress, ScBytes, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec, StringM, UInt128Parts,
    UInt256Parts, Uint256, WriteXdr,
};

use crate::ir::{IrCall, IrMapEntry, IrValue, JsonIR};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur during XDR compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XdrError {
    InvalidNumber {
        kind: &'static str,
        value: String,
        reason: String,
    },
    InvalidAddress {
        address: String,
        reason: String,
    },
    InvalidHex {
        value: String,
        reason: String,
    },
    FeeOverflow {
        fee_stroops: u64,
    },
    XdrSerialize(String),
}

impl fmt::Display for XdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XdrError::InvalidNumber {
                kind,
                value,
                reason,
            } => write!(f, "invalid {} value '{}': {}", kind, value, reason),
            XdrError::InvalidAddress { address, reason } => {
                write!(f, "invalid address '{}': {}", address, reason)
            }
            XdrError::InvalidHex { value, reason } => {
                write!(f, "invalid hex bytes '{}': {}", value, reason)
            }
            XdrError::FeeOverflow { fee_stroops } => {
                write!(
                    f,
                    "fee {} exceeds maximum u32 value ({})",
                    fee_stroops,
                    u32::MAX
                )
            }
            XdrError::XdrSerialize(msg) => write!(f, "XDR serialization failed: {}", msg),
        }
    }
}

impl std::error::Error for XdrError {}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Compiled output for a single contract invocation.
#[derive(Debug)]
pub struct CompiledTransaction {
    pub network_passphrase: String,
    pub source_account: AccountId,
    pub fee: u32,
    pub timeout_seconds: u64,
    pub invoke_args: InvokeContractArgs,
}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------

/// Compiles a `JsonIR` into Stellar XDR types.
pub struct XdrCompiler;

impl XdrCompiler {
    /// Compile a complete IR into one `CompiledTransaction` per call.
    pub fn compile(ir: &JsonIR) -> Result<Vec<CompiledTransaction>, XdrError> {
        let source_account = Self::decode_account_id(&ir.signing.source)?;
        let fee = Self::validate_fee(ir.signing.fee_stroops)?;

        let mut transactions = Vec::with_capacity(ir.calls.len());
        for call in &ir.calls {
            let invoke_args = Self::compile_call(call)?;
            transactions.push(CompiledTransaction {
                network_passphrase: ir.network_passphrase.clone(),
                source_account: source_account.clone(),
                fee,
                timeout_seconds: ir.signing.timeout_seconds,
                invoke_args,
            });
        }
        Ok(transactions)
    }

    /// Serialize an `InvokeContractArgs` to base64-encoded XDR.
    pub fn to_xdr_base64(args: &InvokeContractArgs) -> Result<String, XdrError> {
        args.to_xdr_base64(Limits::none())
            .map_err(|e| XdrError::XdrSerialize(e.to_string()))
    }

    // -- Call compilation ---------------------------------------------------

    fn compile_call(call: &IrCall) -> Result<InvokeContractArgs, XdrError> {
        let contract_address = Self::decode_address(&call.contract)?;
        let function_name: ScSymbol = call.method.clone().try_into().map_err(|_| {
            XdrError::XdrSerialize(format!("method name too long: {}", call.method))
        })?;

        let mut args: Vec<ScVal> = Vec::with_capacity(call.args.len());
        for arg in &call.args {
            args.push(Self::to_scval(arg)?);
        }

        Ok(InvokeContractArgs {
            contract_address,
            function_name,
            args: args
                .try_into()
                .map_err(|_| XdrError::XdrSerialize("too many arguments".to_string()))?,
        })
    }

    // -- Value conversion ---------------------------------------------------

    fn to_scval(value: &IrValue) -> Result<ScVal, XdrError> {
        match value {
            IrValue::Bool(v) => Ok(ScVal::Bool(*v)),
            IrValue::U32(v) => Ok(ScVal::U32(*v)),
            IrValue::I32(v) => Ok(ScVal::I32(*v)),
            IrValue::U64(v) => Ok(ScVal::U64(*v)),
            IrValue::I64(v) => Ok(ScVal::I64(*v)),
            IrValue::U128(s) => Ok(ScVal::U128(Self::u128_to_parts(s)?)),
            IrValue::I128(s) => Ok(ScVal::I128(Self::i128_to_parts(s)?)),
            IrValue::U256(s) => Ok(ScVal::U256(Self::u256_to_parts(s)?)),
            IrValue::I256(s) => Ok(ScVal::I256(Self::i256_to_parts(s)?)),
            IrValue::String(s) => {
                let sm: StringM = s
                    .clone()
                    .try_into()
                    .map_err(|_| XdrError::XdrSerialize("string too long".to_string()))?;
                Ok(ScVal::String(ScString(sm)))
            }
            IrValue::Symbol(s) => {
                let sc: ScSymbol = s
                    .clone()
                    .try_into()
                    .map_err(|_| XdrError::XdrSerialize("symbol too long".to_string()))?;
                Ok(ScVal::Symbol(sc))
            }
            IrValue::Bytes(hex_str) => {
                let bytes = Self::decode_hex(hex_str)?;
                let sc: ScBytes = bytes
                    .try_into()
                    .map_err(|_| XdrError::XdrSerialize("bytes too long".to_string()))?;
                Ok(ScVal::Bytes(sc))
            }
            IrValue::Address(addr) => Ok(ScVal::Address(Self::decode_address(addr)?)),
            IrValue::Vec(items) => {
                let sc_vals: Result<Vec<ScVal>, _> = items.iter().map(Self::to_scval).collect();
                let sc_vec: ScVec = sc_vals?
                    .try_into()
                    .map_err(|_| XdrError::XdrSerialize("vec too large".to_string()))?;
                Ok(ScVal::Vec(Some(sc_vec)))
            }
            IrValue::Map(entries) => {
                let sc_entries: Result<Vec<ScMapEntry>, _> =
                    entries.iter().map(Self::map_entry_to_sc).collect();
                let sc_map: ScMap = sc_entries?
                    .try_into()
                    .map_err(|_| XdrError::XdrSerialize("map too large".to_string()))?;
                Ok(ScVal::Map(Some(sc_map)))
            }
        }
    }

    fn map_entry_to_sc(entry: &IrMapEntry) -> Result<ScMapEntry, XdrError> {
        Ok(ScMapEntry {
            key: Self::to_scval(&entry.key)?,
            val: Self::to_scval(&entry.value)?,
        })
    }

    // -- Numeric helpers ----------------------------------------------------

    fn u128_to_parts(s: &str) -> Result<UInt128Parts, XdrError> {
        let v: u128 = s.parse().map_err(|e| XdrError::InvalidNumber {
            kind: "u128",
            value: s.to_string(),
            reason: format!("{}", e),
        })?;
        Ok(UInt128Parts {
            hi: (v >> 64) as u64,
            lo: v as u64,
        })
    }

    fn i128_to_parts(s: &str) -> Result<Int128Parts, XdrError> {
        let v: i128 = s.parse().map_err(|e| XdrError::InvalidNumber {
            kind: "i128",
            value: s.to_string(),
            reason: format!("{}", e),
        })?;
        Ok(Int128Parts {
            hi: (v >> 64) as i64,
            lo: v as u64,
        })
    }

    fn u256_to_parts(s: &str) -> Result<UInt256Parts, XdrError> {
        let (hi, lo) = parse_u256_decimal(s).map_err(|reason| XdrError::InvalidNumber {
            kind: "u256",
            value: s.to_string(),
            reason,
        })?;
        Ok(UInt256Parts {
            hi_hi: (hi >> 64) as u64,
            hi_lo: hi as u64,
            lo_hi: (lo >> 64) as u64,
            lo_lo: lo as u64,
        })
    }

    fn i256_to_parts(s: &str) -> Result<Int256Parts, XdrError> {
        let is_negative = s.starts_with('-');
        let abs_str = if is_negative { &s[1..] } else { s };

        let (abs_hi, abs_lo) =
            parse_u256_decimal(abs_str).map_err(|reason| XdrError::InvalidNumber {
                kind: "i256",
                value: s.to_string(),
                reason,
            })?;

        if is_negative {
            // Two's complement negation: NOT + 1
            let not_lo = !abs_lo;
            let not_hi = !abs_hi;
            let (neg_lo, carry) = not_lo.overflowing_add(1);
            let neg_hi = not_hi.wrapping_add(if carry { 1 } else { 0 });

            Ok(Int256Parts {
                hi_hi: (neg_hi >> 64) as i64,
                hi_lo: neg_hi as u64,
                lo_hi: (neg_lo >> 64) as u64,
                lo_lo: neg_lo as u64,
            })
        } else {
            Ok(Int256Parts {
                hi_hi: (abs_hi >> 64) as i64,
                hi_lo: abs_hi as u64,
                lo_hi: (abs_lo >> 64) as u64,
                lo_lo: abs_lo as u64,
            })
        }
    }

    // -- Address decoding ---------------------------------------------------

    fn decode_address(addr: &str) -> Result<ScAddress, XdrError> {
        let strkey = Strkey::from_string(addr).map_err(|e| XdrError::InvalidAddress {
            address: addr.to_string(),
            reason: format!("{}", e),
        })?;

        match strkey {
            Strkey::PublicKeyEd25519(pk) => {
                let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)));
                Ok(ScAddress::Account(account_id))
            }
            Strkey::Contract(c) => Ok(ScAddress::Contract(ContractId(Hash(c.0)))),
            _ => Err(XdrError::InvalidAddress {
                address: addr.to_string(),
                reason: "expected G... (account) or C... (contract) address".to_string(),
            }),
        }
    }

    fn decode_account_id(addr: &str) -> Result<AccountId, XdrError> {
        let strkey = Strkey::from_string(addr).map_err(|e| XdrError::InvalidAddress {
            address: addr.to_string(),
            reason: format!("{}", e),
        })?;

        match strkey {
            Strkey::PublicKeyEd25519(pk) => {
                Ok(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0))))
            }
            _ => Err(XdrError::InvalidAddress {
                address: addr.to_string(),
                reason: "source must be a G... account address".to_string(),
            }),
        }
    }

    fn validate_fee(fee_stroops: u64) -> Result<u32, XdrError> {
        u32::try_from(fee_stroops).map_err(|_| XdrError::FeeOverflow { fee_stroops })
    }

    // -- Hex decoding -------------------------------------------------------

    fn decode_hex(hex_str: &str) -> Result<Vec<u8>, XdrError> {
        let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        if hex.is_empty() {
            return Ok(Vec::new());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| XdrError::InvalidHex {
                    value: hex_str.to_string(),
                    reason: format!("{}", e),
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// 256-bit decimal parsing (no external bigint crate)
// ---------------------------------------------------------------------------

/// Parse a non-negative decimal string into `(hi_u128, lo_u128)` where the
/// full 256-bit value = `hi * 2^128 + lo`.
fn parse_u256_decimal(s: &str) -> Result<(u128, u128), String> {
    if s.is_empty() {
        return Err("empty string".to_string());
    }

    let mut hi: u128 = 0;
    let mut lo: u128 = 0;

    for ch in s.bytes() {
        if !ch.is_ascii_digit() {
            return Err(format!("invalid digit '{}'", ch as char));
        }
        let digit = (ch - b'0') as u128;

        // Multiply (hi, lo) by 10 with wide arithmetic, then add digit.
        let (new_lo, carry) = wide_mul_add(lo, 10, digit);
        let new_hi = hi
            .checked_mul(10)
            .and_then(|h| h.checked_add(carry))
            .ok_or_else(|| "value out of u256 range".to_string())?;

        hi = new_hi;
        lo = new_lo;
    }

    Ok((hi, lo))
}

/// Compute `a * b + c` returning `(lo_128, carry_128)`.
/// The full result is `carry * 2^128 + lo`.
fn wide_mul_add(a: u128, b: u128, c: u128) -> (u128, u128) {
    // Split a into two 64-bit halves to avoid u128 overflow.
    let a_hi = a >> 64;
    let a_lo = a & 0xFFFF_FFFF_FFFF_FFFF;

    let prod_lo = a_lo * b; // max: (2^64-1) * b, fits in u128 for small b
    let prod_hi = a_hi * b;

    // prod_lo + c
    let (sum_lo, carry1) = prod_lo.overflowing_add(c);

    // Split sum_lo into halves to add prod_hi shifted left by 64
    let sum_lo_hi = sum_lo >> 64;
    let sum_lo_lo = sum_lo & 0xFFFF_FFFF_FFFF_FFFF;

    let mid = prod_hi + sum_lo_hi + if carry1 { 1 } else { 0 };
    let result_lo = (mid << 64) | sum_lo_lo;
    let carry = mid >> 64;

    (result_lo, carry)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrCall, IrMapEntry, IrSigning, IrValue, JsonIR};
    use stellar_xdr::curr::{Limits, ReadXdr};

    const ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    fn test_ir() -> JsonIR {
        JsonIR {
            version: 1,
            network: "testnet".to_string(),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            calls: vec![IrCall {
                contract: CONTRACT.to_string(),
                method: "transfer".to_string(),
                args: vec![],
            }],
            signing: IrSigning {
                source: ACCOUNT.to_string(),
                fee_stroops: 100_000,
                timeout_seconds: 30,
            },
        }
    }

    // -- i128 ---------------------------------------------------------------

    #[test]
    fn i128_positive() {
        let parts = XdrCompiler::i128_to_parts("10000000").unwrap();
        assert_eq!(
            parts,
            Int128Parts {
                hi: 0,
                lo: 10_000_000
            }
        );
    }

    #[test]
    fn i128_negative_one() {
        let parts = XdrCompiler::i128_to_parts("-1").unwrap();
        assert_eq!(
            parts,
            Int128Parts {
                hi: -1,
                lo: u64::MAX
            }
        );
    }

    #[test]
    fn i128_max() {
        let parts = XdrCompiler::i128_to_parts("170141183460469231731687303715884105727").unwrap();
        assert_eq!(
            parts,
            Int128Parts {
                hi: i64::MAX,
                lo: u64::MAX
            }
        );
    }

    #[test]
    fn i128_min() {
        let parts = XdrCompiler::i128_to_parts("-170141183460469231731687303715884105728").unwrap();
        assert_eq!(
            parts,
            Int128Parts {
                hi: i64::MIN,
                lo: 0
            }
        );
    }

    // -- u128 ---------------------------------------------------------------

    #[test]
    fn u128_zero() {
        let parts = XdrCompiler::u128_to_parts("0").unwrap();
        assert_eq!(parts, UInt128Parts { hi: 0, lo: 0 });
    }

    #[test]
    fn u128_max() {
        let parts = XdrCompiler::u128_to_parts("340282366920938463463374607431768211455").unwrap();
        assert_eq!(
            parts,
            UInt128Parts {
                hi: u64::MAX,
                lo: u64::MAX
            }
        );
    }

    // -- Address decoding ---------------------------------------------------

    #[test]
    fn decode_g_address() {
        let sc = XdrCompiler::decode_address(ACCOUNT).unwrap();
        match sc {
            ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(key))) => {
                assert_eq!(key.0, [0u8; 32]);
            }
            _ => panic!("expected Account"),
        }
    }

    #[test]
    fn decode_c_address() {
        let sc = XdrCompiler::decode_address(CONTRACT).unwrap();
        match sc {
            ScAddress::Contract(contract_id) => {
                assert_eq!(contract_id.0 .0, [0u8; 32]);
            }
            _ => panic!("expected Contract"),
        }
    }

    // -- ScVal conversions --------------------------------------------------

    #[test]
    fn bool_to_scval() {
        assert_eq!(
            XdrCompiler::to_scval(&IrValue::Bool(true)).unwrap(),
            ScVal::Bool(true)
        );
    }

    #[test]
    fn u32_to_scval() {
        assert_eq!(
            XdrCompiler::to_scval(&IrValue::U32(42)).unwrap(),
            ScVal::U32(42)
        );
    }

    #[test]
    fn i32_to_scval() {
        assert_eq!(
            XdrCompiler::to_scval(&IrValue::I32(-7)).unwrap(),
            ScVal::I32(-7)
        );
    }

    #[test]
    fn symbol_to_scval() {
        let result = XdrCompiler::to_scval(&IrValue::Symbol("transfer".to_string())).unwrap();
        match result {
            ScVal::Symbol(s) => assert_eq!(s.to_string(), "transfer"),
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn string_to_scval() {
        let result = XdrCompiler::to_scval(&IrValue::String("hello".to_string())).unwrap();
        match result {
            ScVal::String(s) => assert_eq!(s.to_string(), "hello"),
            _ => panic!("expected String"),
        }
    }

    #[test]
    fn bytes_to_scval() {
        let result = XdrCompiler::to_scval(&IrValue::Bytes("0xdeadbeef".to_string())).unwrap();
        match result {
            ScVal::Bytes(b) => assert_eq!(b.as_slice(), &[0xde, 0xad, 0xbe, 0xef]),
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn empty_bytes_to_scval() {
        let result = XdrCompiler::to_scval(&IrValue::Bytes("0x".to_string())).unwrap();
        match result {
            ScVal::Bytes(b) => assert!(b.as_slice().is_empty()),
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn vec_to_scval() {
        let result =
            XdrCompiler::to_scval(&IrValue::Vec(vec![IrValue::U32(1), IrValue::U32(2)])).unwrap();
        match result {
            ScVal::Vec(Some(sv)) => {
                let items: &[ScVal] = sv.as_slice();
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], ScVal::U32(1));
                assert_eq!(items[1], ScVal::U32(2));
            }
            _ => panic!("expected Vec"),
        }
    }

    #[test]
    fn map_to_scval() {
        let result = XdrCompiler::to_scval(&IrValue::Map(vec![IrMapEntry {
            key: IrValue::Symbol("x".to_string()),
            value: IrValue::I128("1".to_string()),
        }]))
        .unwrap();
        match result {
            ScVal::Map(Some(m)) => {
                assert_eq!(m.as_slice().len(), 1);
            }
            _ => panic!("expected Map"),
        }
    }

    // -- Fee ----------------------------------------------------------------

    #[test]
    fn fee_overflow_error() {
        let err = XdrCompiler::validate_fee(u64::MAX);
        assert!(err.is_err());
        match err.unwrap_err() {
            XdrError::FeeOverflow { .. } => {}
            other => panic!("expected FeeOverflow, got: {:?}", other),
        }
    }

    // -- Full compile -------------------------------------------------------

    #[test]
    fn compile_empty_args() {
        let ir = test_ir();
        let txs = XdrCompiler::compile(&ir).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].fee, 100_000);
        assert!(txs[0].invoke_args.args.as_slice().is_empty());
    }

    #[test]
    fn compile_with_args() {
        let mut ir = test_ir();
        ir.calls[0].args = vec![
            IrValue::Address(ACCOUNT.to_string()),
            IrValue::Address(ACCOUNT.to_string()),
            IrValue::I128("10000000".to_string()),
        ];
        let txs = XdrCompiler::compile(&ir).unwrap();
        assert_eq!(txs[0].invoke_args.args.len(), 3);
    }

    // -- XDR roundtrip ------------------------------------------------------

    #[test]
    fn xdr_roundtrip() {
        let mut ir = test_ir();
        ir.calls[0].args = vec![
            IrValue::Address(ACCOUNT.to_string()),
            IrValue::I128("10000000".to_string()),
        ];

        let txs = XdrCompiler::compile(&ir).unwrap();
        let b64 = XdrCompiler::to_xdr_base64(&txs[0].invoke_args).unwrap();

        // Decode back and verify equality
        let decoded = InvokeContractArgs::from_xdr_base64(&b64, Limits::none()).unwrap();
        assert_eq!(decoded, txs[0].invoke_args);
    }

    #[test]
    fn base64_output_not_empty() {
        let ir = test_ir();
        let txs = XdrCompiler::compile(&ir).unwrap();
        let b64 = XdrCompiler::to_xdr_base64(&txs[0].invoke_args).unwrap();
        assert!(!b64.is_empty());
    }

    // -- Fixture integration ------------------------------------------------

    #[test]
    fn fixture_transfer_compiles_to_xdr() {
        let source = include_str!("../../../tests/fixtures/transfer.soro");
        let tokens = quasar_syntax::lexer::Lexer::tokenize(source).unwrap();
        let program = quasar_syntax::parser::Parser::parse(&tokens).unwrap();
        let ir = crate::Compiler::compile(&program);
        let txs = XdrCompiler::compile(&ir).unwrap();
        assert_eq!(txs.len(), 1);

        let b64 = XdrCompiler::to_xdr_base64(&txs[0].invoke_args).unwrap();
        let decoded = InvokeContractArgs::from_xdr_base64(&b64, Limits::none()).unwrap();
        assert_eq!(decoded, txs[0].invoke_args);
    }
}
