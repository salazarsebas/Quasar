//! Build unsigned Stellar `TransactionEnvelope` from compiled data.

use stellar_xdr::curr::{
    HostFunction, InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody,
    Preconditions, SequenceNumber, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

use callsoro_compile::CompiledTransaction;

use crate::error::SimulationError;

/// Build an unsigned `TransactionEnvelope` from a compiled transaction and sequence number.
///
/// The resulting envelope has no signatures and is suitable for `simulateTransaction`.
pub fn build_transaction_envelope(
    compiled: &CompiledTransaction,
    sequence_number: i64,
) -> Result<TransactionEnvelope, SimulationError> {
    let host_function = HostFunction::InvokeContract(compiled.invoke_args.clone());

    let invoke_op = InvokeHostFunctionOp {
        host_function,
        auth: VecM::default(),
    };

    let operation = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(invoke_op),
    };

    let operations = vec![operation]
        .try_into()
        .map_err(|e| SimulationError::Xdr(format!("operations: {}", e)))?;

    // Extract the raw ed25519 public key bytes from the AccountId
    let account_key = match &compiled.source_account.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => key.0,
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(account_key)),
        fee: compiled.fee,
        seq_num: SequenceNumber(sequence_number),
        cond: Preconditions::None,
        memo: Memo::None,
        operations,
        ext: TransactionExt::V0,
    };

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    Ok(envelope)
}

/// Serialize a `TransactionEnvelope` to base64 XDR.
pub fn envelope_to_base64(envelope: &TransactionEnvelope) -> Result<String, SimulationError> {
    envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| SimulationError::Xdr(format!("serialize envelope: {}", e)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        AccountId, Hash, InvokeContractArgs, PublicKey, ReadXdr, ScAddress, ScSymbol, ScVal,
        Uint256,
    };

    fn make_compiled(fee: u32) -> CompiledTransaction {
        let invoke_args = InvokeContractArgs {
            contract_address: ScAddress::Contract(stellar_xdr::curr::ContractId(Hash([0u8; 32]))),
            function_name: ScSymbol("transfer".to_string().try_into().unwrap()),
            args: vec![ScVal::Bool(true)].try_into().unwrap(),
        };
        CompiledTransaction {
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            source_account: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32]))),
            fee,
            timeout_seconds: 30,
            invoke_args,
        }
    }

    #[test]
    fn build_envelope_basic() {
        let compiled = make_compiled(100);
        let envelope = build_transaction_envelope(&compiled, 42).unwrap();
        // Round-trip: serialize and deserialize
        let b64 = envelope_to_base64(&envelope).unwrap();
        let decoded = TransactionEnvelope::from_xdr_base64(&b64, Limits::none());
        assert!(decoded.is_ok(), "should round-trip: {:?}", decoded);
    }

    #[test]
    fn build_envelope_fields() {
        let compiled = make_compiled(200);
        let envelope = build_transaction_envelope(&compiled, 99).unwrap();
        match &envelope {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.tx.fee, 200);
                assert_eq!(v1.tx.seq_num.0, 99);
                assert!(v1.signatures.is_empty());
                assert_eq!(v1.tx.operations.len(), 1);
                match &v1.tx.operations[0].body {
                    OperationBody::InvokeHostFunction(op) => match &op.host_function {
                        HostFunction::InvokeContract(args) => {
                            assert_eq!(args.function_name.to_string(), "transfer");
                        }
                        other => panic!("expected InvokeContract, got {:?}", other),
                    },
                    other => panic!("expected InvokeHostFunction, got {:?}", other),
                }
            }
            other => panic!("expected Tx variant, got {:?}", other),
        }
    }

    #[test]
    fn build_envelope_zero_fee() {
        let compiled = make_compiled(0);
        let envelope = build_transaction_envelope(&compiled, 1).unwrap();
        let b64 = envelope_to_base64(&envelope).unwrap();
        assert!(!b64.is_empty());
    }

    #[test]
    fn build_envelope_multiple_calls_get_separate_envelopes() {
        let compiled1 = make_compiled(100);
        let compiled2 = make_compiled(200);
        let env1 = build_transaction_envelope(&compiled1, 1).unwrap();
        let env2 = build_transaction_envelope(&compiled2, 2).unwrap();
        let b64_1 = envelope_to_base64(&env1).unwrap();
        let b64_2 = envelope_to_base64(&env2).unwrap();
        assert_ne!(
            b64_1, b64_2,
            "different fees/seqs should produce different XDR"
        );
    }
}
