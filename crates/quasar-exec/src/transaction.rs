//! Build unsigned Stellar `TransactionEnvelope` from compiled data.

use stellar_xdr::curr::{
    HostFunction, InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody,
    Preconditions, ReadXdr, SequenceNumber, SorobanAuthorizationEntry, SorobanTransactionData,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM,
    WriteXdr,
};

use quasar_compile::CompiledTransaction;

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

/// Assemble a transaction by applying simulation results.
///
/// Takes the unsigned envelope and the simulation output, then:
/// 1. Sets `SorobanTransactionData` on the transaction extension
/// 2. Updates the fee to `base_fee + min_resource_fee`
/// 3. Populates auth entries on the `InvokeHostFunctionOp`
pub fn assemble_transaction(
    envelope: TransactionEnvelope,
    transaction_data_b64: &str,
    auth_entries_b64: &[String],
    min_resource_fee: u64,
    base_fee: u32,
) -> Result<TransactionEnvelope, SimulationError> {
    let TransactionEnvelope::Tx(mut v1) = envelope else {
        return Err(SimulationError::Xdr(
            "expected Tx envelope variant".to_string(),
        ));
    };

    // 1. Decode and set SorobanTransactionData
    if !transaction_data_b64.is_empty() {
        let soroban_data =
            SorobanTransactionData::from_xdr_base64(transaction_data_b64, Limits::none())
                .map_err(|e| SimulationError::Xdr(format!("transaction data: {}", e)))?;
        v1.tx.ext = TransactionExt::V1(soroban_data);
    }

    // 2. Update fee: base_fee + min_resource_fee (capped at u32::MAX)
    let total_fee = (base_fee as u64).saturating_add(min_resource_fee);
    v1.tx.fee = u32::try_from(total_fee.min(u32::MAX as u64)).unwrap_or(u32::MAX);

    // 3. Decode and set auth entries on the InvokeHostFunctionOp
    //    VecM doesn't implement DerefMut, so we rebuild the operations vec.
    if !auth_entries_b64.is_empty() {
        let mut ops: Vec<Operation> = v1.tx.operations.to_vec();
        if let OperationBody::InvokeHostFunction(ref mut op) = ops[0].body {
            let mut auth_vec = Vec::with_capacity(auth_entries_b64.len());
            for auth_b64 in auth_entries_b64 {
                let entry = SorobanAuthorizationEntry::from_xdr_base64(auth_b64, Limits::none())
                    .map_err(|e| SimulationError::Xdr(format!("auth entry: {}", e)))?;
                auth_vec.push(entry);
            }
            op.auth = auth_vec
                .try_into()
                .map_err(|e| SimulationError::Xdr(format!("auth vec: {}", e)))?;
        }
        v1.tx.operations = ops
            .try_into()
            .map_err(|e| SimulationError::Xdr(format!("operations: {}", e)))?;
    }

    Ok(TransactionEnvelope::Tx(v1))
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
        AccountId, Hash, InvokeContractArgs, LedgerFootprint, PublicKey, ReadXdr, ScAddress,
        ScSymbol, ScVal, SorobanResources, SorobanTransactionDataExt, Uint256,
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

    fn make_soroban_tx_data_b64() -> String {
        let data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: VecM::default(),
                    read_write: VecM::default(),
                },
                instructions: 100_000,
                disk_read_bytes: 1024,
                write_bytes: 512,
            },
            resource_fee: 50_000,
        };
        data.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_auth_entry_b64() -> String {
        use stellar_xdr::curr::{
            SorobanAuthorizationEntry, SorobanAuthorizedInvocation, SorobanCredentials,
        };
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: SorobanAuthorizedInvocation {
                function: stellar_xdr::curr::SorobanAuthorizedFunction::ContractFn(
                    stellar_xdr::curr::InvokeContractArgs {
                        contract_address: ScAddress::Contract(stellar_xdr::curr::ContractId(Hash(
                            [0u8; 32],
                        ))),
                        function_name: ScSymbol("transfer".to_string().try_into().unwrap()),
                        args: VecM::default(),
                    },
                ),
                sub_invocations: VecM::default(),
            },
        };
        entry.to_xdr_base64(Limits::none()).unwrap()
    }

    #[test]
    fn assemble_sets_transaction_data() {
        let compiled = make_compiled(100);
        let envelope = build_transaction_envelope(&compiled, 42).unwrap();
        let tx_data_b64 = make_soroban_tx_data_b64();

        let assembled = assemble_transaction(envelope, &tx_data_b64, &[], 50_000, 100).unwrap();

        match &assembled {
            TransactionEnvelope::Tx(v1) => match &v1.tx.ext {
                TransactionExt::V1(data) => {
                    assert_eq!(data.resource_fee, 50_000);
                    assert_eq!(data.resources.instructions, 100_000);
                }
                other => panic!("expected V1 ext, got {:?}", other),
            },
            other => panic!("expected Tx variant, got {:?}", other),
        }
    }

    #[test]
    fn assemble_updates_fee() {
        let compiled = make_compiled(100);
        let envelope = build_transaction_envelope(&compiled, 42).unwrap();

        let assembled = assemble_transaction(envelope, "", &[], 50_000, 100).unwrap();

        match &assembled {
            TransactionEnvelope::Tx(v1) => {
                // base_fee (100) + min_resource_fee (50_000) = 50_100
                assert_eq!(v1.tx.fee, 50_100);
            }
            other => panic!("expected Tx variant, got {:?}", other),
        }
    }

    #[test]
    fn assemble_sets_auth_entries() {
        let compiled = make_compiled(100);
        let envelope = build_transaction_envelope(&compiled, 42).unwrap();
        let auth_b64 = make_auth_entry_b64();

        let assembled = assemble_transaction(envelope, "", &[auth_b64], 0, 100).unwrap();

        match &assembled {
            TransactionEnvelope::Tx(v1) => match &v1.tx.operations[0].body {
                OperationBody::InvokeHostFunction(op) => {
                    assert_eq!(op.auth.len(), 1);
                }
                other => panic!("expected InvokeHostFunction, got {:?}", other),
            },
            other => panic!("expected Tx variant, got {:?}", other),
        }
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
