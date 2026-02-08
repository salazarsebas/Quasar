//! Transaction signing with ed25519 keypairs.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use stellar_strkey::Strkey;
use stellar_xdr::curr::{
    DecoratedSignature, Limits, Signature, SignatureHint, TransactionEnvelope, WriteXdr,
};

use crate::execution_error::ExecutionError;

/// Decode a Stellar secret key (`S...` format) into an ed25519 `SigningKey`.
pub fn decode_secret_key(secret: &str) -> Result<SigningKey, ExecutionError> {
    match Strkey::from_string(secret) {
        Ok(Strkey::PrivateKeyEd25519(sk)) => Ok(SigningKey::from_bytes(&sk.0)),
        Ok(_) => Err(ExecutionError::InvalidSecretKey(
            "expected S... secret key, got different key type".into(),
        )),
        Err(e) => Err(ExecutionError::InvalidSecretKey(format!(
            "invalid secret key format: {}",
            e
        ))),
    }
}

/// Sign a `TransactionEnvelope` with the given keypair and network passphrase.
///
/// Computes `SHA256(SHA256(passphrase) || EnvelopeTypeTx [0x00000002] || tx_xdr)`,
/// signs the 32-byte hash with ed25519, and appends a `DecoratedSignature`.
pub fn sign_transaction_envelope(
    envelope: TransactionEnvelope,
    signing_key: &SigningKey,
    network_passphrase: &str,
) -> Result<TransactionEnvelope, ExecutionError> {
    let TransactionEnvelope::Tx(mut v1) = envelope else {
        return Err(ExecutionError::SigningFailed(
            "expected Tx envelope variant".into(),
        ));
    };

    // 1. Compute the transaction hash
    let tx_hash = compute_transaction_hash(&v1.tx, network_passphrase)?;

    // 2. Sign the hash
    let signature = signing_key.sign(&tx_hash);

    // 3. Build hint (last 4 bytes of public key)
    let public_key = signing_key.verifying_key();
    let pk_bytes = public_key.as_bytes();
    let hint = SignatureHint([pk_bytes[28], pk_bytes[29], pk_bytes[30], pk_bytes[31]]);

    // 4. Build DecoratedSignature
    let sig_bytes: Vec<u8> = signature.to_bytes().to_vec();
    let decorated = DecoratedSignature {
        hint,
        signature: Signature(
            sig_bytes
                .try_into()
                .map_err(|e| ExecutionError::SigningFailed(format!("signature: {}", e)))?,
        ),
    };

    // 5. Append to envelope signatures
    let sigs: Vec<DecoratedSignature> = vec![decorated];
    v1.signatures = sigs
        .try_into()
        .map_err(|e| ExecutionError::SigningFailed(format!("signatures vec: {}", e)))?;

    Ok(TransactionEnvelope::Tx(v1))
}

/// Compute the Stellar transaction hash:
/// `SHA256( SHA256(network_passphrase) || EnvelopeTypeTx (0x00000002 BE) || tx_xdr )`
fn compute_transaction_hash(
    tx: &stellar_xdr::curr::Transaction,
    network_passphrase: &str,
) -> Result<[u8; 32], ExecutionError> {
    // Network ID = SHA256(passphrase)
    let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();

    // EnvelopeType::Tx = 2 as big-endian i32
    let envelope_type_tx: [u8; 4] = 2_i32.to_be_bytes();

    // Serialize the Transaction to XDR bytes
    let tx_xdr = tx
        .to_xdr(Limits::none())
        .map_err(|e| ExecutionError::SigningFailed(format!("serialize tx: {}", e)))?;

    // Hash everything together
    let mut hasher = Sha256::new();
    hasher.update(network_id);
    hasher.update(envelope_type_tx);
    hasher.update(&tx_xdr);
    let hash: [u8; 32] = hasher.finalize().into();

    Ok(hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use stellar_xdr::curr::{
        ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Memo,
        MuxedAccount, Operation, OperationBody, Preconditions, ScAddress, ScSymbol, ScVal,
        SequenceNumber, Transaction, TransactionExt, TransactionV1Envelope, Uint256, VecM,
    };

    /// A valid Stellar test secret key (S... format).
    /// Generated from seed bytes [1u8; 32].
    fn test_secret_key_str() -> String {
        let strkey = Strkey::PrivateKeyEd25519(stellar_strkey::ed25519::PrivateKey([1u8; 32]));
        let heapless_str = strkey.to_string();
        String::from(heapless_str.as_str())
    }

    fn make_test_envelope() -> TransactionEnvelope {
        let invoke_args = InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            function_name: ScSymbol("transfer".to_string().try_into().unwrap()),
            args: vec![ScVal::Bool(true)].try_into().unwrap(),
        };

        let invoke_op = InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke_args),
            auth: VecM::default(),
        };

        let operation = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(invoke_op),
        };

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(42),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![operation].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        })
    }

    #[test]
    fn decode_valid_secret_key() {
        let sk_str = test_secret_key_str();
        let result = decode_secret_key(&sk_str);
        assert!(result.is_ok(), "should decode valid S... key");
        let sk = result.unwrap();
        assert_eq!(sk.to_bytes(), [1u8; 32]);
    }

    #[test]
    fn decode_invalid_secret_key() {
        let result = decode_secret_key("INVALID_KEY");
        assert!(result.is_err());
        match result.unwrap_err() {
            ExecutionError::InvalidSecretKey(msg) => {
                assert!(msg.contains("invalid secret key format"), "msg: {}", msg);
            }
            other => panic!("expected InvalidSecretKey, got {:?}", other),
        }
    }

    #[test]
    fn decode_g_address_as_secret_key_fails() {
        // G... is a public key, not a secret key
        let result = decode_secret_key("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF");
        assert!(result.is_err());
        match result.unwrap_err() {
            ExecutionError::InvalidSecretKey(msg) => {
                assert!(msg.contains("expected S... secret key"), "msg: {}", msg);
            }
            other => panic!("expected InvalidSecretKey, got {:?}", other),
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk_str = test_secret_key_str();
        let signing_key = decode_secret_key(&sk_str).unwrap();
        let envelope = make_test_envelope();
        let passphrase = "Test SDF Network ; September 2015";

        // Sign
        let signed = sign_transaction_envelope(envelope, &signing_key, passphrase).unwrap();

        // Verify it has exactly 1 signature
        match &signed {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.signatures.len(), 1);

                // Verify the signature hint is the last 4 bytes of the public key
                let pk = signing_key.verifying_key();
                let pk_bytes = pk.as_bytes();
                assert_eq!(
                    v1.signatures[0].hint.0,
                    [pk_bytes[28], pk_bytes[29], pk_bytes[30], pk_bytes[31]]
                );

                // Verify the signature is valid
                let tx_hash = compute_transaction_hash(&v1.tx, passphrase).unwrap();
                let sig_bytes = &v1.signatures[0].signature.0.to_vec();
                let sig = ed25519_dalek::Signature::from_slice(sig_bytes).unwrap();
                assert!(pk.verify(&tx_hash, &sig).is_ok(), "signature should verify");
            }
            other => panic!("expected Tx variant, got {:?}", other),
        }
    }
}
