//! Full transaction execution orchestrator: simulate -> assemble -> sign -> submit -> poll.

use std::thread;
use std::time::{Duration, Instant};

use callsoro_compile::{CompiledTransaction, JsonIR};

use crate::execution_error::ExecutionError;
use crate::rpc::RpcClient;
use crate::sign::{decode_secret_key, sign_transaction_envelope};
use crate::simulator::parse_simulation_outcome;
use crate::transaction::{assemble_transaction, build_transaction_envelope, envelope_to_base64};
use crate::types::{ExecutionOutcome, ExecutionResult, SimulationOutcome};

/// Configuration for the executor.
pub struct ExecutorConfig {
    /// Stellar secret key (S... format)
    pub secret_key: String,
    /// If true, only simulate without submitting
    pub dry_run: bool,
    /// Maximum seconds to poll for transaction confirmation (default: 300)
    pub poll_timeout_seconds: u64,
    /// Initial polling interval in milliseconds (default: 1000)
    pub poll_initial_interval_ms: u64,
    /// Maximum polling interval in milliseconds (default: 30000)
    pub poll_max_interval_ms: u64,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            secret_key: String::new(),
            dry_run: false,
            poll_timeout_seconds: 300,
            poll_initial_interval_ms: 1000,
            poll_max_interval_ms: 30000,
        }
    }
}

/// Orchestrates full transaction execution against a Soroban RPC endpoint.
pub struct Executor {
    rpc: RpcClient,
    config: ExecutorConfig,
}

impl Executor {
    /// Create a new executor pointing at the given RPC URL.
    pub fn new(rpc_url: &str, config: ExecutorConfig) -> Self {
        Executor {
            rpc: RpcClient::new(rpc_url),
            config,
        }
    }

    /// Execute all calls in the compiled transactions.
    ///
    /// Each call is executed as a separate transaction, sequentially.
    /// Aborts on first failure.
    pub fn execute(
        &self,
        transactions: &[CompiledTransaction],
        ir: &JsonIR,
    ) -> Result<Vec<ExecutionResult>, ExecutionError> {
        if transactions.is_empty() {
            return Ok(vec![]);
        }

        // Validate secret key upfront (fail fast)
        let signing_key = decode_secret_key(&self.config.secret_key)?;

        // Fetch account info once
        let source_str = &ir.signing.source;
        let account_info = self.rpc.get_account(source_str)?;
        let mut sequence = account_info.sequence;

        let mut results = Vec::with_capacity(transactions.len());

        for (i, compiled) in transactions.iter().enumerate() {
            let call = &ir.calls[i];
            sequence += 1;

            let result = self.execute_single(
                compiled,
                &signing_key,
                sequence,
                i,
                &call.contract,
                &call.method,
            )?;

            // Abort on failure
            if matches!(&result.outcome, ExecutionOutcome::Failed { .. }) {
                results.push(result);
                break;
            }

            results.push(result);
        }

        Ok(results)
    }

    fn execute_single(
        &self,
        compiled: &CompiledTransaction,
        signing_key: &ed25519_dalek::SigningKey,
        sequence: i64,
        call_index: usize,
        contract: &str,
        method: &str,
    ) -> Result<ExecutionResult, ExecutionError> {
        // 1. Build unsigned envelope
        let envelope = build_transaction_envelope(compiled, sequence)?;
        let envelope_b64 = envelope_to_base64(&envelope)?;

        // 2. Simulate
        let sim_response = self.rpc.simulate_transaction(&envelope_b64)?;
        let outcome = parse_simulation_outcome(&sim_response)?;

        let (transaction_data, auth, min_resource_fee, return_value) = match &outcome {
            SimulationOutcome::Success {
                transaction_data,
                auth,
                min_resource_fee,
                return_value,
                ..
            } => (
                transaction_data.clone(),
                auth.clone(),
                *min_resource_fee,
                return_value.clone(),
            ),
            SimulationOutcome::Failed { error } => {
                return Ok(ExecutionResult {
                    call_index,
                    contract: contract.into(),
                    method: method.into(),
                    outcome: ExecutionOutcome::Failed {
                        tx_hash: None,
                        error: error.clone(),
                    },
                });
            }
        };

        let total_fee = compiled.fee as u64 + min_resource_fee;

        // 3. Dry-run: stop here
        if self.config.dry_run {
            return Ok(ExecutionResult {
                call_index,
                contract: contract.into(),
                method: method.into(),
                outcome: ExecutionOutcome::Simulated {
                    fee: total_fee,
                    return_value,
                },
            });
        }

        // 4. Assemble
        let assembled = assemble_transaction(
            envelope,
            &transaction_data,
            &auth,
            min_resource_fee,
            compiled.fee,
        )?;

        // 5. Sign
        let signed =
            sign_transaction_envelope(assembled, signing_key, &compiled.network_passphrase)?;
        let signed_b64 =
            envelope_to_base64(&signed).map_err(|e| ExecutionError::Assembly(e.to_string()))?;

        // 6. Submit
        let send_resp = self
            .rpc
            .send_transaction(&signed_b64)
            .map_err(ExecutionError::Simulation)?;

        match send_resp.status.as_str() {
            "ERROR" => {
                return Ok(ExecutionResult {
                    call_index,
                    contract: contract.into(),
                    method: method.into(),
                    outcome: ExecutionOutcome::Failed {
                        tx_hash: Some(send_resp.hash),
                        error: send_resp
                            .error_result_xdr
                            .unwrap_or_else(|| "submission error".into()),
                    },
                });
            }
            "DUPLICATE" => {
                return Err(ExecutionError::Duplicate {
                    hash: send_resp.hash,
                });
            }
            "PENDING" | "TRY_AGAIN_LATER" => {
                // Proceed to polling
            }
            other => {
                return Err(ExecutionError::SubmissionFailed {
                    status: other.into(),
                    message: "unexpected sendTransaction status".into(),
                });
            }
        }

        // 7. Poll
        let poll_result = self.poll_transaction(&send_resp.hash)?;

        match poll_result.status.as_str() {
            "SUCCESS" => Ok(ExecutionResult {
                call_index,
                contract: contract.into(),
                method: method.into(),
                outcome: ExecutionOutcome::Success {
                    tx_hash: send_resp.hash,
                    ledger: poll_result.ledger.unwrap_or(0),
                    fee_charged: total_fee,
                    return_value,
                },
            }),
            "FAILED" => Ok(ExecutionResult {
                call_index,
                contract: contract.into(),
                method: method.into(),
                outcome: ExecutionOutcome::Failed {
                    tx_hash: Some(send_resp.hash),
                    error: poll_result
                        .result_xdr
                        .unwrap_or_else(|| "transaction failed".into()),
                },
            }),
            _ => Err(ExecutionError::PollingTimeout {
                hash: send_resp.hash,
                elapsed_seconds: self.config.poll_timeout_seconds,
            }),
        }
    }

    /// Poll `getTransaction` with exponential backoff.
    fn poll_transaction(
        &self,
        hash: &str,
    ) -> Result<crate::rpc::GetTransactionResponse, ExecutionError> {
        let start = Instant::now();
        let mut interval = self.config.poll_initial_interval_ms;

        loop {
            let elapsed = start.elapsed().as_secs();
            if elapsed > self.config.poll_timeout_seconds {
                return Err(ExecutionError::PollingTimeout {
                    hash: hash.into(),
                    elapsed_seconds: elapsed,
                });
            }

            let resp = self
                .rpc
                .get_transaction(hash)
                .map_err(ExecutionError::Simulation)?;

            match resp.status.as_str() {
                "NOT_FOUND" => {
                    thread::sleep(Duration::from_millis(interval));
                    interval = (interval * 2).min(self.config.poll_max_interval_ms);
                }
                _ => return Ok(resp), // SUCCESS or FAILED
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_config_defaults() {
        let config = ExecutorConfig::default();
        assert!(config.secret_key.is_empty());
        assert!(!config.dry_run);
        assert_eq!(config.poll_timeout_seconds, 300);
        assert_eq!(config.poll_initial_interval_ms, 1000);
        assert_eq!(config.poll_max_interval_ms, 30000);
    }

    #[test]
    fn poll_backoff_increases() {
        // Test the backoff calculation logic directly
        let initial = 1000_u64;
        let max = 30000_u64;

        let mut interval = initial;
        let intervals: Vec<u64> = (0..6)
            .map(|_| {
                let current = interval;
                interval = (interval * 2).min(max);
                current
            })
            .collect();

        assert_eq!(intervals, vec![1000, 2000, 4000, 8000, 16000, 30000]);
    }
}
