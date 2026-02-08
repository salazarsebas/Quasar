//! Error types for full transaction execution.

use std::fmt;

use crate::error::SimulationError;

/// Errors that can occur during transaction execution (sign + submit + poll).
#[derive(Debug, Clone)]
pub enum ExecutionError {
    /// Wraps simulation-phase errors
    Simulation(SimulationError),
    /// Secret key decoding or format error
    InvalidSecretKey(String),
    /// Transaction signing failure
    SigningFailed(String),
    /// sendTransaction RPC returned an error status
    SubmissionFailed { status: String, message: String },
    /// Transaction was confirmed but failed on-chain
    TransactionFailed {
        hash: String,
        result_xdr: String,
        message: String,
    },
    /// Polling timed out waiting for transaction confirmation
    PollingTimeout { hash: String, elapsed_seconds: u64 },
    /// Transaction was already submitted (duplicate)
    Duplicate { hash: String },
    /// XDR assembly/serialization error
    Assembly(String),
    /// User cancelled (e.g. declined mainnet prompt)
    Cancelled,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionError::Simulation(e) => write!(f, "{}", e),
            ExecutionError::InvalidSecretKey(msg) => {
                write!(f, "invalid secret key: {}", msg)
            }
            ExecutionError::SigningFailed(msg) => {
                write!(f, "signing failed: {}", msg)
            }
            ExecutionError::SubmissionFailed { status, message } => {
                write!(f, "submission failed (status {}): {}", status, message)
            }
            ExecutionError::TransactionFailed {
                hash,
                message,
                result_xdr: _,
            } => {
                write!(f, "transaction {} failed: {}", hash, message)
            }
            ExecutionError::PollingTimeout {
                hash,
                elapsed_seconds,
            } => {
                write!(
                    f,
                    "timed out after {}s waiting for transaction {}",
                    elapsed_seconds, hash
                )
            }
            ExecutionError::Duplicate { hash } => {
                write!(f, "transaction {} was already submitted (duplicate)", hash)
            }
            ExecutionError::Assembly(msg) => write!(f, "assembly error: {}", msg),
            ExecutionError::Cancelled => write!(f, "execution cancelled by user"),
        }
    }
}

impl std::error::Error for ExecutionError {}

impl From<SimulationError> for ExecutionError {
    fn from(e: SimulationError) -> Self {
        ExecutionError::Simulation(e)
    }
}
