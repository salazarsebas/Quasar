//! Simulation error types.

use std::fmt;

/// Errors that can occur during transaction simulation.
#[derive(Debug, Clone)]
pub enum SimulationError {
    /// Failed to connect to RPC endpoint
    Network(String),
    /// RPC returned a JSON-RPC error response
    RpcError { code: i64, message: String },
    /// simulateTransaction returned an error field
    SimulationFailed(String),
    /// State restoration needed before this call can succeed
    RestoreRequired { restore_preamble: String },
    /// Invalid or unexpected response format from RPC
    InvalidResponse(String),
    /// XDR serialization/deserialization error
    Xdr(String),
    /// Source account not found on the network
    AccountNotFound(String),
}

impl fmt::Display for SimulationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimulationError::Network(msg) => write!(f, "network error: {}", msg),
            SimulationError::RpcError { code, message } => {
                write!(f, "RPC error (code {}): {}", code, message)
            }
            SimulationError::SimulationFailed(msg) => {
                write!(f, "simulation failed: {}", msg)
            }
            SimulationError::RestoreRequired { restore_preamble } => {
                write!(
                    f,
                    "state restoration required before this call can succeed (restorePreamble: {})",
                    restore_preamble
                )
            }
            SimulationError::InvalidResponse(msg) => {
                write!(f, "invalid RPC response: {}", msg)
            }
            SimulationError::Xdr(msg) => write!(f, "XDR error: {}", msg),
            SimulationError::AccountNotFound(addr) => {
                write!(f, "account not found: {}", addr)
            }
        }
    }
}

impl std::error::Error for SimulationError {}

impl From<reqwest::Error> for SimulationError {
    fn from(e: reqwest::Error) -> Self {
        SimulationError::Network(e.to_string())
    }
}
