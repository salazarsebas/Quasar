//! Data types for simulation results.

use serde::Serialize;

/// Result of simulating a single contract invocation.
#[derive(Debug, Clone, Serialize)]
pub struct SimulationResult {
    /// 0-based index of the call within the script
    pub call_index: usize,
    /// Contract address (C...)
    pub contract: String,
    /// Function name
    pub method: String,
    /// Simulation outcome
    pub outcome: SimulationOutcome,
}

/// Whether the simulation succeeded or failed.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum SimulationOutcome {
    /// Simulation succeeded
    #[serde(rename = "success")]
    Success {
        /// Return value as base64 XDR (ScVal), if any
        return_value: Option<String>,
        /// Resource cost breakdown
        cost: CostBreakdown,
        /// Authorization entries as base64 XDR
        auth: Vec<String>,
        /// Minimum resource fee in stroops
        min_resource_fee: u64,
        /// Soroban transaction data as base64 XDR
        transaction_data: String,
        /// Diagnostic/contract events
        events: Vec<String>,
        /// Latest ledger number at simulation time
        latest_ledger: u64,
    },
    /// Simulation failed
    #[serde(rename = "failed")]
    Failed {
        /// Error message from the RPC
        error: String,
    },
}

/// CPU and memory cost breakdown from simulation.
#[derive(Debug, Clone, Serialize)]
pub struct CostBreakdown {
    /// CPU instructions consumed
    pub cpu_instructions: u64,
    /// Memory bytes consumed
    pub memory_bytes: u64,
}

/// Account information from the network.
#[derive(Debug, Clone, Serialize)]
pub struct AccountInfo {
    /// Account ID (G... address)
    pub account_id: String,
    /// Current sequence number
    pub sequence: i64,
}
