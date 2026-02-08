//! High-level simulation orchestrator.

use callsoro_compile::{CompiledTransaction, JsonIR};
use serde_json::Value;

use crate::error::SimulationError;
use crate::rpc::RpcClient;
use crate::transaction::{build_transaction_envelope, envelope_to_base64};
use crate::types::{CostBreakdown, SimulationOutcome, SimulationResult};

/// Orchestrates transaction simulation against a Soroban RPC endpoint.
pub struct Simulator {
    rpc: RpcClient,
}

impl Simulator {
    /// Create a new simulator pointing at the given RPC URL.
    pub fn new(rpc_url: &str) -> Self {
        Simulator {
            rpc: RpcClient::new(rpc_url),
        }
    }

    /// Simulate all calls in the given compiled transactions.
    ///
    /// Each call is simulated independently. The source account sequence is
    /// fetched once and reused for all calls.
    pub fn simulate(
        &self,
        transactions: &[CompiledTransaction],
        ir: &JsonIR,
    ) -> Result<Vec<SimulationResult>, SimulationError> {
        if transactions.is_empty() {
            return Ok(vec![]);
        }

        // Fetch account sequence once (same source for all calls)
        let source_str = &ir.signing.source;
        let account_info = self.rpc.get_account(source_str)?;
        let sequence = account_info.sequence;

        let mut results = Vec::with_capacity(transactions.len());

        for (i, compiled) in transactions.iter().enumerate() {
            let call = &ir.calls[i];

            // Build unsigned transaction envelope
            let envelope = build_transaction_envelope(compiled, sequence + 1)?;
            let envelope_b64 = envelope_to_base64(&envelope)?;

            // Send to simulateTransaction
            let sim_response = self.rpc.simulate_transaction(&envelope_b64)?;

            // Parse the simulation response
            let outcome = parse_simulation_outcome(&sim_response)?;

            results.push(SimulationResult {
                call_index: i,
                contract: call.contract.clone(),
                method: call.method.clone(),
                outcome,
            });
        }

        Ok(results)
    }
}

/// Resolve the RPC URL from explicit flag, env var, or network default.
pub fn resolve_rpc_url(explicit: Option<&str>, network: &str) -> Result<String, SimulationError> {
    // 1. Explicit --rpc-url flag
    if let Some(url) = explicit {
        return Ok(url.to_string());
    }

    // 2. CALLSORO_RPC_URL env var
    if let Ok(url) = std::env::var("CALLSORO_RPC_URL") {
        if !url.is_empty() {
            return Ok(url);
        }
    }

    // 3. Network default
    match network {
        "testnet" => Ok("https://soroban-testnet.stellar.org".to_string()),
        "mainnet" => Ok("https://soroban-rpc.mainnet.stellar.gateway.fm".to_string()),
        "futurenet" => Ok("https://rpc-futurenet.stellar.org".to_string()),
        other => Err(SimulationError::InvalidResponse(format!(
            "no default RPC URL for network '{}'; use --rpc-url or set CALLSORO_RPC_URL",
            other
        ))),
    }
}

/// Parse a simulateTransaction result JSON into a `SimulationOutcome`.
pub(crate) fn parse_simulation_outcome(
    result: &Value,
) -> Result<SimulationOutcome, SimulationError> {
    // Check for simulation-level error
    if let Some(error) = result.get("error") {
        let error_str = error.as_str().unwrap_or("unknown simulation error");
        return Ok(SimulationOutcome::Failed {
            error: error_str.to_string(),
        });
    }

    // Check for restore preamble
    if let Some(restore) = result.get("restorePreamble") {
        let preamble = serde_json::to_string(restore).unwrap_or_default();
        return Err(SimulationError::RestoreRequired {
            restore_preamble: preamble,
        });
    }

    // Parse success fields
    let transaction_data = result
        .get("transactionData")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let min_resource_fee = result
        .get("minResourceFee")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let latest_ledger = result
        .get("latestLedger")
        .and_then(|v| v.as_str().or_else(|| v.as_u64().map(|_| "")))
        .and_then(|s| {
            if s.is_empty() {
                result.get("latestLedger").and_then(|v| v.as_u64())
            } else {
                s.parse::<u64>().ok()
            }
        })
        .unwrap_or(0);

    let events: Vec<String> = result
        .get("events")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Parse results array — first entry has auth and return value
    let (return_value, auth) =
        if let Some(results_arr) = result.get("results").and_then(|v| v.as_array()) {
            if let Some(first) = results_arr.first() {
                let ret = first.get("xdr").and_then(|v| v.as_str()).map(String::from);
                let auth_entries: Vec<String> = first
                    .get("auth")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|e| e.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                (ret, auth_entries)
            } else {
                (None, vec![])
            }
        } else {
            (None, vec![])
        };

    let cost = if let Some(cost_obj) = result.get("cost") {
        CostBreakdown {
            cpu_instructions: cost_obj
                .get("cpuInsns")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            memory_bytes: cost_obj
                .get("memBytes")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        }
    } else {
        CostBreakdown {
            cpu_instructions: 0,
            memory_bytes: 0,
        }
    };

    Ok(SimulationOutcome::Success {
        return_value,
        cost,
        auth,
        min_resource_fee,
        transaction_data,
        events,
        latest_ledger,
    })
}

/// Format a simulation result as human-readable text.
pub fn format_human_result(result: &SimulationResult, total_calls: usize, base_fee: u32) -> String {
    let contract_short = if result.contract.len() > 10 {
        format!(
            "{}...{}",
            &result.contract[..4],
            &result.contract[result.contract.len() - 4..]
        )
    } else {
        result.contract.clone()
    };

    let mut out = format!(
        "Simulating call {}/{}: {}.{}()\n",
        result.call_index + 1,
        total_calls,
        contract_short,
        result.method
    );

    match &result.outcome {
        SimulationOutcome::Success {
            return_value,
            cost,
            auth,
            min_resource_fee,
            events,
            ..
        } => {
            out.push_str("  Status:     success\n");
            if let Some(ret) = return_value {
                out.push_str(&format!("  Return:     {}\n", ret));
            } else {
                out.push_str("  Return:     void\n");
            }
            out.push_str(&format!(
                "  CPU:        {} instructions\n",
                format_number(cost.cpu_instructions)
            ));
            out.push_str(&format!(
                "  Memory:     {} bytes\n",
                format_number(cost.memory_bytes)
            ));
            let total_fee = *min_resource_fee + base_fee as u64;
            out.push_str(&format!(
                "  Fee:        {} stroops (resource) + {} (base) = {} total\n",
                format_number(*min_resource_fee),
                base_fee,
                format_number(total_fee)
            ));
            out.push_str(&format!("  Auth:       {} entry(ies)\n", auth.len()));
            out.push_str(&format!("  Events:     {} event(s)\n", events.len()));
        }
        SimulationOutcome::Failed { error } => {
            out.push_str(&format!("  Status:     FAILED\n  Error:      {}\n", error));
        }
    }

    out
}

/// Format a number with thousands separators.
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CostBreakdown;
    use serde_json::json;

    #[test]
    fn resolve_rpc_url_explicit() {
        let url = resolve_rpc_url(Some("http://localhost:8000"), "testnet").unwrap();
        assert_eq!(url, "http://localhost:8000");
    }

    #[test]
    fn resolve_rpc_url_network_default_testnet() {
        // Clear env to ensure we test the default path
        std::env::remove_var("CALLSORO_RPC_URL");
        let url = resolve_rpc_url(None, "testnet").unwrap();
        assert_eq!(url, "https://soroban-testnet.stellar.org");
    }

    #[test]
    fn resolve_rpc_url_network_default_mainnet() {
        std::env::remove_var("CALLSORO_RPC_URL");
        let url = resolve_rpc_url(None, "mainnet").unwrap();
        assert_eq!(url, "https://soroban-rpc.mainnet.stellar.gateway.fm");
    }

    #[test]
    fn resolve_rpc_url_unknown_network() {
        std::env::remove_var("CALLSORO_RPC_URL");
        let err = resolve_rpc_url(None, "localnet").unwrap_err();
        match err {
            SimulationError::InvalidResponse(msg) => {
                assert!(msg.contains("localnet"), "msg: {}", msg);
            }
            other => panic!("expected InvalidResponse, got {:?}", other),
        }
    }

    #[test]
    fn parse_outcome_success() {
        let result = json!({
            "transactionData": "AAAA",
            "minResourceFee": "12345",
            "events": ["event1"],
            "results": [{
                "auth": ["auth1"],
                "xdr": "AAAB"
            }],
            "cost": {
                "cpuInsns": "100000",
                "memBytes": "5000"
            },
            "latestLedger": "999"
        });
        let outcome = parse_simulation_outcome(&result).unwrap();
        match outcome {
            SimulationOutcome::Success {
                return_value,
                cost,
                auth,
                min_resource_fee,
                events,
                latest_ledger,
                ..
            } => {
                assert_eq!(return_value, Some("AAAB".to_string()));
                assert_eq!(cost.cpu_instructions, 100000);
                assert_eq!(cost.memory_bytes, 5000);
                assert_eq!(auth, vec!["auth1"]);
                assert_eq!(min_resource_fee, 12345);
                assert_eq!(events, vec!["event1"]);
                assert_eq!(latest_ledger, 999);
            }
            other => panic!("expected Success, got {:?}", other),
        }
    }

    #[test]
    fn parse_outcome_failed() {
        let result = json!({
            "error": "contract function failed"
        });
        let outcome = parse_simulation_outcome(&result).unwrap();
        match outcome {
            SimulationOutcome::Failed { error } => {
                assert_eq!(error, "contract function failed");
            }
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn parse_outcome_restore_required() {
        let result = json!({
            "restorePreamble": {
                "transactionData": "BBBB",
                "minResourceFee": "500"
            }
        });
        let err = parse_simulation_outcome(&result).unwrap_err();
        match err {
            SimulationError::RestoreRequired { restore_preamble } => {
                assert!(
                    restore_preamble.contains("BBBB"),
                    "preamble: {}",
                    restore_preamble
                );
            }
            other => panic!("expected RestoreRequired, got {:?}", other),
        }
    }

    #[test]
    fn format_human_success() {
        let result = SimulationResult {
            call_index: 0,
            contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".to_string(),
            method: "transfer".to_string(),
            outcome: SimulationOutcome::Success {
                return_value: None,
                cost: CostBreakdown {
                    cpu_instructions: 45231,
                    memory_bytes: 312,
                },
                auth: vec![],
                min_resource_fee: 154231,
                transaction_data: "AAAA".to_string(),
                events: vec!["evt1".to_string()],
                latest_ledger: 100,
            },
        };
        let text = format_human_result(&result, 1, 100);
        assert!(text.contains("success"), "text: {}", text);
        assert!(text.contains("45,231"), "text: {}", text);
        assert!(text.contains("154,231"), "text: {}", text);
        assert!(text.contains("1 event(s)"), "text: {}", text);
        assert!(text.contains("void"), "text: {}", text);
    }

    #[test]
    fn format_human_failed() {
        let result = SimulationResult {
            call_index: 0,
            contract: "CABC".to_string(),
            method: "foo".to_string(),
            outcome: SimulationOutcome::Failed {
                error: "something broke".to_string(),
            },
        };
        let text = format_human_result(&result, 1, 100);
        assert!(text.contains("FAILED"), "text: {}", text);
        assert!(text.contains("something broke"), "text: {}", text);
    }

    #[test]
    fn format_number_with_separators() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(123), "123");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(1234567), "1,234,567");
    }
}
