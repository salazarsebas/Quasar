//! JSON-RPC client for Soroban RPC endpoints.

use serde_json::{json, Value};

use crate::error::SimulationError;
use crate::types::AccountInfo;

/// JSON-RPC client for communicating with a Soroban RPC server.
pub struct RpcClient {
    client: reqwest::blocking::Client,
    url: String,
}

impl RpcClient {
    /// Create a new RPC client pointing at the given URL.
    pub fn new(url: &str) -> Self {
        RpcClient {
            client: reqwest::blocking::Client::new(),
            url: url.to_string(),
        }
    }

    /// Fetch account information (id + sequence number) from the network.
    pub fn get_account(&self, account_id: &str) -> Result<AccountInfo, SimulationError> {
        let body = build_jsonrpc_request("getAccount", json!({ "address": account_id }));
        let response = self.send_request(&body)?;
        parse_account_response(&response, account_id)
    }

    /// Send a transaction envelope to `simulateTransaction` and return the raw JSON result.
    pub fn simulate_transaction(&self, tx_xdr_base64: &str) -> Result<Value, SimulationError> {
        let body = build_jsonrpc_request(
            "simulateTransaction",
            json!({ "transaction": tx_xdr_base64 }),
        );
        let response = self.send_request(&body)?;
        parse_simulate_response(&response)
    }

    /// Fetch ledger entries by their base64-encoded XDR keys.
    pub fn get_ledger_entries(&self, keys: &[String]) -> Result<Value, SimulationError> {
        let body = build_jsonrpc_request("getLedgerEntries", json!({ "keys": keys }));
        let response = self.send_request(&body)?;
        parse_ledger_entries_response(&response)
    }

    /// Send a JSON-RPC request and return the parsed JSON body.
    fn send_request(&self, body: &Value) -> Result<Value, SimulationError> {
        let resp = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .json(body)
            .send()?;

        let status = resp.status();
        let text = resp
            .text()
            .map_err(|e| SimulationError::Network(format!("reading response body: {}", e)))?;

        if !status.is_success() {
            return Err(SimulationError::Network(format!(
                "HTTP {}: {}",
                status, text
            )));
        }

        serde_json::from_str(&text)
            .map_err(|e| SimulationError::InvalidResponse(format!("invalid JSON: {}", e)))
    }
}

/// Build a JSON-RPC 2.0 request body.
pub(crate) fn build_jsonrpc_request(method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    })
}

/// Parse a `getAccount` response into `AccountInfo`.
pub(crate) fn parse_account_response(
    response: &Value,
    account_id: &str,
) -> Result<AccountInfo, SimulationError> {
    // Check for JSON-RPC error
    if let Some(error) = response.get("error") {
        let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let message = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();

        // Account not found typically returns a specific error
        if message.contains("not found") || code == -32600 {
            return Err(SimulationError::AccountNotFound(account_id.to_string()));
        }
        return Err(SimulationError::RpcError { code, message });
    }

    let result = response
        .get("result")
        .ok_or_else(|| SimulationError::InvalidResponse("missing 'result' field".to_string()))?;

    let id = result
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(account_id)
        .to_string();

    let sequence = result
        .get("sequence")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| {
            SimulationError::InvalidResponse("missing or invalid 'sequence' field".to_string())
        })?;

    Ok(AccountInfo {
        account_id: id,
        sequence,
    })
}

/// Parse a `simulateTransaction` response, extracting the result portion.
pub(crate) fn parse_simulate_response(response: &Value) -> Result<Value, SimulationError> {
    // Check for JSON-RPC level error
    if let Some(error) = response.get("error") {
        let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let message = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(SimulationError::RpcError { code, message });
    }

    let result = response
        .get("result")
        .ok_or_else(|| SimulationError::InvalidResponse("missing 'result' field".to_string()))?;

    Ok(result.clone())
}

/// Parse a `getLedgerEntries` response, extracting the result portion.
pub(crate) fn parse_ledger_entries_response(response: &Value) -> Result<Value, SimulationError> {
    if let Some(error) = response.get("error") {
        let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let message = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(SimulationError::RpcError { code, message });
    }

    let result = response
        .get("result")
        .ok_or_else(|| SimulationError::InvalidResponse("missing 'result' field".to_string()))?;

    Ok(result.clone())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rpc_request_format() {
        let body = build_jsonrpc_request("getAccount", json!({ "address": "GABC123" }));
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 1);
        assert_eq!(body["method"], "getAccount");
        assert_eq!(body["params"]["address"], "GABC123");
    }

    #[test]
    fn parse_account_success() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "id": "GABC123",
                "sequence": "12345"
            }
        });
        let info = parse_account_response(&response, "GABC123").unwrap();
        assert_eq!(info.account_id, "GABC123");
        assert_eq!(info.sequence, 12345);
    }

    #[test]
    fn parse_account_not_found() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "account not found"
            }
        });
        let err = parse_account_response(&response, "GXYZ").unwrap_err();
        match err {
            SimulationError::AccountNotFound(addr) => assert_eq!(addr, "GXYZ"),
            other => panic!("expected AccountNotFound, got {:?}", other),
        }
    }

    #[test]
    fn parse_simulate_success() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "transactionData": "AAAA",
                "minResourceFee": "12345",
                "events": [],
                "results": [{
                    "auth": [],
                    "xdr": "AAAB"
                }],
                "cost": {
                    "cpuInsns": "100000",
                    "memBytes": "5000"
                },
                "latestLedger": "999"
            }
        });
        let result = parse_simulate_response(&response).unwrap();
        assert_eq!(result["transactionData"], "AAAA");
        assert_eq!(result["minResourceFee"], "12345");
        assert_eq!(result["cost"]["cpuInsns"], "100000");
    }

    #[test]
    fn ledger_entries_request_format() {
        let body = build_jsonrpc_request("getLedgerEntries", json!({ "keys": ["AAAA", "BBBB"] }));
        assert_eq!(body["method"], "getLedgerEntries");
        assert_eq!(body["params"]["keys"][0], "AAAA");
        assert_eq!(body["params"]["keys"][1], "BBBB");
    }

    #[test]
    fn parse_ledger_entries_success() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "entries": [{
                    "key": "AAAA",
                    "xdr": "BBBB",
                    "lastModifiedLedgerSeq": 100
                }],
                "latestLedger": 200
            }
        });
        let result = parse_ledger_entries_response(&response).unwrap();
        assert_eq!(result["entries"][0]["xdr"], "BBBB");
        assert_eq!(result["latestLedger"], 200);
    }

    #[test]
    fn parse_ledger_entries_error() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "invalid params"
            }
        });
        let err = parse_ledger_entries_response(&response).unwrap_err();
        match err {
            SimulationError::RpcError { code, message } => {
                assert_eq!(code, -32600);
                assert_eq!(message, "invalid params");
            }
            other => panic!("expected RpcError, got {:?}", other),
        }
    }

    #[test]
    fn parse_simulate_rpc_error() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32000,
                "message": "something went wrong"
            }
        });
        let err = parse_simulate_response(&response).unwrap_err();
        match err {
            SimulationError::RpcError { code, message } => {
                assert_eq!(code, -32000);
                assert_eq!(message, "something went wrong");
            }
            other => panic!("expected RpcError, got {:?}", other),
        }
    }
}
