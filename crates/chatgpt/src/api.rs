//! Models list and Responses API (stream until `response.completed`).

use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use serde_json::{Value, json};

use crate::oauth::refresh_if_needed;
use crate::store::Credentials;
use crate::{API_BASE, Error, Result};

pub fn http_get_json(url: &str) -> Result<Value> {
    let resp = ureq::get(url).call().map_err(map_ureq)?;
    read_json(resp)
}

pub fn http_post_form(url: &str, body: &str) -> Result<Value> {
    let resp = ureq::post(url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(body)
        .map_err(map_ureq)?;
    read_json(resp)
}

fn map_ureq(e: ureq::Error) -> Error {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            Error::Http { status: code, body }
        }
        other => Error::Network(other.to_string()),
    }
}

fn read_json(resp: ureq::Response) -> Result<Value> {
    let text = resp.into_string().map_err(|e| Error::Network(e.to_string()))?;
    Ok(serde_json::from_str(&text)?)
}

/// List models available to the signed-in ChatGPT plan (`visibility == "list"`).
pub fn list_models(config_dir: &Path, creds: &mut Credentials) -> Result<Vec<(String, String)>> {
    if !creds.has_plan_usage() {
        return Err(Error::NoPlanUsage);
    }
    refresh_if_needed(config_dir, creds)?;
    let resp = ureq::get(&format!("{API_BASE}/models"))
        .set("Authorization", &format!("Bearer {}", creds.access_token))
        .call()
        .map_err(map_ureq)?;
    let v = read_json(resp)?;
    let mut out = Vec::new();
    if let Some(arr) = v.get("models").and_then(|m| m.as_array()).or_else(|| v.get("data").and_then(|m| m.as_array())) {
        for m in arr {
            let vis = m.get("visibility").and_then(|x| x.as_str()).unwrap_or("list");
            if vis != "list" {
                continue;
            }
            let slug = m.get("slug").or_else(|| m.get("id")).and_then(|x| x.as_str()).unwrap_or("");
            if slug.is_empty() {
                continue;
            }
            let name = m.get("display_name").or_else(|| m.get("id")).and_then(|x| x.as_str()).unwrap_or(slug);
            out.push((slug.to_string(), name.to_string()));
        }
    }
    Ok(out)
}

/// A function/tool call requested by the model.
#[derive(Clone, Debug)]
pub struct FunctionCall {
    pub call_id: String,
    pub name: String,
    pub arguments: String,
}

/// One completed Responses API turn.
#[derive(Clone, Debug, Default)]
pub struct ResponseOutput {
    pub text: String,
    pub function_calls: Vec<FunctionCall>,
    pub response_id: Option<String>,
}

/// Tool definitions exposed to the model (GridCraft agent).
pub fn agent_tools() -> Value {
    json!([
        {
            "type": "function",
            "name": "execute_command",
            "description": "Run any GridCraft command by id with JSON params. Discover ids with list_commands. Examples: cell.set, home.bold, insert.chart, range.setValues, selection.set.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "Command id, e.g. cell.set" },
                    "params": { "type": "object", "description": "Command parameters (omit or {} for defaults)" }
                },
                "required": ["command"],
                "additionalProperties": false
            }
        },
        {
            "type": "function",
            "name": "list_commands",
            "description": "List GridCraft commands (id, label, params). Optional search substring.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": { "type": "string" }
                },
                "additionalProperties": false
            }
        },
        {
            "type": "function",
            "name": "inspect_workbook",
            "description": "Summary of the active workbook: sheets, selection, names, tables, charts.",
            "parameters": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "type": "function",
            "name": "read_range",
            "description": "Read cell values from a range as a 2-D array. Without range, reads the used range.",
            "parameters": {
                "type": "object",
                "properties": {
                    "range": { "type": "string", "description": "A1 range, e.g. A1:D10" },
                    "formulas": { "type": "boolean" },
                    "formatted": { "type": "boolean" }
                },
                "additionalProperties": false
            }
        }
    ])
}

const SYSTEM: &str = "You are GridCraft's spreadsheet agent. Help the user edit and analyze their workbook. \
Use tools to inspect and change cells. Prefer execute_command for edits. Be concise. \
Never invent command ids — call list_commands when unsure.";

/// Run one user message (and optional prior function results) through the Responses API.
/// Collects the SSE stream until `response.completed`.
pub fn complete_turn(config_dir: &Path, creds: &mut Credentials, model: &str, input: &[Value]) -> Result<ResponseOutput> {
    if !creds.has_plan_usage() {
        return Err(Error::NoPlanUsage);
    }
    refresh_if_needed(config_dir, creds)?;

    let mut messages = vec![json!({"role": "system", "content": SYSTEM})];
    messages.extend(input.iter().cloned());

    let body = json!({
        "model": model,
        "input": messages,
        "tools": agent_tools(),
        "store": false,
        "stream": true,
    });

    let resp = ureq::post(&format!("{API_BASE}/responses"))
        .set("Authorization", &format!("Bearer {}", creds.access_token))
        .set("Content-Type", "application/json")
        .send_json(&body)
        .map_err(map_ureq)?;

    parse_sse_response(resp.into_reader())
}

fn parse_sse_response(reader: impl Read) -> Result<ResponseOutput> {
    let mut out = ResponseOutput::default();
    let mut event_name = String::new();
    let mut data_buf = String::new();
    let buffered = BufReader::new(reader);
    for line in buffered.lines() {
        let line = line.map_err(|e| Error::Network(e.to_string()))?;
        if line.is_empty() {
            if !data_buf.is_empty() {
                handle_sse_event(&event_name, &data_buf, &mut out)?;
            }
            event_name.clear();
            data_buf.clear();
            continue;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            event_name = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            if !data_buf.is_empty() {
                data_buf.push('\n');
            }
            data_buf.push_str(rest.trim_start());
        }
    }
    if !data_buf.is_empty() {
        handle_sse_event(&event_name, &data_buf, &mut out)?;
    }
    Ok(out)
}

fn handle_sse_event(event: &str, data: &str, out: &mut ResponseOutput) -> Result<()> {
    let v: Value = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let ty = if event.is_empty() { v.get("type").and_then(|t| t.as_str()).unwrap_or("") } else { event };

    match ty {
        "response.output_text.delta" => {
            if let Some(delta) = v.get("delta").and_then(|d| d.as_str()) {
                out.text.push_str(delta);
            }
        }
        "response.failed" => {
            let code = v.pointer("/response/error/code").and_then(|c| c.as_str()).unwrap_or("unknown_error");
            let msg = v.pointer("/response/error/message").and_then(|c| c.as_str()).unwrap_or(code);
            return Err(Error::msg(format!("response failed: {msg}")));
        }
        "response.completed" => {
            if let Some(id) = v.pointer("/response/id").and_then(|i| i.as_str()) {
                out.response_id = Some(id.to_string());
            }
            if let Some(arr) = v.pointer("/response/output").and_then(|o| o.as_array()) {
                for item in arr {
                    let is_fn = item.get("type").and_then(|t| t.as_str()) == Some("function_call");
                    if out.text.is_empty() || is_fn {
                        collect_output_item(item, out);
                    }
                }
            }
        }
        "response.output_item.done" => {
            if let Some(item) = v.get("item") {
                collect_output_item(item, out);
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_output_item(item: &Value, out: &mut ResponseOutput) {
    match item.get("type").and_then(|t| t.as_str()) {
        Some("message") => {
            if let Some(content) = item.get("content").and_then(|c| c.as_array()) {
                for c in content {
                    if c.get("type").and_then(|t| t.as_str()) == Some("output_text")
                        && let Some(t) = c.get("text").and_then(|t| t.as_str())
                        && out.text.is_empty()
                    {
                        out.text.push_str(t);
                    }
                }
            }
        }
        Some("function_call") => {
            let call_id = item.get("call_id").or_else(|| item.get("id")).and_then(|c| c.as_str()).unwrap_or("").to_string();
            let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let arguments = item.get("arguments").and_then(|a| a.as_str()).unwrap_or("{}").to_string();
            if !name.is_empty() && !out.function_calls.iter().any(|f| f.call_id == call_id && f.name == name) {
                out.function_calls.push(FunctionCall { call_id, name, arguments });
            }
        }
        _ => {}
    }
}
