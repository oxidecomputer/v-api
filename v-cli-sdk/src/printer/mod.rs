// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use owo_colors::{OwoColorize, Style};
use serde::Serialize;
use std::fmt::Write;

#[derive(Debug, Clone)]
pub enum Printer {
    Json,
    Tab,
}

pub trait CliOutput {
    fn output_error<T>(&self, value: &progenitor_client::Error<T>)
    where
        T: schemars::JsonSchema + serde::Serialize + std::fmt::Debug;
}

impl Printer {
    /// Print any serializable response object in the configured format.
    ///
    /// - `Json` mode emits compact, single-line JSON.
    /// - `Tab` mode pretty-prints with indentation and aligned key/value
    ///   pairs within each object.
    pub fn print_response<T>(&self, value: &T)
    where
        T: Serialize,
    {
        let json_value = serde_json::to_value(value)
            .unwrap_or_else(|e| serde_json::Value::String(format!("<serialization error: {}>", e)));

        if json_value.is_null() {
            return;
        }

        match self {
            Printer::Json => {
                println!("{}", serde_json::to_string(&json_value).unwrap_or_default());
            }
            Printer::Tab => {
                let styles = TabStyles::default();
                let mut output = String::new();
                pretty_print_value(&mut output, &json_value, 0, &styles);
                print!("{}", output);
            }
        }
    }

    /// Print an error from a progenitor client response.
    ///
    /// A 401 Unauthorized is treated specially: instead of dumping the raw
    /// server error we print a short, actionable message telling the user to
    /// authenticate first.
    pub fn print_error_response<T>(&self, value: &progenitor_client::Error<T>)
    where
        T: schemars::JsonSchema + serde::Serialize + std::fmt::Debug,
    {
        // Check for 401 Unauthorized up-front, regardless of output format.
        if let Some(status) = value.status()
            && status == reqwest::StatusCode::UNAUTHORIZED
        {
            eprintln!("Authentication required. Please run `auth login` first.");
            return;
        }

        match self {
            Printer::Json => {
                // For JSON mode, try to extract a serializable body from the
                // error and fall back to the Debug representation.
                let msg = match value {
                    progenitor_client::Error::ErrorResponse(rv) => {
                        serde_json::to_string(rv.as_ref()).ok()
                    }
                    _ => None,
                };
                eprintln!("{}", msg.unwrap_or_else(|| format!("{:?}", value)));
            }
            Printer::Tab => {
                eprintln!("{}", value);
            }
        }
    }
}

impl CliOutput for Printer {
    fn output_error<T>(&self, value: &progenitor_client::Error<T>)
    where
        T: schemars::JsonSchema + serde::Serialize + std::fmt::Debug,
    {
        self.print_error_response(value);
    }
}

// ---------------------------------------------------------------------------
// Indented pretty-printer for serde_json::Value
// ---------------------------------------------------------------------------

const INDENT_STR: &str = "  ";

#[derive(Debug, Clone)]
struct TabStyles {
    label: Style,
    value: Style,
    null: Style,
}

impl Default for TabStyles {
    fn default() -> Self {
        TabStyles {
            label: Style::new().bold(),
            value: Style::new(),
            null: Style::new().dimmed(),
        }
    }
}

fn write_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str(INDENT_STR);
    }
}

fn pretty_print_value(
    out: &mut String,
    value: &serde_json::Value,
    depth: usize,
    styles: &TabStyles,
) {
    match value {
        serde_json::Value::Object(map) => {
            let max_key_len = map.keys().map(|k| k.len()).max().unwrap_or(0);
            for (key, val) in map {
                pretty_print_field(out, key, val, depth, max_key_len, styles);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                write_indent(out, depth);
                let _ = writeln!(out, "{}", format!("[{}]", i).style(styles.label));
                pretty_print_value(out, val, depth + 1, styles);
            }
        }
        _ => {
            write_indent(out, depth);
            let _ = writeln!(out, "{}", format_scalar(value, styles));
        }
    }
}

fn pretty_print_field(
    out: &mut String,
    key: &str,
    value: &serde_json::Value,
    depth: usize,
    max_key_len: usize,
    styles: &TabStyles,
) {
    // Number of spaces after the colon so all sibling values align.
    let padding = max_key_len - key.len() + 1;

    match value {
        serde_json::Value::Object(_) => {
            write_indent(out, depth);
            let _ = writeln!(out, "{}:", key.style(styles.label));
            pretty_print_value(out, value, depth + 1, styles);
        }
        serde_json::Value::Array(arr) if arr.is_empty() => {
            write_indent(out, depth);
            let _ = writeln!(
                out,
                "{}:{:padding$}{}",
                key.style(styles.label),
                "",
                "[]".style(styles.null),
            );
        }
        serde_json::Value::Array(arr) if arr.iter().all(is_scalar) => {
            // Print simple arrays inline: key on the first line, continuation
            // lines aligned under the first value.
            for (i, val) in arr.iter().enumerate() {
                write_indent(out, depth);
                if i == 0 {
                    let _ = writeln!(
                        out,
                        "{}:{:padding$}{}",
                        key.style(styles.label),
                        "",
                        format_scalar(val, styles),
                    );
                } else {
                    // Align under the first value: key length + colon + padding.
                    let lead = max_key_len + 2;
                    let _ = writeln!(out, "{:lead$}{}", "", format_scalar(val, styles));
                }
            }
        }
        serde_json::Value::Array(arr) => {
            write_indent(out, depth);
            let _ = writeln!(out, "{}:", key.style(styles.label));
            for (i, val) in arr.iter().enumerate() {
                write_indent(out, depth + 1);
                let _ = writeln!(out, "{}", format!("[{}]", i).style(styles.label));
                pretty_print_value(out, val, depth + 2, styles);
            }
        }
        _ => {
            write_indent(out, depth);
            let _ = writeln!(
                out,
                "{}:{:padding$}{}",
                key.style(styles.label),
                "",
                format_scalar(value, styles),
            );
        }
    }
}

fn is_scalar(value: &serde_json::Value) -> bool {
    matches!(
        value,
        serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_)
    )
}

fn format_scalar(value: &serde_json::Value, styles: &TabStyles) -> String {
    match value {
        serde_json::Value::Null => format!("{}", "null".style(styles.null)),
        serde_json::Value::Bool(b) => format!("{}", b.style(styles.value)),
        serde_json::Value::Number(n) => format!("{}", n.style(styles.value)),
        serde_json::Value::String(s) => format!("{}", s.style(styles.value)),
        other => format!("{}", other.style(styles.value)),
    }
}
