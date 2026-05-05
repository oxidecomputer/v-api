// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use owo_colors::{OwoColorize, Style};
use serde::Serialize;
use std::io::Write;
use tabwriter::TabWriter;

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
    /// - `Tab` mode serializes to a `serde_json::Value` and pretty-prints it
    ///   with tab-aligned key/value pairs.
    pub fn print_response<T>(&self, value: &T)
    where
        T: Serialize,
    {
        let json_value = serde_json::to_value(value)
            .unwrap_or_else(|e| serde_json::Value::String(format!("<serialization error: {}>", e)));

        match self {
            Printer::Json => {
                println!("{}", serde_json::to_string(&json_value).unwrap_or_default());
            }
            Printer::Tab => {
                let styles = TabStyles::default();
                let mut tw = TabWriter::new(vec![]).ansi(true);
                pretty_print_value(&mut tw, &json_value, 0, &styles);
                tw.flush().unwrap();
                let output = String::from_utf8(tw.into_inner().unwrap()).unwrap();
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
        if let Some(status) = value.status() {
            if status == reqwest::StatusCode::UNAUTHORIZED {
                eprintln!("Authentication required. Please run `sprue auth login` first.");
                return;
            }
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
// Tab-indented pretty-printer for serde_json::Value
// ---------------------------------------------------------------------------

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

fn indent(tw: &mut TabWriter<Vec<u8>>, depth: usize) {
    for _ in 0..depth {
        let _ = write!(tw, "\t");
    }
}

fn pretty_print_value(
    tw: &mut TabWriter<Vec<u8>>,
    value: &serde_json::Value,
    depth: usize,
    styles: &TabStyles,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                pretty_print_field(tw, key, val, depth, styles);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                indent(tw, depth);
                let _ = writeln!(tw, "{}", format!("[{}]", i).style(styles.label),);
                pretty_print_value(tw, val, depth + 1, styles);
            }
        }
        _ => {
            indent(tw, depth);
            let _ = writeln!(tw, "{}", format_scalar(value, styles));
        }
    }
}

fn pretty_print_field(
    tw: &mut TabWriter<Vec<u8>>,
    key: &str,
    value: &serde_json::Value,
    depth: usize,
    styles: &TabStyles,
) {
    match value {
        serde_json::Value::Object(_) => {
            indent(tw, depth);
            let _ = writeln!(tw, "{}:", key.style(styles.label));
            pretty_print_value(tw, value, depth + 1, styles);
        }
        serde_json::Value::Array(arr) if arr.is_empty() => {
            indent(tw, depth);
            let _ = writeln!(
                tw,
                "{}:\t{}",
                key.style(styles.label),
                "[]".style(styles.null),
            );
        }
        serde_json::Value::Array(arr) if arr.iter().all(is_scalar) => {
            // Print simple arrays inline, one value per line with the key on
            // the first line only (mimics the existing TabDisplay list style).
            for (i, val) in arr.iter().enumerate() {
                indent(tw, depth);
                if i == 0 {
                    let _ = writeln!(
                        tw,
                        "{}:\t{}",
                        key.style(styles.label),
                        format_scalar(val, styles),
                    );
                } else {
                    let _ = writeln!(tw, "\t{}", format_scalar(val, styles));
                }
            }
        }
        serde_json::Value::Array(arr) => {
            indent(tw, depth);
            let _ = writeln!(tw, "{}:", key.style(styles.label));
            for (i, val) in arr.iter().enumerate() {
                indent(tw, depth + 1);
                let _ = writeln!(tw, "{}", format!("[{}]", i).style(styles.label),);
                pretty_print_value(tw, val, depth + 2, styles);
            }
        }
        _ => {
            indent(tw, depth);
            let _ = writeln!(
                tw,
                "{}:\t{}",
                key.style(styles.label),
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
        // Fallback for non-scalars that end up here
        other => format!("{}", other.style(styles.value)),
    }
}
