/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Simple helpers to emit standardized log lines without imposing a specific subscriber.

Output shape: "<message>" cid=<correlation_id> key1=<value1> key2=<value2> ...
- Strings are quoted via Debug formatting; numbers/bools/etc are unquoted.
*/

/// Render a log line with the agreed message and key=value structure.
pub fn line<S, K, V, I>(message: S, cid: Option<&str>, fields: I) -> String
where
    S: AsRef<str>,
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Into<String>,
{
    let mut out = String::new();
    // Message first, always quoted
    out.push('"');
    out.push_str(message.as_ref());
    out.push('"');

    // Optional correlation id next
    if let Some(cid) = cid {
        out.push(' ');
        out.push_str("cid=");
        out.push('"');
        out.push_str(cid);
        out.push('"');
    }

    // Then remaining fields as key=value
    for (k, v) in fields.into_iter() {
        out.push(' ');
        out.push_str(k.as_ref());
        out.push('=');
        let rendered: String = v.into();
        out.push_str(&rendered);
    }

    out
}

/// Emit an info-level standardized log line.
pub fn info<S, K, V, I>(message: S, cid: Option<&str>, fields: I)
where
    S: AsRef<str>,
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Into<String>,
{
    log::info!("{}", line(message, cid, fields));
}

/// Emit a debug-level standardized log line.
pub fn debug<S, K, V, I>(message: S, cid: Option<&str>, fields: I)
where
    S: AsRef<str>,
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Into<String>,
{
    log::debug!("{}", line(message, cid, fields));
}

/// Emit a warn-level standardized log line.
pub fn warn<S, K, V, I>(message: S, cid: Option<&str>, fields: I)
where
    S: AsRef<str>,
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Into<String>,
{
    log::warn!("{}", line(message, cid, fields));
}

/// Emit an error-level standardized log line.
pub fn error<S, K, V, I>(message: S, cid: Option<&str>, fields: I)
where
    S: AsRef<str>,
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Into<String>,
{
    log::error!("{}", line(message, cid, fields));
}

/// Structured value rendering to ensure strings are quoted and primitive values are not.
pub trait StructuredValue {
    /// Render the value as a string suitable for key=value logging.
    fn render(&self) -> String;
}

impl StructuredValue for String {
    fn render(&self) -> String {
        format!("\"{}\"", self)
    }
}
impl StructuredValue for &str {
    fn render(&self) -> String {
        format!("\"{}\"", self)
    }
}

macro_rules! impl_structured_for_display {
    ($($t:ty),* $(,)?) => {
        $( impl StructuredValue for $t { fn render(&self) -> String { format!("{}", self) } } )*
    };
}

impl_structured_for_display!(
    bool, i8, i16, i32, i64, isize, u8, u16, u32, u64, usize, f32, f64,
);

// Note: we avoid a blanket &T impl to prevent overlap with &str

/// Convenience to produce a key/value pair where the value is rendered with `StructuredValue`.
pub fn kv_render<K: AsRef<str>, V: StructuredValue>(k: K, v: V) -> (String, String) {
    (k.as_ref().to_string(), v.render())
}

// Macro to emit info-level structured logs in a concise form.
// Usage:
//   structured_log::info!("Message");
//   structured_log::info!("Message", key1 = val1, key2 = val2);
//   structured_log::info!("Message", cid_expr, key1 = val1, key2 = val2);
#[macro_export]
/// Internal macro used to implement structured_log::info!. Do not use directly.
macro_rules! __structured_log_info_internal_do_not_use_directly {
    ($message:expr $(, $key:ident = $val:expr )* $(,)?) => {{
        let mut __fields: ::std::vec::Vec<(::std::string::String, ::std::string::String)> = ::std::vec![];
        $( __fields.push( $crate::structured_log::kv_render(::core::stringify!($key), $val) ); )*
        { ::log::info!("{}", $crate::structured_log::line($message, None, __fields)); }
    }};
    ($message:expr, $cid:expr $(, $key:ident = $val:expr )* $(,)?) => {{
        let __cid_string: ::std::string::String = $cid.to_string();
        let mut __fields: ::std::vec::Vec<(::std::string::String, ::std::string::String)> = ::std::vec![];
        $( __fields.push( $crate::structured_log::kv_render(::core::stringify!($key), $val) ); )*
        { ::log::info!("{}", $crate::structured_log::line($message, Some(__cid_string.as_str()), __fields)); }
    }};
}

// Provide an exported root macro name `structured_log_info!` used for re-exporting into this module.
#[macro_export]
/// Emit an info-level structured log line. Usage:
/// - structured_log::info!("Message");
/// - structured_log::info!("Message", key1 = val1, key2 = val2);
/// - structured_log::info!("Message", cid_expr, key1 = val1, key2 = val2);
macro_rules! structured_log_info {
    ($($t:tt)*) => { $crate::__structured_log_info_internal_do_not_use_directly!($($t)*) };
}

// Allow calling as crate::structured_log::info!(..)
pub use crate::structured_log_info as info;
