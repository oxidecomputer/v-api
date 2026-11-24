// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use email_address::{EmailAddress, Options};

/// The delivery domain of `value` if it is a single addr-spec. Display names and domain literals
/// are rejected, as are characters that are invisible or break lines.
pub fn email_domain(value: &str) -> Option<String> {
    if value.chars().any(is_disallowed_char) {
        return None;
    }

    let options = Options::default()
        .without_domain_literal()
        .without_display_text();

    EmailAddress::parse_with_options(value, options)
        .ok()
        .map(|email| email.domain().to_string())
}

fn is_disallowed_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Zero width and bidi formatting
            '\u{00AD}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                // Line and paragraph separators
                | '\u{2028}'
                | '\u{2029}'
        )
}

#[cfg(test)]
mod tests {
    use super::email_domain;

    #[test]
    fn test_accepts_addresses() {
        for (email, domain) in [
            ("a@example.com", "example.com"),
            ("first.last+tag@sub.example.co", "sub.example.co"),
            ("o'neil@example.org", "example.org"),
            ("\u{e9}@example.com", "example.com"),
            ("user@localhost", "localhost"),
            ("A@Example.COM", "Example.COM"),
            ("a@xn--bcher-kva.example", "xn--bcher-kva.example"),
            ("a@b\u{fc}cher.example", "b\u{fc}cher.example"),
            ("a%b@example.com", "example.com"),
            ("b!a@example.com", "example.com"),
            ("a\u{a0}b@example.com", "example.com"),
            ("a\u{3000}b@example.com", "example.com"),
            ("a\u{ff20}b@example.com", "example.com"),
            ("a\u{fe6b}b@example.com", "example.com"),
            // Quoted local parts may contain `@`, but the domain is still the delivery domain
            ("\"a\"@evil.com", "evil.com"),
            ("\"a@example.com@\"@evil.com", "evil.com"),
        ] {
            assert_eq!(email_domain(email).as_deref(), Some(domain), "{email}");
        }
    }

    #[test]
    fn test_rejects_ambiguous_addresses() {
        for email in [
            "",
            "a",
            "@example.com",
            "a@",
            "a@@example.com",
            "a@example.com@evil.com",
            "Name <a@evil.com>",
            "a@example.com <a@evil.com>",
            "<a@evil.com>",
            "a(a@example.com@)@evil.com",
            "a@evil.com(example.com)",
            "a\\@example.com@evil.com",
            "a @evil.com",
            " a@evil.com",
            "a@evil.com ",
            "a@evil.com\n",
            "a@evil.com\r\nBcc: b@evil.com",
            "a@evil.com,b@example.com",
            "a@evil.com;b@example.com",
            "a@[127.0.0.1]",
            "a..b@evil.com",
            ".a@evil.com",
            "a.@evil.com",
            "a@evil..com",
            "a@.evil.com",
            "a@evil.com.",
            "a@-evil.com",
            "a@evil-.com",
            "a\u{200b}@evil.com",
            "\"a\u{200b}\"@evil.com",
            "a\u{202e}@evil.com",
            "a\u{85}@evil.com",
            "a\u{2028}@evil.com",
            "a@evil\u{200b}.com",
        ] {
            assert_eq!(email_domain(email), None, "{email:?}");
        }
    }

    #[test]
    fn test_rejects_overlong_parts() {
        let local = "a".repeat(65);
        assert_eq!(email_domain(&format!("{local}@example.com")), None);

        let label = "a".repeat(64);
        assert_eq!(email_domain(&format!("a@{label}.com")), None);
    }
}
