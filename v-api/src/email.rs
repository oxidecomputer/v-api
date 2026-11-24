// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A deliberately narrow email grammar: a single `local@domain` addr-spec. Display names, angle
//! brackets, quoted local parts, comments, whitespace, control characters, separators, domain
//! literals and extra `@` characters are all rejected, so the text after the only `@` is always
//! the domain mail is delivered to.

const LOCAL_MAX: usize = 64;
const DOMAIN_MAX: usize = 253;
const LABEL_MAX: usize = 63;

/// The domain of `value` if it is a plain `local@domain` address.
pub fn email_domain(value: &str) -> Option<&str> {
    let (local, domain) = value.split_once('@')?;
    (is_local_part(local) && is_domain(domain)).then_some(domain)
}

// RFC 5322 dot-atom with atext, plus non-ASCII alphanumerics. `%` and `!` are excluded as they
// can source-route mail to another host.
fn is_local_part(local: &str) -> bool {
    local.len() <= LOCAL_MAX
        && local.split('.').all(|atom| {
            !atom.is_empty()
                && atom.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || "#$&'*+-/=?^_`{|}~".contains(c)
                        || (!c.is_ascii() && c.is_alphanumeric())
                })
        })
}

// ASCII letters, digits and hyphens; internationalized domains must be punycode
fn is_domain(domain: &str) -> bool {
    domain.len() <= DOMAIN_MAX
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= LABEL_MAX
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

#[cfg(test)]
mod tests {
    use super::email_domain;

    #[test]
    fn test_accepts_plain_addresses() {
        for (email, domain) in [
            ("a@example.com", "example.com"),
            ("first.last+tag@sub.example.co", "sub.example.co"),
            ("o'neil@example.org", "example.org"),
            ("\u{e9}@example.com", "example.com"),
            ("user@localhost", "localhost"),
            ("A@Example.COM", "Example.COM"),
            ("a@xn--bcher-kva.example", "xn--bcher-kva.example"),
        ] {
            assert_eq!(email_domain(email), Some(domain), "{email}");
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
            "\"a@example.com@\"@evil.com",
            "\"a\"@evil.com",
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
            "a@evil_com.com",
            "a\u{ff20}example.com@evil.com",
            "a\u{200b}@evil.com",
            "a@evil\u{200b}.com",
            "a@b\u{fc}cher.example",
            "a%evil.com@example.com",
            "evil.com!a@example.com",
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
