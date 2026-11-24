//! Mandatory output redaction, config secret placeholder masking, and UTF-8 safe truncation.

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use regex::Regex;

use crate::config::ServerProfile;

fn private_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        )
        .unwrap()
    })
}

fn ssh_rsh_echo_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?:-e|--rsh)[=\s]+['"]?ssh\b[^'"\n]*['"]?"#).unwrap())
}

fn aws_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap())
}

fn bearer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}").unwrap())
}

fn dsn_creds_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b((?:mysql|postgres|postgresql|redis|rediss|mongodb(?:\+srv)?|amqp)://[^:\s/@]+:)([^@\s/]+)(@)",
        )
        .unwrap()
    })
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)")
            .unwrap()
    })
}

fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\{REDACTED_SECRET_(\d+)\}\}").unwrap())
}

fn is_ip_boundary_char(b: u8) -> bool {
    !(b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

fn redact_ipv4(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;

    for m in ipv4_re().find_iter(text) {
        let start = m.start();
        let end = m.end();
        let left_ok = start == 0 || is_ip_boundary_char(bytes[start - 1]);
        let right_ok = end == bytes.len() || is_ip_boundary_char(bytes[end]);
        if left_ok && right_ok {
            out.push_str(&text[last..start]);
            out.push_str("[REDACTED_IP]");
            last = end;
        }
    }
    out.push_str(&text[last..]);
    out
}

#[derive(Debug, Clone)]
pub struct Redactor {
    profiles: Vec<ServerProfile>,
}

impl Redactor {
    pub fn new(all_profiles: &BTreeMap<String, ServerProfile>) -> Self {
        Self {
            profiles: all_profiles.values().cloned().collect(),
        }
    }

    pub fn redact(
        &self,
        text: &str,
        active_profile: Option<&ServerProfile>,
        extra_literals: &[(&str, &str)],
    ) -> String {
        if text.is_empty() {
            return String::new();
        }

        let mut out = private_key_re()
            .replace_all(text, "[REDACTED_PRIVATE_KEY]")
            .into_owned();
        out = ssh_rsh_echo_re()
            .replace_all(&out, "[REDACTED_SSH_CMD]")
            .into_owned();

        let mut replacements: Vec<(String, String)> = Vec::new();
        for &(lit, tag) in extra_literals {
            if !lit.is_empty() {
                replacements.push((lit.to_string(), tag.to_string()));
            }
        }

        let mut to_scrub: Vec<&ServerProfile> = self.profiles.iter().collect();
        if let Some(active) = active_profile {
            if !to_scrub.iter().any(|p| p.alias == active.alias) {
                to_scrub.push(active);
            }
        }

        for prof in to_scrub {
            replacements.push((
                format!("{}@{}", prof.user, prof.host),
                "[REDACTED_USER]@[REDACTED_HOST]".to_string(),
            ));
            replacements.push((
                prof.key_file.to_string_lossy().into_owned(),
                "[REDACTED_KEY]".to_string(),
            ));
            if let Some(ref sk) = prof.sync_key_file {
                replacements.push((
                    sk.to_string_lossy().into_owned(),
                    "[REDACTED_KEY]".to_string(),
                ));
            }
            replacements.push((prof.host.clone(), "[REDACTED_HOST]".to_string()));
            if prof.user.len() >= 2 {
                replacements.push((prof.user.clone(), "[REDACTED_USER]".to_string()));
            }
        }

        // Longest literal first to prevent partial substring leaks
        replacements.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (lit, tag) in replacements {
            if !lit.is_empty() {
                out = out.replace(&lit, &tag);
            }
        }

        out = aws_key_re().replace_all(&out, "[REDACTED_SECRET]").into_owned();
        out = bearer_re()
            .replace_all(&out, "Bearer [REDACTED_SECRET]")
            .into_owned();
        out = dsn_creds_re()
            .replace_all(&out, "${1}[REDACTED_SECRET]${3}")
            .into_owned();
        redact_ipv4(&out)
    }
}

pub fn mask_config_secrets(
    content: &str,
    redact_patterns: &[String],
) -> Result<(String, BTreeMap<String, String>), String> {
    if redact_patterns.is_empty() {
        return Ok((content.to_string(), BTreeMap::new()));
    }
    let compiled: Vec<Regex> = redact_patterns
        .iter()
        .map(|p| Regex::new(p).map_err(|e| format!("Invalid redact regex: {e}")))
        .collect::<Result<_, _>>()?;

    let mut secret_map: BTreeMap<String, String> = BTreeMap::new();
    let mut counter: usize = 0;
    let mut masked = String::with_capacity(content.len());

    for line in content.split_inclusive('\n') {
        let mut current = line.to_string();
        for regex in &compiled {
            let mut next = String::with_capacity(current.len());
            let mut last = 0;
            for m in regex.find_iter(&current) {
                let matched = m.as_str();
                next.push_str(&current[last..m.start()]);
                if placeholder_re().is_match(matched) {
                    next.push_str(matched);
                } else {
                    counter += 1;
                    let ph = format!("{{{{REDACTED_SECRET_{counter}}}}}");
                    secret_map.insert(ph.clone(), matched.to_string());
                    next.push_str(&ph);
                }
                last = m.end();
            }
            next.push_str(&current[last..]);
            current = next;
        }
        masked.push_str(&current);
    }

    Ok((masked, secret_map))
}

pub fn unmask_config_secrets(
    draft_content: &str,
    secret_map: &BTreeMap<String, String>,
) -> Result<String, String> {
    let found: HashSet<String> = placeholder_re()
        .captures_iter(draft_content)
        .map(|c| format!("{{{{REDACTED_SECRET_{}}}}}", &c[1]))
        .collect();
    let expected: HashSet<String> = secret_map.keys().cloned().collect();

    let mut unknown: Vec<&String> = found.difference(&expected).collect();
    if !unknown.is_empty() {
        unknown.sort();
        let joined = unknown
            .into_iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "Draft contains unknown secret placeholder(s): {joined}"
        ));
    }

    let mut missing: Vec<&String> = expected.difference(&found).collect();
    if !missing.is_empty() {
        missing.sort();
        let joined = missing
            .into_iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "Draft removed or modified protected secret placeholder(s): {joined}"
        ));
    }

    let mut restored = draft_content.to_string();
    for (ph, real_val) in secret_map {
        if restored.matches(ph.as_str()).count() != 1 {
            return Err(format!(
                "Placeholder {ph} must appear exactly once in draft."
            ));
        }
        restored = restored.replace(ph, real_val);
    }
    Ok(restored)
}

pub fn truncate_output(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let suffix = "\n... [OUTPUT TRUNCATED]\n";
    let budget = max_bytes.saturating_sub(suffix.len());
    let mut cut = budget.min(text.len());
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{}", &text[..cut], suffix)
}
