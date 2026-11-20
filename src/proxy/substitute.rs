use std::collections::HashSet;
use regex::Regex;
use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};
use crate::vault::VaultClient;

// Placeholder pattern: {{vault:credential_name}}
// Name may contain alphanumerics, underscores, hyphens, and dots.
const PLACEHOLDER_PATTERN: &str = r"\{\{vault:([a-zA-Z0-9_\-\.]+)\}\}";

/// Extract all unique credential names referenced by placeholders in a string.
pub fn extract_placeholder_names(input: &str) -> FerroResult<HashSet<String>> {
    let re = Regex::new(PLACEHOLDER_PATTERN)
        .map_err(|e| FerroError::Internal(e.to_string()))?;

    let names = re
        .captures_iter(input)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .collect();

    Ok(names)
}

/// Resolve all {{vault:name}} placeholders in a string, returning the
/// substituted result as a Zeroizing<String>.
///
/// Each resolved credential value is zeroed immediately after substitution.
/// The returned string contains the real values and must be treated as
/// sensitive — callers should use it only for the outbound request and
/// drop it as soon as possible.
pub async fn substitute(
    input: &str,
    vault: &VaultClient,
    known_names: &[String],
) -> FerroResult<Zeroizing<String>> {
    let re = Regex::new(PLACEHOLDER_PATTERN)
        .map_err(|e| FerroError::Internal(e.to_string()))?;

    // Collect unique names first to avoid fetching the same credential twice
    let names = extract_placeholder_names(input)?;

    // Validate all names exist before fetching any values — fail fast if any
    // placeholder references a credential that doesn't exist in the vault
    for name in &names {
        if !known_names.contains(name) {
            return Err(FerroError::UnknownPlaceholder(name.clone()));
        }
    }

    // Fetch each unique credential value once, holding them in a local map.
    // All values are Zeroizing — they wipe when this map is dropped.
    let mut values: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::new();

    for name in &names {
        let value = vault.get_password(name).await?;
        values.insert(name.clone(), value);
    }

    // Build the substituted string. We work on a plain String during
    // construction, then wrap in Zeroizing before returning.
    let mut result = String::with_capacity(input.len());
    let mut last_end = 0;

    for cap in re.captures_iter(input) {
        let full_match = cap.get(0).unwrap();
        let name = cap.get(1).unwrap().as_str();

        // Append the text before this placeholder unchanged
        result.push_str(&input[last_end..full_match.start()]);

        // Append the real credential value
        if let Some(value) = values.get(name) {
            result.push_str(value.as_str());
        }

        last_end = full_match.end();
    }

    // Append any remaining text after the last placeholder
    result.push_str(&input[last_end..]);

    // values map is dropped here — all Zeroizing credential values are wiped

    Ok(Zeroizing::new(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_names() {
        let input = r#"{"Authorization": "Bearer {{vault:proxmox_token}}", "X-Key": "{{vault:nas_key}}"}"#;
        let names = extract_placeholder_names(input).unwrap();
        assert!(names.contains("proxmox_token"));
        assert!(names.contains("nas_key"));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_extract_no_placeholders() {
        let input = r#"{"Authorization": "Bearer real_token"}"#;
        let names = extract_placeholder_names(input).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn test_extract_duplicate_placeholders() {
        let input = r#"{{vault:token}} and {{vault:token}} again"#;
        let names = extract_placeholder_names(input).unwrap();
        // HashSet deduplicates
        assert_eq!(names.len(), 1);
        assert!(names.contains("token"));
    }
}
