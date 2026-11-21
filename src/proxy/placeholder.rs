//! Placeholder grammar.
//!
//! ```text
//! {{vault:NAME}}                  password
//! {{vault:NAME:password}}         password (explicit)
//! {{vault:NAME:username}}         login username
//! {{vault:NAME:totp}}             current TOTP code
//! {{vault:NAME:notes}}            item notes
//! {{vault:NAME:field:FIELD}}      custom field
//!
//! NAME / FIELD := plain word [A-Za-z0-9_.-]+
//!               | 'single-quoted string'   (escapes: \' and \\)
//! ```
//!
//! Quoting lets any item or field name be referenced without imposing a
//! naming convention. Single quotes are used because placeholders usually
//! travel inside JSON, where double quotes would need escaping twice.
//!
//! Anything that starts with `{{vault:` but does not parse is an error, so a
//! malformed placeholder is rejected instead of being forwarded literally.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::error::{FerroError, FerroResult};

const PREFIX: &str = "{{vault:";
const SUFFIX: &str = "}}";

/// Which value of a vault item a placeholder refers to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Selector {
    Password,
    Username,
    Totp,
    Notes,
    Field(String),
}

/// One parsed placeholder: an item name plus a selector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Placeholder {
    pub item: String,
    pub selector: Selector,
}

/// A placeholder found in a string, with its byte range.
#[derive(Debug, Clone, PartialEq)]
pub struct Occurrence {
    pub start: usize,
    pub end: usize,
    pub placeholder: Placeholder,
}

impl Placeholder {
    /// The canonical text between `{{vault:` and `}}`. A password placeholder
    /// renders as just the (possibly quoted) item name, so 0.1.0 audit entries
    /// and labels are unchanged.
    pub fn label(&self) -> String {
        let item = quote_if_needed(&self.item);
        match &self.selector {
            Selector::Password => item,
            Selector::Username => format!("{item}:username"),
            Selector::Totp => format!("{item}:totp"),
            Selector::Notes => format!("{item}:notes"),
            Selector::Field(f) => format!("{item}:field:{}", quote_if_needed(f)),
        }
    }

    /// The full placeholder string, ready to paste into a request.
    pub fn render(&self) -> String {
        format!("{PREFIX}{}{SUFFIX}", self.label())
    }
}

fn is_plain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// Render a name as a plain word when possible, otherwise single-quoted with
/// `\` and `'` escaped.
pub fn quote_if_needed(name: &str) -> String {
    if !name.is_empty() && name.chars().all(is_plain_char) {
        return name.to_string();
    }
    let mut out = String::with_capacity(name.len() + 2);
    out.push('\'');
    for c in name.chars() {
        if c == '\\' || c == '\'' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// Cursor over the text after `{{vault:`.
struct Parser<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> {
        self.s[self.pos..].chars().next()
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.s[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    /// A plain word or a single-quoted string.
    fn name(&mut self, what: &str) -> Result<String, String> {
        match self.peek() {
            Some('\'') => {
                self.pos += 1;
                let mut out = String::new();
                loop {
                    let c = self
                        .peek()
                        .ok_or_else(|| format!("unterminated quoted {what}"))?;
                    self.pos += c.len_utf8();
                    match c {
                        '\'' => break,
                        '\\' => {
                            let e = self
                                .peek()
                                .ok_or_else(|| format!("unterminated quoted {what}"))?;
                            if e != '\\' && e != '\'' {
                                return Err(format!(
                                    "invalid escape '\\{e}' in quoted {what} (only \\' and \\\\ are allowed)"
                                ));
                            }
                            self.pos += e.len_utf8();
                            out.push(e);
                        }
                        c => out.push(c),
                    }
                }
                if out.is_empty() {
                    return Err(format!("empty {what}"));
                }
                Ok(out)
            }
            _ => {
                let start = self.pos;
                while let Some(c) = self.peek() {
                    if !is_plain_char(c) {
                        break;
                    }
                    self.pos += c.len_utf8();
                }
                if self.pos == start {
                    return Err(format!(
                        "expected a {what}: a word of letters, digits, '_', '-' or '.', or a 'quoted name'"
                    ));
                }
                Ok(self.s[start..self.pos].to_string())
            }
        }
    }

    fn word(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if !c.is_ascii_alphanumeric() {
                break;
            }
            self.pos += 1;
        }
        self.s[start..self.pos].to_string()
    }

    fn placeholder(&mut self) -> Result<Placeholder, String> {
        let item = self.name("item name")?;
        let selector = if self.eat(":") {
            match self.word().as_str() {
                "password" => Selector::Password,
                "username" => Selector::Username,
                "totp" => Selector::Totp,
                "notes" => Selector::Notes,
                "field" => {
                    if !self.eat(":") {
                        return Err("expected ':' and a field name after 'field'".to_string());
                    }
                    Selector::Field(self.name("field name")?)
                }
                "" => return Err("expected a selector after ':'".to_string()),
                other => {
                    return Err(format!(
                        "unknown selector '{other}' (use password, username, totp, notes or field:NAME)"
                    ))
                }
            }
        } else {
            Selector::Password
        };
        if !self.eat(SUFFIX) {
            return Err("expected '}}' to close the placeholder".to_string());
        }
        Ok(Placeholder { item, selector })
    }
}

/// Find and parse every placeholder in `input`.
pub fn scan(input: &str) -> FerroResult<Vec<Occurrence>> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = input[from..].find(PREFIX) {
        let start = from + rel;
        let mut p = Parser {
            s: input,
            pos: start + PREFIX.len(),
        };
        let placeholder = p.placeholder().map_err(|reason| {
            // Show the start of the offending text, bounded and on a char boundary.
            let snippet: String = input[start..].chars().take(60).collect();
            FerroError::MalformedPlaceholder(format!("{reason}, in: {snippet}"))
        })?;
        out.push(Occurrence {
            start,
            end: p.pos,
            placeholder,
        });
        from = p.pos;
    }
    Ok(out)
}

/// Collect the distinct placeholders in a string.
pub fn collect(input: &str, out: &mut BTreeSet<Placeholder>) -> FerroResult<()> {
    out.extend(scan(input)?.into_iter().map(|o| o.placeholder));
    Ok(())
}

/// Collect the distinct placeholders in every string (keys and values) of a JSON value.
pub fn collect_json(value: &Value, out: &mut BTreeSet<Placeholder>) -> FerroResult<()> {
    match value {
        Value::String(s) => collect(s, out),
        Value::Array(items) => items.iter().try_for_each(|v| collect_json(v, out)),
        Value::Object(map) => map.iter().try_for_each(|(k, v)| {
            collect(k, out)?;
            collect_json(v, out)
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(s: &str) -> Placeholder {
        let occ = scan(s).unwrap();
        assert_eq!(occ.len(), 1, "{s}");
        occ[0].placeholder.clone()
    }

    fn ph(item: &str, selector: Selector) -> Placeholder {
        Placeholder {
            item: item.to_string(),
            selector,
        }
    }

    #[test]
    fn plain_password_placeholder_is_unchanged_from_0_1() {
        assert_eq!(
            one("{{vault:proxmox_token}}"),
            ph("proxmox_token", Selector::Password)
        );
        assert_eq!(
            one("{{vault:service.account.password}}"),
            ph("service.account.password", Selector::Password)
        );
    }

    #[test]
    fn selectors() {
        assert_eq!(one("{{vault:x:password}}"), ph("x", Selector::Password));
        assert_eq!(one("{{vault:x:username}}"), ph("x", Selector::Username));
        assert_eq!(one("{{vault:x:totp}}"), ph("x", Selector::Totp));
        assert_eq!(one("{{vault:x:notes}}"), ph("x", Selector::Notes));
        assert_eq!(
            one("{{vault:x:field:api_key}}"),
            ph("x", Selector::Field("api_key".into()))
        );
    }

    #[test]
    fn quoted_names_allow_any_characters() {
        assert_eq!(
            one("{{vault:'Proxmox (prod)'}}"),
            ph("Proxmox (prod)", Selector::Password)
        );
        assert_eq!(
            one("{{vault:'a: b }} c':field:'key:with:colons'}}"),
            ph("a: b }} c", Selector::Field("key:with:colons".into()))
        );
        assert_eq!(
            one(r"{{vault:'it\'s':username}}"),
            ph("it's", Selector::Username)
        );
        assert_eq!(
            one(r"{{vault:'back\\slash'}}"),
            ph(r"back\slash", Selector::Password)
        );
        assert_eq!(
            one("{{vault:'ünïcödé 名前'}}"),
            ph("ünïcödé 名前", Selector::Password)
        );
    }

    #[test]
    fn spans_and_multiple_occurrences() {
        let s = "Bearer {{vault:a}} and {{vault:'b c':username}}!";
        let occ = scan(s).unwrap();
        assert_eq!(occ.len(), 2);
        assert_eq!(&s[occ[0].start..occ[0].end], "{{vault:a}}");
        assert_eq!(&s[occ[1].start..occ[1].end], "{{vault:'b c':username}}");
    }

    #[test]
    fn adjacent_placeholders() {
        let occ = scan("{{vault:a}}{{vault:b}}").unwrap();
        assert_eq!(occ.len(), 2);
    }

    #[test]
    fn no_placeholders() {
        assert!(scan("plain {{other}} text {vault:x}").unwrap().is_empty());
    }

    #[test]
    fn malformed_placeholders_are_errors() {
        for bad in [
            "{{vault:}}",
            "{{vault:a b}}",
            "{{vault:a",
            "{{vault:'unterminated}}",
            "{{vault:''}}",
            "{{vault:a:}}",
            "{{vault:a:bogus}}",
            "{{vault:a:field}}",
            "{{vault:a:field:}}",
            r"{{vault:'bad \n escape'}}",
            "{{vault:a}x",
        ] {
            let err = scan(bad).unwrap_err();
            assert!(
                matches!(err, FerroError::MalformedPlaceholder(_)),
                "{bad} -> {err:?}"
            );
        }
    }

    #[test]
    fn render_round_trips() {
        for p in [
            ph("simple", Selector::Password),
            ph("Proxmox (prod)", Selector::Username),
            ph("it's \\ odd", Selector::Field("api secret".into())),
            ph("x", Selector::Field("key:with:colons".into())),
            ph("x", Selector::Totp),
            ph("x", Selector::Notes),
        ] {
            assert_eq!(one(&p.render()), p, "{}", p.render());
        }
    }

    #[test]
    fn rendering() {
        assert_eq!(ph("tok", Selector::Password).render(), "{{vault:tok}}");
        assert_eq!(
            ph("a b", Selector::Username).render(),
            "{{vault:'a b':username}}"
        );
        assert_eq!(
            ph("x", Selector::Field("api secret".into())).render(),
            "{{vault:x:field:'api secret'}}"
        );
        assert_eq!(quote_if_needed("it's"), r"'it\'s'");
    }

    #[test]
    fn collect_json_includes_keys_and_rejects_malformed() {
        let mut out = BTreeSet::new();
        collect_json(
            &serde_json::json!({"{{vault:k}}": ["{{vault:'v w':notes}}", 1]}),
            &mut out,
        )
        .unwrap();
        assert!(out.contains(&ph("k", Selector::Password)));
        assert!(out.contains(&ph("v w", Selector::Notes)));
        let err = collect_json(
            &serde_json::json!({"a": "{{vault:bad name}}"}),
            &mut BTreeSet::new(),
        )
        .unwrap_err();
        assert!(matches!(err, FerroError::MalformedPlaceholder(_)));
    }
}
