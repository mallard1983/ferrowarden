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
const SESSION_PREFIX: &str = "{{session:";
const SUFFIX: &str = "}}";

/// The longest session name, in characters.
pub const MAX_SESSION_NAME_LEN: usize = 64;

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

/// What a `{{...}}` in a string refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// `{{vault:...}}`: a vault value.
    Vault(Placeholder),
    /// `{{session:NAME}}`: a captured session, by name.
    Session(String),
}

impl Token {
    /// The audit label: [`Placeholder::label`] for a vault placeholder (so
    /// existing labels are unchanged), `session:NAME` for a session. Events
    /// list session names plainly; this is the single-label form.
    #[allow(dead_code)]
    pub fn label(&self) -> String {
        match self {
            Token::Vault(p) => p.label(),
            Token::Session(name) => format!("session:{name}"),
        }
    }
}

/// A token found in a string, with its byte range.
#[derive(Debug, Clone, PartialEq)]
pub struct Occurrence {
    pub start: usize,
    pub end: usize,
    pub token: Token,
}

/// Is `name` a valid session name: 1 to 64 plain characters?
pub fn is_session_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_SESSION_NAME_LEN
        && name.chars().all(is_plain_char)
}

/// The distinct tokens of a request, split by kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collected {
    pub vault: BTreeSet<Placeholder>,
    pub sessions: BTreeSet<String>,
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

    /// The text after `{{session:`: a plain word, then `}}`.
    fn session(&mut self) -> Result<String, String> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if !is_plain_char(c) {
                break;
            }
            self.pos += c.len_utf8();
        }
        let name = &self.s[start..self.pos];
        if name.is_empty() {
            return Err(
                "expected a session name: a word of letters, digits, '_', '-' or '.' (quoting is not allowed)"
                    .to_string(),
            );
        }
        if name.chars().count() > MAX_SESSION_NAME_LEN {
            return Err(format!(
                "a session name has at most {MAX_SESSION_NAME_LEN} characters"
            ));
        }
        if !self.eat(SUFFIX) {
            return Err("expected '}}' to close the placeholder".to_string());
        }
        Ok(name.to_string())
    }
}

/// Find and parse every placeholder in `input`, in position order.
pub fn scan(input: &str) -> FerroResult<Vec<Occurrence>> {
    let mut out = Vec::new();
    let mut from = 0;
    loop {
        let rest = &input[from..];
        let next = match (rest.find(PREFIX), rest.find(SESSION_PREFIX)) {
            (None, None) => break,
            (Some(v), None) => (v, false),
            (None, Some(s)) => (s, true),
            (Some(v), Some(s)) => {
                if v < s {
                    (v, false)
                } else {
                    (s, true)
                }
            }
        };
        let (rel, is_session) = next;
        let start = from + rel;
        let prefix = if is_session { SESSION_PREFIX } else { PREFIX };
        let mut p = Parser {
            s: input,
            pos: start + prefix.len(),
        };
        let parsed = if is_session {
            p.session().map(Token::Session)
        } else {
            p.placeholder().map(Token::Vault)
        };
        let token = parsed.map_err(|reason| {
            // Show the start of the offending text, bounded and on a char boundary.
            let snippet: String = input[start..].chars().take(60).collect();
            FerroError::MalformedPlaceholder(format!("{reason}, in: {snippet}"))
        })?;
        out.push(Occurrence {
            start,
            end: p.pos,
            token,
        });
        from = p.pos;
    }
    Ok(out)
}

/// Collect the distinct tokens in a string.
pub fn collect(input: &str, out: &mut Collected) -> FerroResult<()> {
    for occ in scan(input)? {
        match occ.token {
            Token::Vault(p) => {
                out.vault.insert(p);
            }
            Token::Session(name) => {
                out.sessions.insert(name);
            }
        }
    }
    Ok(())
}

/// Collect the distinct tokens in every string (keys and values) of a JSON value.
pub fn collect_json(value: &Value, out: &mut Collected) -> FerroResult<()> {
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
mod tests;
