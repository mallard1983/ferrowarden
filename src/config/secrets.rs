//! Secrets that come from the environment or from a file named by
//! `<NAME>_FILE` (a Docker secret, a `chmod 400` bind mount).
//!
//! One helper serves every such secret (the admin key, the notifier tokens)
//! so they all behave the same way. The value is read here, in Rust, into a
//! [`Zeroizing`] string. It is never written into the process environment:
//! `/proc/<pid>/environ` holds only the path of the file, never its content.
//!
//! Error messages name variables and error kinds, never a secret value.

use std::io;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};

/// What to do when both `NAME` and `NAME_FILE` are set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Both {
    /// Refuse to start: the operator probably has two sources of truth.
    Error,
    /// The direct variable wins and the file is not read (the admin key:
    /// a plain variable is for non-Docker use, the file for Docker).
    DirectWins,
}

/// Look up the secret `name`, directly or through the file `{name}_FILE`.
///
/// `get` reads an environment variable (empty counts as unset); `read` reads
/// a file. Both are injected so tests need neither. Returns `Ok(None)` when
/// neither variable is set. Trailing newlines (LF, CR) are removed from the
/// value; an empty value is an error.
pub fn load_secret(
    name: &str,
    both: Both,
    get: impl Fn(&str) -> Option<String>,
    read: impl Fn(&Path) -> io::Result<Vec<u8>>,
) -> FerroResult<Option<Zeroizing<String>>> {
    let file_name = format!("{name}_FILE");
    let direct = get(name).map(Zeroizing::new);
    let file = get(&file_name);
    let raw = match (direct, file) {
        (Some(_), Some(_)) if both == Both::Error => {
            return Err(FerroError::Config(format!(
                "set only one of {name} and {file_name}, not both"
            )))
        }
        (Some(v), _) => v,
        (None, Some(path)) => read_secret_file(&file_name, Path::new(&path), read)?,
        (None, None) => return Ok(None),
    };
    let value = Zeroizing::new(strip_line_end(&raw).to_string());
    if value.is_empty() {
        return Err(FerroError::Config(format!(
            "the secret from {name} (or {file_name}) is empty"
        )));
    }
    Ok(Some(value))
}

/// The process-environment version of [`load_secret`]: real variables, real
/// files.
pub fn load_secret_from_env(name: &str, both: Both) -> FerroResult<Option<Zeroizing<String>>> {
    load_secret(
        name,
        both,
        |n| std::env::var(n).ok().filter(|v| !v.is_empty()),
        |p| std::fs::read(p),
    )
}

/// Read the file named by `var` (for the messages) as UTF-8 text.
fn read_secret_file(
    var: &str,
    path: &Path,
    read: impl Fn(&Path) -> io::Result<Vec<u8>>,
) -> FerroResult<Zeroizing<String>> {
    let bytes = Zeroizing::new(read(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => {
            FerroError::Config(format!("{var} does not exist: {}", path.display()))
        }
        // Compose mounts file secrets with their host owner and mode, so on a
        // Linux host the usual cause is a file the container user cannot read.
        io::ErrorKind::PermissionDenied => FerroError::Config(format!(
            "cannot read {} (named by {var}) as UID {}. On a Linux host: \
             sudo chown 999:999 secrets/ferrowarden_admin_key secrets/bw_master_password \
             certs/server.key",
            path.display(),
            current_uid()
        )),
        kind => FerroError::Config(format!("cannot read {var} ({kind:?})")),
    })?);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| FerroError::Config(format!("{var} does not hold valid UTF-8 text")))?;
    Ok(Zeroizing::new(text.to_string()))
}

/// The user id this process runs as, for the "cannot read" hint. Taken from
/// the owner of `/proc/self`, which avoids a `libc` dependency; `?` elsewhere.
fn current_uid() -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata("/proc/self") {
            return meta.uid().to_string();
        }
    }
    "?".to_string()
}

/// Remove trailing line endings only: any other whitespace may be part of the
/// secret.
pub fn strip_line_end(s: &str) -> &str {
    s.trim_end_matches(['\n', '\r'])
}

#[cfg(test)]
mod tests;
