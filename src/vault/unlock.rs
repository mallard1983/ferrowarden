use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};

/// Read the master password from a file, returning it as a Zeroizing string.
/// The file must contain only the password on the first line (no trailing newline required).
/// The caller passes the result straight to `Vault::unlock`, which consumes and wipes it.
pub fn read_password_file(path: &std::path::Path) -> FerroResult<Zeroizing<String>> {
    let raw = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| FerroError::Config(format!("Cannot read unlock file: {}", e)))?,
    );

    // Trim trailing newlines only — preserve any intentional whitespace in the
    // password. The same rule as every other secret file (config::secrets).
    let password = crate::config::secrets::strip_line_end(&raw).to_string();

    if password.is_empty() {
        return Err(FerroError::Config("Unlock file is empty".to_string()));
    }

    Ok(Zeroizing::new(password))
}

#[cfg(test)]
mod tests;
