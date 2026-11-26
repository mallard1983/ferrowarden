use super::*;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn reads_plain_password() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "my_secure_password").unwrap();
    let pw = read_password_file(f.path()).unwrap();
    assert_eq!(pw.as_str(), "my_secure_password");
}

#[test]
fn strips_trailing_newline() {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, "my_secure_password").unwrap();
    let pw = read_password_file(f.path()).unwrap();
    assert_eq!(pw.as_str(), "my_secure_password");
}

#[test]
fn strips_crlf() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "my_secure_password\r\n").unwrap();
    let pw = read_password_file(f.path()).unwrap();
    assert_eq!(pw.as_str(), "my_secure_password");
}

#[test]
fn preserves_internal_whitespace() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "pass word with spaces").unwrap();
    let pw = read_password_file(f.path()).unwrap();
    assert_eq!(pw.as_str(), "pass word with spaces");
}

#[test]
fn empty_file_returns_error() {
    let f = NamedTempFile::new().unwrap();
    let err = read_password_file(f.path()).unwrap_err();
    assert!(err.to_string().contains("empty"));
}

#[test]
fn missing_file_returns_error() {
    let path = std::path::Path::new("/nonexistent/path/unlock.key");
    let err = read_password_file(path).unwrap_err();
    assert!(err.to_string().contains("Cannot read unlock file"));
}
