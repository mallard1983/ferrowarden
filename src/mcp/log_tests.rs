
use super::log_filter;

#[test]
fn only_plain_levels_are_accepted_and_libraries_stay_quiet() {
    assert_eq!(
        log_filter("debug").as_deref(),
        Some("off,rmcp=error,ferrowarden_mcp=debug")
    );
    assert_eq!(
        log_filter(" INFO ").as_deref(),
        Some("off,rmcp=error,ferrowarden_mcp=info")
    );
    // A full filter would be able to switch on HTTP-library logs.
    assert_eq!(log_filter("hyper=trace"), None);
    assert_eq!(log_filter(""), None);
}
