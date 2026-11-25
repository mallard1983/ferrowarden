use super::*;

fn parse(args: &[&str]) -> Cli {
    parse_args(args.iter().map(|s| s.to_string()))
}

#[test]
fn arguments() {
    assert_eq!(parse(&[]), Cli::Run);
    assert_eq!(parse(&["--help"]), Cli::Help);
    assert_eq!(parse(&["-h"]), Cli::Help);
    assert_eq!(parse(&["--version"]), Cli::Version);
    assert_eq!(parse(&["-V"]), Cli::Version);
    assert_eq!(parse(&["serve"]), Cli::Unknown("serve".into()));
    assert_eq!(parse(&["--help", "extra"]), Cli::Help);
}

#[test]
fn usage_uses_the_approved_voice_line() {
    assert!(USAGE.starts_with(
            "ferrowarden-mcp \u{2014} MCP tools for calling APIs through Ferrowarden with named vault credentials."
        ));
}
