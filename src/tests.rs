
use super::*;

fn parse(args: &[&str]) -> Cli {
    parse_args(args.iter().map(|a| a.to_string()))
}

#[test]
fn no_arguments_runs() {
    assert_eq!(parse(&[]), Cli::Run);
}

#[test]
fn help_and_version_flags() {
    assert_eq!(parse(&["--help"]), Cli::Help);
    assert_eq!(parse(&["-h"]), Cli::Help);
    assert_eq!(parse(&["--version"]), Cli::Version);
    assert_eq!(parse(&["-V"]), Cli::Version);
}

#[test]
fn healthcheck_is_a_subcommand_without_arguments() {
    assert_eq!(parse(&["healthcheck"]), Cli::Healthcheck);
    assert_eq!(
        parse(&["healthcheck", "--insecure"]),
        Cli::Unknown("--insecure".into())
    );
    assert!(USAGE.contains("healthcheck"));
}

#[test]
fn anything_else_is_unknown() {
    assert_eq!(parse(&["serve"]), Cli::Unknown("serve".into()));
    assert_eq!(parse(&["-v"]), Cli::Unknown("-v".into()));
    assert_eq!(parse(&["--help2"]), Cli::Unknown("--help2".into()));
}

#[test]
fn usage_starts_with_the_description() {
    assert!(USAGE.starts_with(
            "Ferrowarden \u{2014} proxy authenticated API calls for agents using named vault credentials."
        ));
    assert!(USAGE.contains("docs/setup.md"));
}
