use super::*;

fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn limit_defaults_to_100_capped_by_the_buffer() {
    assert_eq!(parse_limit(&[], 1000).unwrap(), 100);
    assert_eq!(parse_limit(&[], 50).unwrap(), 50);
}

#[test]
fn limit_accepts_one_to_buffer_size() {
    assert_eq!(parse_limit(&q(&[("limit", "1")]), 1000).unwrap(), 1);
    assert_eq!(parse_limit(&q(&[("limit", "1000")]), 1000).unwrap(), 1000);
    for bad in ["0", "1001", "-1", "abc", "", "1.5", " 5"] {
        assert!(parse_limit(&q(&[("limit", bad)]), 1000).is_err(), "{bad:?}");
    }
}

#[test]
fn limit_rejects_unknown_and_repeated_parameters() {
    assert!(parse_limit(&q(&[("lmit", "5")]), 1000).is_err());
    assert!(parse_limit(&q(&[("limit", "5"), ("x", "1")]), 1000).is_err());
    assert!(parse_limit(&q(&[("limit", "5"), ("limit", "5")]), 1000).is_err());
    assert!(parse_limit(&q(&[("Limit", "5")]), 1000).is_err());
}
