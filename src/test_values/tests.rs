use super::*;

#[test]
fn a_stand_in_secret_is_random_hex_and_never_repeats() {
    let a = random_secret();
    let b = random_secret();
    assert_eq!(a.len(), 32);
    assert!(a
        .bytes()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_ne!(a, b);
}
