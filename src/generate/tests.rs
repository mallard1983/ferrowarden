use super::*;
use std::collections::HashSet;

#[test]
fn the_sets_have_the_documented_sizes_and_no_duplicates() {
    let sizes = [
        (Charset::Alphanumeric, 62),
        (Charset::Ascii, 76),
        (Charset::Hex, 16),
        (Charset::Base64Url, 64),
    ];
    for (set, size) in sizes {
        let a = set.alphabet();
        assert_eq!(a.len(), size, "{set:?}");
        assert_eq!(a.iter().collect::<HashSet<_>>().len(), size, "{set:?}");
    }
}

#[test]
fn the_ascii_set_has_no_shell_url_or_json_special_characters() {
    for forbidden in b"\"'\\$` &;|<>/?(){}[]\n\t" {
        assert!(!ASCII.contains(forbidden), "{}", *forbidden as char);
    }
    let symbols: String = ASCII
        .iter()
        .filter(|b| !b.is_ascii_alphanumeric())
        .map(|b| *b as char)
        .collect();
    assert_eq!(symbols, "-_.~!@#%^*+=:,");
}

#[test]
fn names_round_trip() {
    for set in Charset::ALL {
        assert_eq!(Charset::parse(set.as_str()), Some(set));
    }
    assert_eq!(Charset::parse("ASCII"), None);
    assert_eq!(Charset::parse(""), None);
    assert_eq!(Charset::default(), Charset::Alphanumeric);
}

#[test]
fn lengths_are_bounded() {
    assert!(check_length(15).is_err());
    assert_eq!(check_length(16).unwrap(), 16);
    assert_eq!(check_length(128).unwrap(), 128);
    assert!(check_length(129).is_err());
    assert!(generate(Charset::Hex, 8).is_err());
    assert!(generate(Charset::Hex, 200).is_err());
}

#[test]
fn a_generated_value_has_the_length_and_only_set_characters() {
    for set in Charset::ALL {
        for length in [16, 32, 128] {
            let v = generate(set, length).unwrap();
            assert_eq!(v.chars().count(), length as usize);
            assert!(
                v.bytes().all(|b| set.alphabet().contains(&b)),
                "{set:?} produced a character outside its set"
            );
        }
    }
}

#[test]
fn every_symbol_of_every_set_appears_with_the_real_generator() {
    // 128 characters x 400 draws: each symbol of the largest set is expected
    // ~670 times, so a missing one means a broken sampler, not bad luck.
    for set in Charset::ALL {
        let mut seen = HashSet::new();
        for _ in 0..400 {
            seen.extend(generate(set, 128).unwrap().bytes());
        }
        let wanted: HashSet<u8> = set.alphabet().iter().copied().collect();
        assert_eq!(seen, wanted, "{set:?}");
    }
}

#[test]
fn two_values_differ() {
    let a = generate(Charset::Alphanumeric, 32).unwrap();
    let b = generate(Charset::Alphanumeric, 32).unwrap();
    assert_ne!(*a, *b);
}

/// A source that hands out the given bytes in order, then zeros.
fn script(bytes: Vec<u8>) -> impl FnMut(&mut [u8]) -> bool {
    let mut pos = 0;
    move |buf: &mut [u8]| {
        for slot in buf.iter_mut() {
            *slot = bytes.get(pos).copied().unwrap_or(0);
            pos += 1;
        }
        true
    }
}

#[test]
fn bytes_at_or_above_the_limit_are_rejected_not_wrapped() {
    // Alphanumeric: 62 characters, so the limit is 256 - (256 % 62) = 248.
    // 247 is the last usable byte (247 % 62 = 61, the last character); 248
    // and up are skipped. Were they wrapped, 248 would give 'A' (248 % 62 = 0).
    let mut bytes = vec![248u8, 255, 250, 247];
    bytes.extend(std::iter::repeat_n(61u8, 15)); // the last character
    let v = generate_with(Charset::Alphanumeric, 16, script(bytes)).unwrap();
    assert_eq!(&*v, "9999999999999999");
}

#[test]
fn the_mapping_is_the_alphabet_in_order() {
    // Hex has no rejection (256 % 16 == 0): byte b gives alphabet[b % 16].
    let bytes: Vec<u8> = (0u8..16).collect();
    let v = generate_with(Charset::Hex, 16, script(bytes)).unwrap();
    assert_eq!(&*v, "0123456789abcdef");
    let v = generate_with(Charset::Hex, 16, script(vec![255; 16])).unwrap();
    assert_eq!(&*v, "ffffffffffffffff");
}

#[test]
fn the_rejection_limit_leaves_every_character_equally_likely() {
    // Count how many bytes 0..=255 each character would get under the rule:
    // all counts are equal, for every set.
    for set in Charset::ALL {
        let size = set.alphabet().len();
        let limit = 256 - (256 % size);
        let mut counts = vec![0usize; size];
        for b in 0..limit {
            counts[b % size] += 1;
        }
        assert!(counts.iter().all(|c| *c == counts[0]), "{set:?}");
        // And the limit is the largest multiple of the size that fits.
        assert!(limit + size > 256 && limit % size == 0, "{set:?}");
    }
}

#[test]
fn a_failing_source_is_an_error_and_a_hopeless_one_does_not_loop() {
    assert!(generate_with(Charset::Hex, 16, |_| false).is_err());
    // Every byte rejected (255 for alphanumeric): gives up with an error.
    let r = generate_with(Charset::Alphanumeric, 16, |buf| {
        buf.fill(255);
        true
    });
    assert!(r.is_err());
}
