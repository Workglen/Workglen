//! Capability boundaries: protocol validity is not domain reputation.
use workglen_idna::{domain_to_ascii, domain_to_ascii_strict};
#[test]
fn uts46_is_not_idna2008_or_impersonation_detection() {
    for (input, expected) in [
        ("a·b.test", "xn--ab-0ea.test"),
        ("l·l.test", "xn--ll-0ea.test"),
        ("😀.test", "xn--e28h.test"),
        ("раypal.com", "xn--ypal-43d9g.com"),
    ] {
        assert_eq!(domain_to_ascii(input).unwrap(), expected);
        assert_eq!(domain_to_ascii_strict(input).unwrap(), expected);
    }
    for input in [
        "a\u{200d}b.test",
        "\u{0301}a.test",
        "אa.test",
        "a\u{202e}.test",
    ] {
        assert!(domain_to_ascii(input).is_err(), "{input:?}");
    }
}
#[test]
fn hostile_contextual_sequences_are_bounded() {
    // Payload families in Python idna's GHSA-65pc-fj4g-8rjx. This does
    // not assert vulnerability parity: our UTS #46 engine has no ContextO loop.
    for input in [
        "\u{0660}".repeat(100_000),
        format!("{}漢", "・".repeat(100_000)),
    ] {
        assert!(domain_to_ascii(&input).is_err());
    }
    assert!(domain_to_ascii(&"\u{0660}".repeat(1001)).is_err());
}
