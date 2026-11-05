//! Capability boundaries: protocol validity is not domain reputation.
use workglen_idna::{domain_to_ascii, domain_to_ascii_strict, has_mixed_script_labels};
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
fn mixed_script_check_is_explicit_bounded_and_not_confusable_detection() {
    for input in [
        "раypal.com",
        "xn--ypal-43d9g.com",
        "aβ.example",
        "officeпривет.example",
    ] {
        assert!(has_mixed_script_labels(input).unwrap(), "{input:?}");
    }
    for input in [
        "paypal.com",
        "почта.рф",
        "παράδειγμα.ελ",
        "example.中国",
        "example.123",
    ] {
        assert!(!has_mixed_script_labels(input).unwrap(), "{input:?}");
    }
    // Japanese script combinations can be legitimate: this is a risk signal,
    // not a malicious-domain verdict or a same-script confusable skeleton.
    assert!(has_mixed_script_labels("日本語テスト.example").unwrap());
    assert!(has_mixed_script_labels("a\u{200d}b.test").is_err());
    assert!(has_mixed_script_labels(&"a".repeat(65_537)).is_err());
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
