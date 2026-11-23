//! The GUI's theme files (`gui/view/src/theme_css.rs`) on arbitrary text:
//! user themes are files the GUI reads, so parsing and resolving must
//! never panic or recurse without bound, whatever they hold. Checks what
//! the module promises: every problem is placed inside the text, a
//! resolved colour written back as hex reads as the same colour, a file
//! imported by an identical one resolves the same, and resolving is
//! deterministic.
//!
//! The module uses nothing but `std`, so it is included by path rather
//! than through the GUI's workspace (which would build every engine crate
//! for the fuzzer).

#![no_main]

#[path = "../../gui/view/src/theme_css.rs"]
#[allow(dead_code, reason = "the target uses part of the module")]
mod theme_css;

use libfuzzer_sys::fuzz_target;
use theme_css::{Kind, Resolver, Sheet, Value, parse};

/// Properties of every kind, chosen by the name so the fuzzer reaches each.
fn kind(name: &str) -> Kind {
    match name {
        "--name" => Kind::Text,
        "--appearance" => Kind::Keyword(&["dark", "light"]),
        _ => match name.len() % 4 {
            0 => Kind::Color,
            1 => Kind::Any,
            2 => Kind::Keyword(&["opaque", "transparent"]),
            _ => Kind::Fraction,
        },
    }
}

/// Every declared property's value (each name once), then the
/// diagnostics as text.
fn resolve(layers: &[Sheet]) -> (Vec<(String, Option<Value>)>, Vec<String>) {
    let mut resolver = Resolver::new(layers, kind);
    let mut names: Vec<String> = Vec::new();
    for name in layers.iter().flat_map(Sheet::names) {
        if !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
    }
    let values = names
        .into_iter()
        .map(|n| {
            let v = resolver.get(&n);
            (n, v)
        })
        .collect();
    let diagnostics = resolver.finish().iter().map(ToString::to_string).collect();
    (values, diagnostics)
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let sheet = parse("fuzz.css", text);
    let lines = u32::try_from(text.lines().count().max(1)).unwrap_or(u32::MAX);
    for d in &sheet.diagnostics {
        assert!(d.line >= 1 && d.column >= 1, "{d}");
        assert!(d.line <= lines.saturating_add(1), "{d} past line {lines}");
    }
    let one = std::slice::from_ref(&sheet);
    let (values, diagnostics) = resolve(one);
    for d in &diagnostics {
        assert!(d.starts_with("fuzz.css:"), "{d}");
    }
    // Deterministic.
    assert_eq!(resolve(one), (values.clone(), diagnostics));
    // An identical file over it changes no value.
    let twice = [sheet.clone(), sheet.clone()];
    assert_eq!(resolve(&twice).0, values);
    // A colour written back as hex reads as itself.
    for (_, value) in &values {
        if let Some(Value::Color(c)) = value {
            let again = [parse("again.css", &format!(":root {{ --c: #{c:08x}; }}"))];
            let mut resolver = Resolver::new(&again, |_| Kind::Color);
            assert_eq!(resolver.get("--c"), Some(Value::Color(*c)));
            assert!(resolver.finish().is_empty());
        }
    }
});
