//! Reserved field values derived from the assembly syntax.
//!
//! Where an operand's syntax is a `Choice` whose alternatives are named by
//! the field values they stand for (`<T>` in `[size, Q]` as `T_00_0_8B`,
//! `T_00_1_16B`, …, `T_11_1_2D`), a value combination no alternative names
//! has no syntax: it is RESERVED, and the decode pseudocode makes it
//! UNDEFINED (`if size:Q == '110' then UNDEFINED;`). Only choices every
//! instance of the encoding goes through count: those in the template or in
//! rules it references, not inside an alternative of another choice.
//!
//! Only arrangement specifiers (`<T>`, `<Ta>`, `<Tb>`, …) and scalar widths
//! (`<V>`, `<Va>`, `<Vb>`) are used: other value-named choices name a
//! representative value rather than all of them (`<R>` of the
//! extended-register forms lists `R_00x_W` and `R_x11_X`, yet every `option`
//! value has a register width).
//!
//! SVE writes arrangements in a 2-bit `size` field with letter-named
//! alternatives (`T_H__51`, `Tb_S`). `size` gives the larger of the element
//! sizes the operands use (`H`, `S`, `D` for `SADDLB`'s `<T>`, and for
//! `ADDHNB`'s `<Tb>`), as `B`, `H`, `S`, `D` = `00`, `01`, `10`, `11`, so
//! the choice with the largest letters names the allowed `size` values.

use std::collections::BTreeMap;

use xtask::aarchmrs::{AssemblyRule, Pattern, Symbol};

use super::model::Encoding;

/// Field values allowed by an operand's syntax: the fields, and the patterns
/// of each alternative.
pub type Allowed<'a> = (Vec<&'a str>, Vec<Vec<Pattern>>);

/// The syntax-derived restrictions of `encoding`.
pub fn reserved_values<'a>(
    encoding: &Encoding<'a>,
    rules: &'a BTreeMap<String, AssemblyRule>,
) -> Vec<Allowed<'a>> {
    let instruction = encoding.instruction;
    let mut out = Vec::new();
    // Letter sets of SVE element-size choices encoded in `size`.
    let mut letters: Vec<Vec<u64>> = Vec::new();
    let mut pending: Vec<&Symbol> = instruction.assembly.iter().collect();
    let mut seen: Vec<&str> = Vec::new();
    while let Some(symbol) = pending.pop() {
        let Symbol::Rule(id) = symbol else { continue };
        if seen.contains(&id.as_str()) {
            continue;
        }
        seen.push(id);
        match rules.get(id) {
            Some(AssemblyRule::Rule { symbols, .. }) => pending.extend(symbols),
            Some(AssemblyRule::Choice {
                display: Some(display),
                choices,
            }) if is_arrangement(display) => {
                let Some(fields) = instruction.encoded_in.get(display) else {
                    continue;
                };
                let Some(widths) = fields
                    .iter()
                    .map(|field| encoding.field(field).map(|(_, width)| width))
                    .collect::<Option<Vec<u32>>>()
                else {
                    continue;
                };
                let alternatives: Option<Vec<&str>> = choices
                    .iter()
                    .map(|choice| match choice.as_slice() {
                        [Symbol::Rule(alternative)] => Some(alternative.as_str()),
                        _ => None,
                    })
                    .collect();
                let Some(alternatives) = alternatives else {
                    continue;
                };
                let named: Option<Vec<Vec<Pattern>>> = alternatives
                    .iter()
                    .map(|alternative| value_named(alternative, &widths))
                    .collect();
                if let Some(allowed) = named {
                    out.push((fields.iter().map(String::as_str).collect(), allowed));
                } else if fields.as_slice() == ["size"]
                    && let Some(sizes) = alternatives
                        .iter()
                        .map(|alternative| element_size(alternative))
                        .collect::<Option<Vec<u64>>>()
                {
                    letters.push(sizes);
                }
            }
            Some(AssemblyRule::Choice { .. } | AssemblyRule::Token { .. }) | None => {}
        }
    }
    if let Some(sizes) = letters
        .into_iter()
        .max_by_key(|sizes| sizes.iter().max().copied())
    {
        let allowed = sizes
            .into_iter()
            .filter_map(|size| Pattern::try_from(format!("{size:02b}")).ok())
            .map(|pattern| vec![pattern])
            .collect();
        out.push((vec!["size"], allowed));
    }
    out
}

/// Arrangements `<T>`, `<Ta>`, `<Tb>`, `<Ts>` and scalar widths `<V>`,
/// `<Va>`, `<Vb>`.
fn is_arrangement(display: &str) -> bool {
    display
        .strip_prefix("<T")
        .or_else(|| display.strip_prefix("<V"))
        .and_then(|rest| rest.strip_suffix('>'))
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_lowercase()))
}

/// The id without a `__N` suffix (AARCHMRS numbers rules that would
/// otherwise share an id: `T_H__51`).
fn stem(id: &str) -> &str {
    id.split_once("__").map_or(id, |(stem, _)| stem)
}

/// The element size an SVE alternative such as `T_H__51`, `Tb_S` or
/// `T_xt_D` names (its last part): 0 to 3 for `B`, `H`, `S`, `D`.
fn element_size(id: &str) -> Option<u64> {
    let (_, letter) = stem(id).rsplit_once('_')?;
    match letter {
        "B" => Some(0),
        "H" => Some(1),
        "S" => Some(2),
        "D" => Some(3),
        _ => None,
    }
}

/// The field patterns a value-named rule id stands for: `T_00_1_16B` with
/// widths `[2, 1]` is `['00', '1']`. The values are the first run of
/// `widths.len()` `_`-separated parts after the first part that have the
/// given widths and consist of `0`, `1` and `x`.
pub fn value_named(id: &str, widths: &[u32]) -> Option<Vec<Pattern>> {
    let parts: Vec<&str> = stem(id).split('_').collect();
    (1..parts.len()).find_map(|start| {
        let values = parts.get(start..start + widths.len())?;
        values
            .iter()
            .zip(widths)
            .map(|(value, &width)| {
                let pattern = Pattern::try_from((*value).to_owned()).ok()?;
                (pattern.width() == width).then_some(pattern)
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::{element_size, value_named};

    #[test]
    fn reads_values_from_rule_ids() {
        let values = |id, widths: &[u32]| {
            value_named(id, widths)
                .map(|v| v.iter().map(|p| p.as_str().to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(values("T_00_1_16B", &[2, 1]).unwrap(), ["00", "1"]);
        assert_eq!(values("s_2_0_absent_default", &[1]).unwrap(), ["0"]);
        assert_eq!(values("R_x11_X", &[3]).unwrap(), ["x11"]);
        // A rule-numbering suffix is not a value.
        assert_eq!(values("T_S__11", &[2]), None);
    }

    #[test]
    fn reads_sve_element_sizes() {
        assert_eq!(element_size("T_H__51"), Some(1));
        assert_eq!(element_size("Tb_D"), Some(3));
        assert_eq!(element_size("T_xt_S__2"), Some(2));
        assert_eq!(element_size("T_Q"), None);
        assert_eq!(element_size("T_00_0_8B"), None);
    }
}
