//! `access.rs` of the decoder: how each instruction accesses its operands,
//! the memory it accesses, the registers it uses without naming them and
//! the condition flags it reads and writes.
//!
//! Operand access is generated per form, slot by slot, from the code that
//! pushes the slot's operands (`symbols`): every `ops.push(<operand>)` of a
//! slot becomes `ops.push(<the slot's access>)` with the slot's control flow
//! kept, so `access` pushes exactly one entry per operand `operands` pushes,
//! for every word, by construction. A slot's access comes from Arm's name
//! for it (`<Xd>` is written, `<Xn>` read, `<Zdn>` both, `<Xt>` by the
//! memory access) and the rules in `rules.rs`; generation fails for a slot
//! no rule covers.

mod rules;

use std::collections::BTreeMap;

use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};
use quote::quote;
use xtask::aarchmrs::Package;

use super::emit::encoding_ident;
use super::model::Encoding;
use super::symbols::{Form, Missing, Syntax, extract};
use super::{AARCHMRS_NOTICE, aliases, output};
use crate::Result;
use crate::codegen::{GeneratedFile, lit};
use rules::{Rule, matches};

/// The kinds of memory access (`MemoryKind` variants).
const KINDS: &[&str] = &[
    "Load",
    "Store",
    "Atomic",
    "LoadExclusive",
    "StoreExclusive",
    "Prefetch",
    "Copy",
    "LoadTag",
    "StoreTag",
];

/// What one form is: its encoding, names and memory kind.
struct Context<'a> {
    encoding: &'a Encoding<'a>,
    form: &'a Form<'a>,
    /// The memory access kind (a `KINDS` entry) of a memory form.
    kind: Option<&'static str>,
    /// Whether a `/M` predicate governs the form (merging).
    merging: bool,
    /// Whether a `/<ZM>` predicate governs the form: merging when the `M`
    /// field is 1, zeroing otherwise.
    merging_if_m: bool,
}

impl Context<'_> {
    /// Whether the form matches `pattern`: its encoding's name, or for a
    /// pattern naming an alias (`ENCODING__alias`) the form's name.
    fn is(&self, pattern: &str) -> bool {
        if pattern.contains("__") {
            matches(pattern, &self.form.name)
        } else {
            matches(pattern, self.encoding.name())
        }
    }
}

/// What a slot's key names.
#[derive(Debug, PartialEq, Eq)]
enum Named {
    /// A memory operand `[…]`.
    Memory,
    /// A register: its class letters and its role (`d`, `n`, `dn`, `t`, …,
    /// digits and `+1` dropped).
    Register(String, String),
    /// A ZA array vector group (`ZA.S[<Wv>, …]`, `ZA[<Wv>, …]`).
    Array,
    /// ZT0 or a part of it.
    Table,
    /// A register written as a literal (`X16`).
    Literal(String),
    /// Anything else: immediates, shifts, labels, conditions, names.
    Value,
}

/// The head of a key: up to the first character ending a register name.
fn head(key: &str) -> &str {
    let end = key
        .find(['.', '[', '/', ',', '!', '}', '-', ' ', ']'])
        .unwrap_or(key.len());
    key.get(..end).unwrap_or(key)
}

/// Classifies a slot key.
fn classify(key: &str) -> Named {
    if key.starts_with('[') {
        return Named::Memory;
    }
    let key = key
        .strip_prefix("{, ")
        .or_else(|| key.strip_prefix('{'))
        .or_else(|| key.strip_prefix('('))
        .unwrap_or(key);
    if key.starts_with("ZA.") || key.starts_with("ZA[") {
        return Named::Array;
    }
    if key.starts_with("ZT0") {
        return Named::Table;
    }
    if key.starts_with("ZA0") {
        return Named::Register("ZA".to_owned(), String::new());
    }
    let head = head(key);
    let mut displays = Vec::new();
    let mut literal = String::new();
    let mut rest = head;
    while let Some(start) = rest.find('<') {
        literal.push_str(rest.get(..start).unwrap_or_default());
        let after = rest.get(start + 1..).unwrap_or_default();
        let end = after.find('>').unwrap_or(after.len());
        let display = after.get(..end).unwrap_or_default();
        let display = display.split('|').next().unwrap_or_default();
        if !matches!(display, "HV" | "T") {
            displays.push(display);
        }
        rest = after.get(end + 1..).unwrap_or_default();
    }
    let Some(first) = displays.first() else {
        let is_register = head.len() > 1
            && head.starts_with(['X', 'W'])
            && head
                .get(1..)
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()));
        return if is_register {
            Named::Literal(head.to_owned())
        } else {
            Named::Value
        };
    };
    // `D<d>`, `V<m>`: a class letter written before the display.
    let prefixed = !literal.is_empty() && literal.bytes().all(|b| b.is_ascii_uppercase());
    if !prefixed && !first.starts_with(|c: char| c.is_ascii_uppercase()) {
        return Named::Value;
    }
    let (class, role) = if prefixed {
        (
            literal,
            displays.last().copied().unwrap_or_default().to_owned(),
        )
    } else if let [class, .., role] = displays.as_slice() {
        ((*class).to_owned(), (*role).to_owned())
    } else {
        let split = first
            .find(|c: char| !c.is_ascii_uppercase())
            .unwrap_or(first.len());
        let (class, role) = first.split_at(split);
        (class.to_owned(), role.to_owned())
    };
    let role: String = role.chars().filter(char::is_ascii_lowercase).collect();
    Named::Register(class, role)
}

/// The access of a slot, or an error naming the slot no rule covers.
fn slot_rule(context: &Context<'_>, position: usize, key: &str) -> Result<Rule> {
    for (forms, keys, rule, _) in rules::SLOT_RULES {
        if context.is(forms) && keys.iter().any(|glob| rules::matches_key(glob, key)) {
            return Ok(*rule);
        }
    }
    let unknown = || format!("{}: no access rule for `{key}`", context.form.name);
    let rule = match classify(key) {
        Named::Memory => match context.kind {
            Some("Load" | "LoadExclusive" | "LoadTag" | "Prefetch") => Rule::Read,
            Some("Store" | "StoreExclusive" | "StoreTag") => Rule::Write,
            Some("Atomic") => Rule::ReadWrite,
            _ => return Err(unknown().into()),
        },
        // A ZA tile slice read by MOVA or MOVAZ.
        Named::Register(_, role) if role.is_empty() && position > 0 && context.kind.is_none() => {
            Rule::Read
        }
        Named::Register(_, role) => register_rule(context, key, &role).ok_or_else(unknown)?,
        Named::Array | Named::Table if context.kind.is_some() => {
            transfer(context, key).ok_or_else(unknown)?
        }
        Named::Array if position == 0 => Rule::ReadWrite,
        Named::Table if position == 0 => Rule::Write,
        Named::Array | Named::Table | Named::Value => Rule::Read,
        Named::Literal(_) => return Err(unknown().into()),
    };
    Ok(rule)
}

/// The access of a memory form's transfer operand.
fn transfer(context: &Context<'_>, key: &str) -> Option<Rule> {
    match context.kind? {
        // A single-structure load into one lane keeps the other lanes.
        "Load" if key.contains("}[") => Some(Rule::ReadWrite),
        "Load" | "LoadExclusive" | "LoadTag" | "Atomic" => Some(Rule::Write),
        "Store" | "StoreExclusive" | "StoreTag" => Some(Rule::Read),
        _ => None,
    }
}

/// The access of a register slot by its role.
fn register_rule(context: &Context<'_>, key: &str, role: &str) -> Option<Rule> {
    Some(match role {
        "t" | "" if context.kind.is_some() => transfer(context, key)?,
        "s" if context.kind.is_some() => match context.kind? {
            "Atomic" | "Copy" | "Store" => Rule::Read,
            "StoreExclusive" => Rule::Write,
            _ => return None,
        },
        "d" | "" => destination(context),
        "dn" | "da" | "dm" => Rule::ReadWrite,
        "n" | "m" | "a" | "k" | "g" | "v" | "t" | "s" => Rule::Read,
        _ => return None,
    })
}

/// The access of a destination register.
fn destination(context: &Context<'_>) -> Rule {
    let name = context.encoding.name();
    if rules::READS_DESTINATION
        .iter()
        .any(|(forms, _)| matches(forms, name))
        || context.merging
    {
        return Rule::ReadWrite;
    }
    if let Some((_, fields, _)) = rules::READS_DESTINATION_IF
        .iter()
        .find(|(forms, ..)| matches(forms, name))
    {
        return Rule::ReadWriteIf(fields);
    }
    if context.merging_if_m {
        return Rule::ReadWriteIf(&["M"]);
    }
    Rule::Write
}

/// `Access` code for a rule.
fn access_code(context: &Context<'_>, rule: Rule) -> Result<TokenStream> {
    Ok(match rule {
        Rule::Read => quote! { Access::Read },
        Rule::Write => quote! { Access::Write },
        Rule::ReadWrite => quote! { Access::ReadWrite },
        Rule::ReadWriteIf(fields) => {
            let values = fields
                .iter()
                .map(|field| {
                    let (start, width) = context
                        .encoding
                        .field(field)
                        .ok_or_else(|| format!("{}: no field {field}", context.form.name))?;
                    Ok(extract(start, width))
                })
                .collect::<Result<Vec<_>>>()?;
            quote! { if (#(#values)|*) != 0 { Access::ReadWrite } else { Access::Write } }
        }
    })
}

/// Whether `code` (or a group in it) branches.
fn branches(code: &TokenStream) -> bool {
    code.clone().into_iter().any(|tree| match tree {
        TokenTree::Ident(ident) => ident == "if" || ident == "match",
        TokenTree::Group(group) => branches(&group.stream()),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

/// Whether `tree` is the identifier `name`.
fn is_ident(tree: Option<&TokenTree>, name: &str) -> bool {
    matches!(tree, Some(TokenTree::Ident(ident)) if ident == name)
}

/// Replaces the argument of every `ops.push(…)` in `code` by `access`, and
/// counts them.
fn rewrite(code: TokenStream, access: &TokenStream, pushes: &mut usize) -> TokenStream {
    let trees: Vec<TokenTree> = code.into_iter().collect();
    let mut out = TokenStream::new();
    let mut index = 0;
    while let Some(tree) = trees.get(index) {
        let is_push = is_ident(Some(tree), "ops")
            && matches!(trees.get(index + 1), Some(TokenTree::Punct(p)) if p.as_char() == '.')
            && is_ident(trees.get(index + 2), "push")
            && matches!(
                trees.get(index + 3),
                Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis
            );
        if is_push {
            out.extend(quote! { ops.push(#access) });
            *pushes += 1;
            index += 4;
            continue;
        }
        match tree {
            TokenTree::Group(group) => {
                let mut inner =
                    Group::new(group.delimiter(), rewrite(group.stream(), access, pushes));
                inner.set_span(group.span());
                out.extend([TokenTree::Group(inner)]);
            }
            other @ (TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_)) => {
                out.extend([other.clone()]);
            }
        }
        index += 1;
    }
    prune(out)
}

/// Turns `if let Some(name) = value { body }` whose body no longer uses
/// `name` into `if (value).is_some() { body }`.
fn unbind(trees: &[TokenTree]) -> Vec<TokenTree> {
    let mut out = Vec::new();
    let mut index = 0;
    while let Some(tree) = trees.get(index) {
        let binding = is_ident(Some(tree), "if")
            && is_ident(trees.get(index + 1), "let")
            && is_ident(trees.get(index + 2), "Some")
            && matches!(trees.get(index + 4), Some(TokenTree::Punct(p)) if p.as_char() == '=');
        let body = trees
            .iter()
            .skip(index + 5)
            .position(|t| matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace))
            .map(|position| position + index + 5);
        if binding
            && let Some(TokenTree::Group(name)) = trees.get(index + 3)
            && let Some(body) = body
            && let Some(TokenTree::Group(block)) = trees.get(body)
            && !uses(&block.stream(), &name.stream().to_string())
        {
            let value: TokenStream = trees
                .get(index + 5..body)
                .unwrap_or_default()
                .iter()
                .cloned()
                .collect();
            out.extend(quote! { if (#value).is_some() });
            index = body;
            continue;
        }
        out.push(tree.clone());
        index += 1;
    }
    out
}

/// Drops `let` statements whose variable the rest of the block no longer
/// uses (the operand values the pushes used to take), and the bindings of
/// `if let` that no longer use theirs.
fn prune(code: TokenStream) -> TokenStream {
    let trees: Vec<TokenTree> = code.into_iter().collect();
    let trees = unbind(&trees);
    let mut statements: Vec<Vec<TokenTree>> = vec![Vec::new()];
    for tree in trees {
        let end = matches!(&tree, TokenTree::Punct(p) if p.as_char() == ';');
        if let Some(last) = statements.last_mut() {
            last.push(tree);
        }
        if end {
            statements.push(Vec::new());
        }
    }
    let mut kept: Vec<Vec<TokenTree>> = Vec::new();
    for (index, statement) in statements.iter().enumerate() {
        if is_ident(statement.first(), "let")
            && let Some(TokenTree::Ident(name)) = statement.get(1)
        {
            let name = name.to_string();
            let used = statements
                .iter()
                .skip(index + 1)
                .any(|later| uses(&later.iter().cloned().collect(), &name));
            if !used {
                continue;
            }
        }
        kept.push(statement.clone());
    }
    kept.into_iter().flatten().collect()
}

/// Whether `code` mentions the identifier `name`.
fn uses(code: &TokenStream, name: &str) -> bool {
    code.clone().into_iter().any(|tree| match tree {
        TokenTree::Ident(ident) => ident == name,
        TokenTree::Group(group) => uses(&group.stream(), name),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

/// The access code of one form.
fn form_access(context: &Context<'_>, syntax: &Syntax) -> Result<TokenStream> {
    let mut code = TokenStream::new();
    let mut registers: Vec<&str> = Vec::new();
    for (position, (key, slot)) in syntax.slots.iter().enumerate() {
        let mut rule = slot_rule(context, position, key)?;
        if let Named::Register(..) = classify(key) {
            let name = head(key);
            // A register Arm writes twice (`AESE <Zdn>.B, <Zdn>.B, <Zm>.B`)
            // is one operand tied to another: the second is the source.
            if registers.contains(&name) {
                rule = Rule::Read;
            }
            registers.push(name);
        }
        let access = access_code(context, rule)?;
        let mut pushes = 0;
        let rewritten = rewrite(slot.clone(), &access, &mut pushes);
        if branches(slot) {
            code.extend(rewritten);
        } else {
            // Straight-line code pushes the same operands for every word.
            for _ in 0..pushes {
                code.extend(quote! { ops.push(#access); });
            }
        }
    }
    Ok(code)
}

/// Match arms by code: the code and the patterns sharing it.
type Arms = BTreeMap<String, (TokenStream, Vec<TokenStream>)>;

/// Adds `pattern` to the arm with `code`.
fn add_arm(arms: &mut Arms, code: TokenStream, pattern: TokenStream) {
    arms.entry(code.to_string())
        .or_insert_with(|| (code, Vec::new()))
        .1
        .push(pattern);
}

/// The arms of the four generated functions, and the rules found missing.
#[derive(Default)]
struct Generated {
    access: Arms,
    memory: Arms,
    implicit: Arms,
    flags: Arms,
    errors: Vec<String>,
}

impl Generated {
    /// Adds `code` to `arms` under `pattern`, or records the error.
    fn add(
        errors: &mut Vec<String>,
        arms: &mut Arms,
        code: Result<Option<TokenStream>>,
        pattern: TokenStream,
    ) {
        match code {
            Ok(Some(code)) if !code.is_empty() => add_arm(arms, code, pattern),
            Ok(_) => {}
            Err(error) => errors.push(error.to_string()),
        }
    }

    /// Adds the arms of one encoding and its aliases.
    fn encoding(
        &mut self,
        encoding: &Encoding<'_>,
        package: &Package,
        missing: &mut Missing,
    ) -> Result<()> {
        let path: Vec<&str> = encoding.groups.iter().map(|g| g.name.as_str()).collect();
        let path = path.join("/");
        let variant = encoding_ident(encoding.name())?;
        let mut kind = None;
        for (index, (form, alias)) in forms(encoding, &path)?.iter().enumerate() {
            let Some(syntax) = form.syntax(&package.assembly_rules, missing)? else {
                continue;
            };
            if index == 0 {
                kind = memory_kind(encoding, &path, &syntax).unwrap_or_else(|error| {
                    self.errors.push(error.to_string());
                    None
                });
                let code = kind
                    .map(|kind| memory_code(encoding, &path, &syntax, kind))
                    .transpose();
                Self::add(
                    &mut self.errors,
                    &mut self.memory,
                    code,
                    quote! { Encoding::#variant },
                );
            }
            let context = Context {
                encoding,
                form,
                kind,
                merging: syntax.slots.iter().any(|(key, _)| key.ends_with("/M")),
                merging_if_m: syntax.slots.iter().any(|(key, _)| key.ends_with("/<ZM>")),
            };
            let alias = lit(*alias);
            Self::add(
                &mut self.errors,
                &mut self.access,
                form_access(&context, &syntax).map(Some),
                quote! { (Encoding::#variant, #alias) },
            );
        }
        let pattern = quote! { Encoding::#variant };
        Self::add(
            &mut self.errors,
            &mut self.implicit,
            implicit_code(encoding),
            pattern.clone(),
        );
        Self::add(
            &mut self.errors,
            &mut self.flags,
            flags_code(encoding),
            pattern,
        );
        Ok(())
    }
}

/// An encoding's forms: its own syntax (alias 0) and its aliases, numbered
/// as `syntax.rs` numbers them.
fn forms<'a>(encoding: &Encoding<'a>, path: &'a str) -> Result<Vec<(Form<'a>, u8)>> {
    let instruction = encoding.instruction;
    let mut forms = vec![(
        Form {
            name: encoding.name().to_owned(),
            path,
            instruction,
            assembly: &instruction.assembly,
            encoded_in: &instruction.encoded_in,
        },
        0u8,
    )];
    for alias in aliases::ordered(encoding.name(), &instruction.aliases) {
        let number = instruction
            .aliases
            .iter()
            .position(|other| std::ptr::eq(other, alias))
            .map_or(0, |i| i + 1);
        forms.push((
            Form {
                name: format!("{}__{}", encoding.name(), alias.name),
                path,
                instruction,
                assembly: &alias.assembly,
                encoded_in: &alias.encoded_in,
            },
            u8::try_from(number)?,
        ));
    }
    Ok(forms)
}

/// Generates `access.rs`.
pub fn generate(encodings: &[Encoding<'_>], package: &Package) -> Result<GeneratedFile> {
    let mut missing = Missing::default();
    let mut generated = Generated::default();
    for encoding in encodings {
        generated.encoding(encoding, package, &mut missing)?;
    }
    missing.check()?;
    if !generated.errors.is_empty() {
        return Err(format!(
            "{} access rules missing:\n  {}",
            generated.errors.len(),
            generated.errors.join("\n  ")
        )
        .into());
    }
    Ok(file(&generated))
}

/// The memory access kind of an encoding, from its own syntax: `None`
/// without a memory operand.
fn memory_kind(
    encoding: &Encoding<'_>,
    path: &str,
    syntax: &Syntax,
) -> Result<Option<&'static str>> {
    let name = encoding.name();
    let memory =
        syntax.slots.iter().any(|(key, _)| key.starts_with('[')) || path.ends_with("/loadlit");
    // SVE ADR writes its vector address operand `[<Zn>.<T>, <Zm>.<T>…]`
    // like a memory operand but only computes the addresses.
    if !memory || matches("*/sve_int_adr/*", path) {
        return Ok(None);
    }
    let (_, kind, _) = rules::MEMORY_KINDS
        .iter()
        .find(|(forms, _, _)| matches(forms, name))
        .ok_or_else(|| format!("{name}: memory operand without a memory kind rule"))?;
    let kind = KINDS
        .iter()
        .find(|k| *k == kind)
        .ok_or_else(|| format!("unknown memory kind {kind}"))?;
    Ok(Some(kind))
}

/// Bytes of one register of class `class`.
fn register_bytes(class: &str) -> Option<u32> {
    Some(match class {
        "B" => 1,
        "H" => 2,
        "W" | "S" => 4,
        "X" | "D" => 8,
        "Q" => 16,
        _ => return None,
    })
}

/// The `MemoryAccess` code of a memory encoding.
fn memory_code(
    encoding: &Encoding<'_>,
    path: &str,
    syntax: &Syntax,
    kind: &str,
) -> Result<TokenStream> {
    let name = encoding.name();
    let size = memory_size(encoding, path, syntax)
        .ok_or_else(|| format!("{name}: no rule for the memory access size"))?;
    let kind = proc_macro2::Ident::new(kind, proc_macro2::Span::call_site());
    Ok(quote! { Some(MemoryAccess { kind: MemoryKind::#kind, size: #size }) })
}

/// The access size code of a memory encoding.
fn memory_size(encoding: &Encoding<'_>, path: &str, syntax: &Syntax) -> Option<TokenStream> {
    let name = encoding.name();
    if let Some((_, size, _)) = rules::MEMORY_SIZES
        .iter()
        .find(|(forms, ..)| matches(forms, name))
    {
        let size = lit(*size);
        return Some(quote! { #size });
    }
    if matches(rules::MEMORY_UNSIZED, name) || matches(rules::VECTOR_LENGTH_GROUPS, path) {
        return Some(quote! { 0 });
    }
    structure_size(encoding, path, syntax).or_else(|| register_size(encoding, syntax))
}

/// The access size of an Advanced SIMD structure load or store: the
/// registers of the list, the lane of each, or one element of each.
fn structure_size(encoding: &Encoding<'_>, path: &str, syntax: &Syntax) -> Option<TokenStream> {
    let (key, _) = syntax
        .slots
        .iter()
        .find(|(key, _)| key.starts_with("{<Vt>"))?;
    let count = u32::try_from(key.matches("<Vt").count()).ok()?;
    if key.contains("}[") {
        let element = key.split('.').nth(1)?.chars().next()?;
        let bytes = register_bytes(&element.to_string())?;
        let size = lit(count * bytes);
        return Some(quote! { #size });
    }
    if matches("*/asisdlse*", path) {
        let (start, width) = encoding.field("Q")?;
        let q = extract(start, width);
        let count = lit(count * 8);
        return Some(quote! { #count << #q });
    }
    let (start, width) = encoding.field("size")?;
    let size = extract(start, width);
    let count = lit(count);
    Some(quote! { #count << #size })
}

/// The access size of a load or store of general or SIMD&FP registers: the
/// transfer registers' bytes, a general register narrowed to the
/// encoding's fixed `size` field.
fn register_size(encoding: &Encoding<'_>, syntax: &Syntax) -> Option<TokenStream> {
    let registers = |wanted: &str| -> Vec<String> {
        syntax
            .slots
            .iter()
            .filter_map(|(key, _)| match classify(key) {
                Named::Register(class, role) if role == wanted => Some(class),
                Named::Register(..)
                | Named::Memory
                | Named::Array
                | Named::Table
                | Named::Literal(_)
                | Named::Value => None,
            })
            .collect()
    };
    let mut transfer = registers("t");
    if transfer.is_empty() {
        transfer = registers("s");
    }
    let fixed_size = encoding
        .instruction
        .encoding
        .fields
        .iter()
        .find(|f| f.name.as_deref() == Some("size") && f.value.mask() == (1 << f.width) - 1)
        .map(|f| 1u32 << f.value.value());
    let mut total = 0;
    for class in &transfer {
        let bytes = register_bytes(class)?;
        total += match (class.as_str(), fixed_size) {
            ("W" | "X", Some(size)) => size,
            _ => bytes,
        };
    }
    (total > 0).then(|| {
        let total = lit(total);
        quote! { #total }
    })
}

/// A register named in `rules::IMPLICIT`.
fn implicit_register(name: &str) -> Result<TokenStream> {
    let known = matches!(name, "SP" | "FFR")
        || name
            .strip_prefix('X')
            .and_then(|n| n.parse::<u8>().ok())
            .is_some_and(|n| n < 31);
    if !known {
        return Err(format!("unknown implicit register {name}").into());
    }
    let name = proc_macro2::Ident::new(name, proc_macro2::Span::call_site());
    Ok(quote! { #name })
}

/// The constants of the registers `rules::IMPLICIT` names.
fn register_constants() -> TokenStream {
    let mut numbers: Vec<u8> = rules::IMPLICIT
        .iter()
        .flat_map(|(_, _, reads, writes, _)| reads.iter().chain(writes.iter()))
        .filter_map(|name| name.strip_prefix('X')?.parse().ok())
        .collect();
    numbers.sort_unstable();
    numbers.dedup();
    numbers
        .into_iter()
        .map(|number| {
            let name =
                proc_macro2::Ident::new(&format!("X{number}"), proc_macro2::Span::call_site());
            let number = lit(number);
            quote! {
                const #name: Register = Register::new(RegisterClass::X, #number);
            }
        })
        .collect()
}

/// A run of general registers after a field, `X(Rt+1..Rt+7)`: a slice of
/// `X_REGISTERS`.
fn register_run(encoding: &Encoding<'_>, run: &str) -> Result<Option<TokenStream>> {
    let Some(inner) = run.strip_prefix("X(").and_then(|r| r.strip_suffix(')')) else {
        return Ok(None);
    };
    let parse = |bound: &str| -> Result<(String, u32)> {
        let (field, offset) = bound
            .split_once('+')
            .ok_or_else(|| format!("bad register run {run}"))?;
        Ok((field.to_owned(), offset.parse()?))
    };
    let (first, last) = inner
        .split_once("..")
        .ok_or_else(|| format!("bad register run {run}"))?;
    let ((field, first), (other, last)) = (parse(first)?, parse(last)?);
    if field != other {
        return Err(format!("bad register run {run}").into());
    }
    let (start, width) = encoding
        .field(&field)
        .ok_or_else(|| format!("{}: no field {field}", encoding.name()))?;
    let value = extract(start, width);
    let (first, end) = (lit(first), lit(last + 1));
    Ok(Some(quote! {
        X_REGISTERS.get((#value + #first) as usize..(#value + #end) as usize).unwrap_or(&[])
    }))
}

/// The code of a list of `rules::IMPLICIT` registers.
fn implicit_list(encoding: &Encoding<'_>, names: &[&str]) -> Result<TokenStream> {
    if let [run] = names
        && let Some(code) = register_run(encoding, run)?
    {
        return Ok(code);
    }
    let registers = names
        .iter()
        .map(|r| implicit_register(r))
        .collect::<Result<Vec<_>>>()?;
    Ok(quote! { &[#(#registers),*] })
}

/// The `Implicit` code of an encoding, if it uses registers it does not name.
fn implicit_code(encoding: &Encoding<'_>) -> Result<Option<TokenStream>> {
    let name = encoding.name();
    let Some((_, condition, reads, writes, _)) = rules::IMPLICIT
        .iter()
        .find(|(forms, ..)| matches(forms, name))
    else {
        return Ok(None);
    };
    let reads = implicit_list(encoding, reads)?;
    let writes = implicit_list(encoding, writes)?;
    let value = quote! { Implicit { reads: #reads, writes: #writes } };
    if *condition == "true" {
        return Ok(Some(value));
    }
    let (field, equal) = condition
        .split_once(" == ")
        .ok_or_else(|| format!("{name}: bad implicit condition {condition}"))?;
    let (start, width) = encoding
        .field(field)
        .ok_or_else(|| format!("{name}: no field {field}"))?;
    let field = extract(start, width);
    let equal: u64 = equal.parse()?;
    let equal = lit(equal);
    Ok(Some(
        quote! { if #field == #equal { #value } else { Implicit::NONE } },
    ))
}

/// A `FlagSet` of the letters N, Z, C, V.
fn flag_set(letters: &str) -> Option<TokenStream> {
    let mut bits = 0u8;
    for letter in letters.chars() {
        bits |= match letter {
            'N' => 8,
            'Z' => 4,
            'C' => 2,
            'V' => 1,
            _ => return None,
        };
    }
    let bits = lit(bits);
    Some(quote! { FlagSet::from_bits(#bits) })
}

/// `op0:op1:CRn:CRm:op2` of NZCV in bits 19:5 of MRS and MSR.
const NZCV: u32 = 0x5a10;

/// The `Flags` code of an encoding, if it reads or writes the flags.
fn flags_code(encoding: &Encoding<'_>) -> Result<Option<TokenStream>> {
    let name = encoding.name();
    let rule = rules::FLAGS.iter().find(|(forms, ..)| matches(forms, name));
    let condition = encoding.field("cond");
    if rule.is_none() && condition.is_none() {
        return Ok(None);
    }
    let (read, written) = rule.map_or(("", ""), |(_, read, written, _)| (*read, *written));
    let nzcv = lit(NZCV);
    let side = |text: &str| -> Result<TokenStream> {
        Ok(match text {
            "nzcv" => quote! {
                if ((word >> 5) & 0x7fff) == #nzcv { FlagSet::NZCV } else { FlagSet::NONE }
            },
            "mask" => quote! { FlagSet::from_bits((word & 15) as u8) },
            letters => flag_set(letters).ok_or_else(|| format!("{name}: bad flags {letters}"))?,
        })
    };
    let mut read = side(read)?;
    if let Some((start, width)) = condition {
        let cond = extract(start, width);
        read = quote! { #read.union(FlagSet::tested_by(#cond as u8)) };
    }
    let written = side(written)?;
    Ok(Some(quote! { Flags { read: #read, written: #written } }))
}

/// The module.
fn file(generated: &Generated) -> GeneratedFile {
    let access = generated
        .access
        .values()
        .map(|(code, patterns)| quote! { #(#patterns)|* => { #code } });
    let arm =
        |(code, patterns): &(TokenStream, Vec<TokenStream>)| quote! { #(#patterns)|* => #code, };
    let memory = generated.memory.values().map(arm);
    let implicit = generated.implicit.values().map(arm);
    let flags = generated.flags.values().map(arm);
    let constants = register_constants();
    let x_registers = (0..32u8).map(|n| {
        let n = lit(n);
        quote! { Register::new(RegisterClass::X, #n) }
    });
    let tokens = quote! {
        use super::encoding::Encoding;
        use super::sysreg;
        use crate::access::{Access, Accesses, FlagSet, Flags, Implicit, MemoryAccess, MemoryKind};
        use crate::operand::{Register, RegisterClass};

        /// The stack pointer.
        const SP: Register = Register::new(RegisterClass::Xsp, 31);
        /// The SVE first-fault register.
        const FFR: Register = Register::new(RegisterClass::Ffr, 0);
        #constants
        /// The general registers, `X_REGISTERS[n]` being `xn` (31: `xzr`).
        static X_REGISTERS: [Register; 32] = [#(#x_registers),*];

        /// Pushes the access of each operand of alias `alias` of `encoding`
        /// for `word`, as `syntax::operands` pushes the operands.
        pub fn access(encoding: Encoding, alias: u8, word: u32, ops: &mut Accesses) {
            match (encoding, alias) {
                #(#access)*
                _ => {}
            }
        }

        /// The memory access of `encoding`, `None` if it accesses none.
        pub fn memory(encoding: Encoding, word: u32) -> Option<MemoryAccess> {
            match encoding {
                #(#memory)*
                _ => None,
            }
        }

        /// The registers `encoding` uses without naming them.
        pub fn implicit(encoding: Encoding, word: u32) -> Implicit {
            match encoding {
                #(#implicit)*
                _ => Implicit::NONE,
            }
        }

        /// The condition flags `encoding` reads and writes.
        pub fn flags(encoding: Encoding, word: u32) -> Flags {
            match encoding {
                #(#flags)*
                _ => Flags::NONE,
            }
        }
    };
    GeneratedFile {
        path: output("access"),
        notice: AARCHMRS_NOTICE,
        docs: vec![
            "Operand access, memory accesses, implicit registers and condition flags".to_owned(),
            "of the A64 forms (`xtask/src/aarch64/access`).".to_owned(),
        ],
        tokens,
    }
}
