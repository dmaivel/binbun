//! syzkaller's syscall descriptions (syzlang): semantic parameter types
//! for system calls, such as `mmap`'s `prot` being the flag set
//! `mmap_prot` rather than an `int`.
//!
//! Flag sets become flag enumerations (`flags mmap_prot`), structures and
//! unions records (without layouts: syzlang does not give them), resources
//! (`resource fd[int32]`) and plain type aliases (`type signalno
//! int32[0:65]`) typedefs, so a file descriptor stays an `fd`. Types the
//! generator does not model (templates, `proc`, `bool8`) are opaque. A
//! call's variants (`openat$dir`) are folded into its widest form (the most
//! parameters: the plain form if it is among them, else the first declared),
//! so its parameters are every argument the kernel may read: `ptrace`'s
//! plain form takes 2, its variants 4; `fcntl$getflags` 2, `fcntl` 3.
//!
//! A call's number is the kernel's (`__NR_name` in the target's
//! `asm/unistd_64.h`, [`numbers`]); variants share their call's. A call
//! the table does not have (syzkaller's pseudo-calls `syz_*`, another
//! architecture's) has none.
//!
//! Flag values are only known with `resolve`, which compiles and runs a C
//! probe that includes the descriptions' headers: use it only on trusted
//! descriptions. A probe built for another architecture (`$CC` a cross
//! compiler) runs under the `probe_runner` given, an emulator such as
//! `qemu-aarch64`, so the values are that architecture's headers'.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;
use std::str::Lines;
use std::{env, fs};

use binbun_typedb::database::{Definition, Function, Target, TypeRef};
use binbun_typedb::types::{Enum, Field, Opaque, Param, Record, Signature, Typedef, Variant};

use crate::Declarations;

/// What the description files define, before conversion.
#[derive(Debug, Default)]
struct Descriptions {
    includes: Vec<String>,
    flag_sets: BTreeMap<String, Vec<String>>,
    /// Resources and plain type aliases: the type each names.
    aliases: BTreeMap<String, SyzType>,
    syscalls: Vec<Syscall>,
    /// Structures and unions by name; one declared twice keeps its first
    /// definition.
    composites: BTreeMap<String, Composite>,
}

#[derive(Debug)]
struct Syscall {
    name: String,
    /// Whether this is a variant (`openat$dir`), not the plain form.
    variant: bool,
    params: Vec<(String, SyzType)>,
    ret: Option<String>,
}

#[derive(Debug)]
struct Composite {
    name: String,
    union: bool,
    fields: Vec<(String, SyzType)>,
}

#[derive(Clone, Debug)]
enum SyzType {
    Int(u8),
    IntPtr,
    Flags(String),
    Const,
    Ptr(Box<SyzType>),
    Buffer,
    Vma,
    Filename,
    Len,
    Array(Box<SyzType>, Option<u64>),
    Named(String),
    Void,
}

/// The parser's options.
#[derive(Clone, Debug)]
pub struct Options<'a> {
    /// The target, for pointer-sized integers and `char`.
    pub target: &'a Target,
    /// Whether flag values are resolved by compiling and running a probe.
    pub resolve: bool,
    /// Includes skipped when resolving, by substring (kernel-internal
    /// headers that do not compile in user space).
    pub skip_includes: &'a [String],
    /// The program the probe is run with (`PROGRAM probe`), if any.
    pub probe_runner: Option<&'a str>,
    /// The system call numbers of the target, by name ([`numbers`]).
    pub numbers: &'a BTreeMap<String, u64>,
}

/// The system call numbers a kernel UAPI header defines (`#define
/// __NR_read 0`, as `asm/unistd_64.h` does), by name. Definitions in terms
/// of other macros (`asm-generic/unistd.h`'s `__NR3264_fcntl`) are not
/// read: give the generated per-architecture table.
///
/// # Errors
///
/// If a name is defined twice with different numbers.
pub fn numbers(header: &str) -> Result<BTreeMap<String, u64>, String> {
    let mut numbers = BTreeMap::new();
    for line in header.lines() {
        let mut words = line.split_whitespace();
        let (Some("#define"), Some(macro_name), Some(value), None) =
            (words.next(), words.next(), words.next(), words.next())
        else {
            continue;
        };
        let (Some(name), Ok(number)) = (macro_name.strip_prefix("__NR_"), value.parse::<u64>())
        else {
            continue;
        };
        if let Some(old) = numbers.insert(name.to_owned(), number)
            && old != number
        {
            return Err(format!("__NR_{name} is both {old} and {number}"));
        }
    }
    Ok(numbers)
}

/// Parses the description files `paths`.
///
/// # Errors
///
/// If a file cannot be read, or the probe resolving flag values cannot be
/// built or run.
pub fn parse(paths: &[&Path], options: &Options<'_>) -> Result<Declarations, String> {
    let descriptions = read(paths)?;
    // Numbers are their own values; names only with the probe.
    let mut values: BTreeMap<String, i128> = descriptions
        .flag_sets
        .values()
        .flatten()
        .filter_map(|constant| Some((constant.clone(), number(constant)?)))
        .collect();
    if options.resolve {
        values.extend(resolve_constant_values(
            &descriptions.includes,
            &descriptions.flag_sets,
            options.skip_includes,
            options.probe_runner,
        )?);
    }
    convert(&descriptions, &values, options.target, options.numbers)
}

/// The description files `paths`, with flag sets expanded.
fn read(paths: &[&Path]) -> Result<Descriptions, String> {
    let mut descriptions = Descriptions::default();
    for path in paths {
        let content =
            fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        parse_file(&content, &mut descriptions);
    }
    resolve_flag_refs(&mut descriptions.flag_sets);
    // Sets of strings (`devnames = "lo", "tunl0"`) name no integers.
    descriptions
        .flag_sets
        .retain(|_, constants| !constants.iter().all(|constant| constant.starts_with('"')));
    for constants in descriptions.flag_sets.values_mut() {
        let mut seen = BTreeSet::new();
        constants.retain(|constant| seen.insert(constant.clone()));
    }
    Ok(descriptions)
}

/// The declarations of `descriptions`, with flag `values` and system call
/// `numbers`.
fn convert(
    descriptions: &Descriptions,
    values: &BTreeMap<String, i128>,
    target: &Target,
    numbers: &BTreeMap<String, u64>,
) -> Result<Declarations, String> {
    let mut converter = Converter {
        target,
        descriptions,
        opaque: BTreeSet::new(),
    };
    let mut declarations = Declarations::default();
    for (name, constants) in &descriptions.flag_sets {
        declarations.define(Definition::Enum(Enum {
            key: format!("flags {name}"),
            name: Some(name.clone()),
            size: None,
            flags: true,
            variants: constants
                .iter()
                .map(|constant| Variant {
                    name: constant.clone(),
                    value: values.get(constant).copied(),
                })
                .collect(),
        }))?;
    }
    for (name, ty) in &descriptions.aliases {
        let target = converter.convert(ty);
        declarations.define(Definition::Typedef(Typedef {
            key: name.clone(),
            name: name.clone(),
            target,
        }))?;
    }
    for composite in descriptions.composites.values() {
        let record = Record {
            key: composite_key(composite),
            name: Some(composite.name.clone()),
            union: composite.union,
            size: None,
            align: None,
            fields: Some(
                composite
                    .fields
                    .iter()
                    .map(|(name, ty)| Field {
                        name: Some(name.clone()),
                        ty: converter.convert(ty),
                        bit_offset: None,
                        bit_width: None,
                    })
                    .collect(),
            ),
        };
        declarations.define(Definition::Record(record))?;
    }
    // Each call once: its widest form, the plain one (`openat`) among
    // equals, else the first declared (`openat$dir`).
    let mut chosen: BTreeMap<&str, &Syscall> = BTreeMap::new();
    for syscall in &descriptions.syscalls {
        chosen
            .entry(syscall.name.as_str())
            .and_modify(|old| {
                let wider = syscall.params.len() > old.params.len();
                let plain =
                    syscall.params.len() == old.params.len() && old.variant && !syscall.variant;
                if wider || plain {
                    *old = syscall;
                }
            })
            .or_insert(syscall);
    }
    for syscall in chosen.into_values() {
        let signature = Signature {
            ret: converter.ret(syscall.ret.as_deref()),
            params: syscall
                .params
                .iter()
                .enumerate()
                .map(|(index, (name, ty))| Param {
                    name: Some(name.clone()),
                    ty: converter.convert(&folded(descriptions, &syscall.name, index, ty)),
                })
                .collect(),
            variadic: false,
            convention: None,
        };
        declarations.functions.push(Function {
            name: syscall.name.clone(),
            library: None,
            signature,
            // syzlang states no such attribute.
            no_return: false,
            no_throw: false,
            format: None,
            format_arg: Vec::new(),
            alloc_size: None,
            number: numbers.get(&syscall.name).copied(),
        });
    }
    for name in converter.opaque {
        declarations.define(Definition::Opaque(Opaque {
            key: name.clone(),
            name,
        }))?;
    }
    Ok(declarations)
}

/// The type of parameter `index` of call `name`, `ty` in the form
/// chosen, as all its forms (`openat`, `openat$dir`) fold into one: a flag
/// set only where no form gives the parameter another set or a value of
/// another kind (a pointer, a resource); otherwise the forms put other
/// things there than the set holds (`fcntl$dupfd`'s `cmd`, two of
/// `fcntl`'s many commands), so the parameter is a plain integer. A form
/// passing a constant or a plain integer there narrows the call
/// (`openat$…`'s `const[O_WRONLY]`, `const[O_RDONLY]` 0 the set leaves
/// out) and leaves the set.
fn folded(descriptions: &Descriptions, name: &str, index: usize, ty: &SyzType) -> SyzType {
    let SyzType::Flags(set) = ty else {
        return ty.clone();
    };
    if !descriptions.flag_sets.contains_key(set) {
        return ty.clone();
    }
    let agree = descriptions
        .syscalls
        .iter()
        .filter(|form| form.name == name)
        .filter_map(|form| form.params.get(index))
        .all(|(_, other)| match other {
            SyzType::Flags(other) => other == set,
            SyzType::Const | SyzType::Int(_) | SyzType::IntPtr | SyzType::Len => true,
            SyzType::Ptr(_)
            | SyzType::Buffer
            | SyzType::Vma
            | SyzType::Filename
            | SyzType::Array(..)
            | SyzType::Named(_)
            | SyzType::Void => false,
        });
    if agree { ty.clone() } else { SyzType::IntPtr }
}

struct Converter<'a> {
    target: &'a Target,
    descriptions: &'a Descriptions,
    /// The names referred to but not defined.
    opaque: BTreeSet<String>,
}

fn composite_key(composite: &Composite) -> String {
    let kind = if composite.union { "union" } else { "struct" };
    format!("{kind} {}", composite.name)
}

impl Converter<'_> {
    fn int(&self, signed: bool) -> TypeRef {
        TypeRef::Int {
            signed,
            size: self.target.pointer_size,
        }
    }

    fn convert(&mut self, ty: &SyzType) -> TypeRef {
        match ty {
            &SyzType::Int(size) => TypeRef::Int { signed: true, size },
            SyzType::IntPtr => self.int(true),
            SyzType::Flags(name) => {
                if self.descriptions.flag_sets.contains_key(name) {
                    TypeRef::Named(format!("flags {name}"))
                } else {
                    self.named(name)
                }
            }
            SyzType::Const => TypeRef::Int {
                signed: true,
                size: 4,
            },
            SyzType::Ptr(inner) => TypeRef::Pointer(Box::new(self.convert(inner))),
            SyzType::Buffer | SyzType::Vma => TypeRef::Pointer(Box::new(TypeRef::Void)),
            SyzType::Filename => TypeRef::Pointer(Box::new(TypeRef::Char {
                signed: char_is_signed(&self.target.arch),
            })),
            SyzType::Len => self.int(false),
            SyzType::Array(inner, count) => TypeRef::Array {
                element: Box::new(self.convert(inner)),
                count: *count,
            },
            SyzType::Named(name) => self.named(name),
            SyzType::Void => TypeRef::Void,
        }
    }

    /// A name: a resource or alias, a structure or union, a flag set, or
    /// an opaque type.
    fn named(&mut self, name: &str) -> TypeRef {
        let descriptions = self.descriptions;
        if descriptions.aliases.contains_key(name) {
            return TypeRef::Named(name.to_owned());
        }
        if let Some(composite) = descriptions.composites.get(name) {
            return TypeRef::Named(composite_key(composite));
        }
        if descriptions.flag_sets.contains_key(name) {
            return TypeRef::Named(format!("flags {name}"));
        }
        self.opaque.insert(name.to_owned());
        TypeRef::Named(name.to_owned())
    }

    /// A call's return type: its resource, a pointer for an address
    /// (`vma`), else a pointer-sized integer.
    fn ret(&mut self, ret: Option<&str>) -> TypeRef {
        match ret {
            Some(name) if self.descriptions.aliases.contains_key(name) => {
                TypeRef::Named(name.to_owned())
            }
            Some("vma" | "vma64") => TypeRef::Pointer(Box::new(TypeRef::Void)),
            Some(_) | None => self.int(true),
        }
    }
}

/// Whether plain `char` is signed on `arch` (it is not on Arm and
/// AArch64).
fn char_is_signed(arch: &str) -> bool {
    !matches!(arch, "aarch64" | "arm" | "arm64")
}

fn parse_file(content: &str, descriptions: &mut Descriptions) {
    let mut lines = content.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("define ") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("include <") {
            if let Some(header) = rest.strip_suffix('>') {
                descriptions.includes.push(header.to_owned());
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("resource ") {
            // `resource fd_dir[fd]: AT_FDCWD`
            if let Some((name, base)) = rest.split_once('[')
                && let Some((base, _)) = base.split_once(']')
            {
                descriptions
                    .aliases
                    .insert(name.trim().to_owned(), parse_type(base));
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("type ") {
            if line.ends_with('{') {
                skip_block(&mut lines, '}');
            } else if line.ends_with('[') {
                skip_block(&mut lines, ']');
            } else if let Some((name, body)) = rest.split_once(char::is_whitespace)
                && !name.contains('[')
            {
                // A plain alias; templates (`type foo[T] …`) are not
                // modelled.
                descriptions
                    .aliases
                    .insert(name.to_owned(), parse_type(body));
            }
            continue;
        }
        if !line.contains('=') && !line.contains('(') {
            for (open, close, union) in [('{', '}', false), ('[', ']', true)] {
                if let Some(name) = line.strip_suffix(open) {
                    let name = name.trim().to_owned();
                    let fields = parse_composite_body(&mut lines, close);
                    descriptions
                        .composites
                        .entry(name.clone())
                        .or_insert(Composite {
                            name,
                            union,
                            fields,
                        });
                }
            }
            continue;
        }
        if let Some((name, constants)) = line.split_once('=') {
            // `_ = __NR_mmap2, …` lists constants syzkaller should know
            // of; it is not a flag set.
            if !name.contains('(') && name.trim() != "_" {
                let constants: Vec<String> = constants
                    .split(',')
                    .map(|constant| constant.trim().to_owned())
                    .filter(|constant| !constant.is_empty())
                    .collect();
                if !constants.is_empty() {
                    descriptions
                        .flag_sets
                        .insert(name.trim().to_owned(), constants);
                }
                continue;
            }
        }
        if let Some(syscall) = parse_syscall(line) {
            descriptions.syscalls.push(syscall);
        }
    }
}

fn skip_block(lines: &mut Lines<'_>, close: char) {
    for line in lines.by_ref() {
        if line.trim().starts_with(close) {
            return;
        }
    }
}

fn parse_composite_body(lines: &mut Lines<'_>, close: char) -> Vec<(String, SyzType)> {
    let mut fields = Vec::new();
    for line in lines.by_ref() {
        let line = line.trim();
        if line.starts_with(close) {
            break;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, ty)) = line.split_once(['\t', ' ']) {
            fields.push((name.trim().to_owned(), parse_type(strip_attributes(ty))));
        }
    }
    fields
}

/// A field's type without its attributes (`int32\t(out)`,
/// `bpf_link_id\t(if[value[flags] & X])`): what precedes the first `(`
/// outside brackets.
fn strip_attributes(ty: &str) -> &str {
    let mut depth = 0i32;
    for (i, c) in ty.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            '(' if depth == 0 => return ty.get(..i).unwrap_or(ty).trim(),
            _ => {}
        }
    }
    ty.trim()
}

/// `name$variant(param type, …) ret`.
fn parse_syscall(line: &str) -> Option<Syscall> {
    let (raw_name, after) = line.split_once('(')?;
    let (name, variant) = match raw_name.split_once('$') {
        Some((name, _)) => (name.to_owned(), true),
        None => (raw_name.to_owned(), false),
    };
    let close = find_close(after)?;
    let (params, tail) = after.split_at(close);
    let tail = tail.get(1..).unwrap_or("").trim();
    let ret = tail
        .split('(')
        .next()
        .map(str::trim)
        .filter(|ret| !ret.is_empty())
        .map(str::to_owned);
    let mut parsed = Vec::new();
    if !params.trim().is_empty() {
        for param in split_top_level(params) {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }
            let (name, ty) = param.split_once(char::is_whitespace)?;
            parsed.push((name.trim().to_owned(), parse_type(ty)));
        }
    }
    Some(Syscall {
        name,
        variant,
        params: parsed,
        ret,
    })
}

/// Splits on commas outside brackets.
fn split_top_level(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(s.get(start..i).unwrap_or(""));
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s.get(start..).unwrap_or(""));
    parts
}

/// The index of the `)` closing an already opened parenthesis.
fn find_close(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' if depth == 0 => return Some(i),
            ')' | ']' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// The text inside `prefix[…]`.
fn bracketed<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = s.strip_prefix(prefix)?.strip_prefix('[')?;
    let mut depth = 0i32;
    for (i, c) in rest.char_indices() {
        match c {
            '[' => depth += 1,
            ']' if depth == 0 => return rest.get(..i),
            ']' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn parse_type(s: &str) -> SyzType {
    let s = s.trim();
    if let Some(inner) = bracketed(s, "flags") {
        let name = inner.split(',').next().unwrap_or(inner).trim();
        return SyzType::Flags(name.to_owned());
    }
    if bracketed(s, "const").is_some() {
        return SyzType::Const;
    }
    if let Some(inner) = bracketed(s, "ptr").or_else(|| bracketed(s, "ptr64")) {
        // `ptr[direction, type, opt]`
        let Some(pointee) = split_top_level(inner).get(1).map(|ty| ty.trim()) else {
            return SyzType::Ptr(Box::new(SyzType::Void));
        };
        let pointee = parse_type(pointee);
        return match pointee {
            SyzType::Filename | SyzType::Buffer => pointee,
            SyzType::Int(_)
            | SyzType::IntPtr
            | SyzType::Flags(_)
            | SyzType::Const
            | SyzType::Ptr(_)
            | SyzType::Vma
            | SyzType::Len
            | SyzType::Array(..)
            | SyzType::Named(_)
            | SyzType::Void => SyzType::Ptr(Box::new(pointee)),
        };
    }
    if s.starts_with("buffer[") {
        return SyzType::Buffer;
    }
    if s.starts_with("len[") || s.starts_with("bytesize[") || s.starts_with("fileoff") {
        return SyzType::Len;
    }
    if let Some(inner) = bracketed(s, "array") {
        let parts = split_top_level(inner);
        let element = parts.first().copied().unwrap_or(inner);
        let count = parts.get(1).and_then(|count| count.trim().parse().ok());
        return SyzType::Array(Box::new(parse_type(element)), count);
    }
    if s.starts_with("glob[") || s.starts_with("string") || s == "filename" {
        return SyzType::Filename;
    }
    if s == "vma" || s.starts_with("vma[") || s == "vma64" {
        return SyzType::Vma;
    }
    // `int32[0:65]`, `int32:3` (a bit-field), `int16be`.
    let base = s.split(['[', ':']).next().unwrap_or(s);
    match base.trim_end_matches("be") {
        "int8" => SyzType::Int(1),
        "int16" => SyzType::Int(2),
        "int32" => SyzType::Int(4),
        "int64" => SyzType::Int(8),
        "intptr" => SyzType::IntPtr,
        "void" => SyzType::Void,
        _ => SyzType::Named(base.to_owned()),
    }
}

/// Expands references to other flag sets (`clone3_flags = …, clone_flags`).
fn resolve_flag_refs(flag_sets: &mut BTreeMap<String, Vec<String>>) {
    // Bounded: references nest a few levels, and a cycle must not hang.
    for _ in 0..10 {
        let snapshot = flag_sets.clone();
        let mut changed = false;
        for constants in flag_sets.values_mut() {
            let mut expanded = Vec::with_capacity(constants.len());
            for constant in constants.iter() {
                match snapshot.get(constant) {
                    Some(referenced) => {
                        expanded.extend(referenced.iter().cloned());
                        changed = true;
                    }
                    None => expanded.push(constant.clone()),
                }
            }
            *constants = expanded;
        }
        if !changed {
            break;
        }
    }
}

fn is_c_identifier(s: &str) -> bool {
    s.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The value of a numeric constant as syzlang writes it (`0x10`, `-1`).
fn number(s: &str) -> Option<i128> {
    let (negative, digits) = match s.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, s),
    };
    let value = match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(hex) => i128::from_str_radix(hex, 16).ok()?,
        None => digits.parse().ok()?,
    };
    Some(if negative { -value } else { value })
}

/// The values of the named flag constants, by compiling and running a
/// probe that includes the descriptions' headers (`$CC`, default `cc`) and
/// prints each, with `runner` if given. A name the headers do not declare
/// (as a macro or an enumerator) is left out of the next attempt, until
/// the probe compiles.
fn resolve_constant_values(
    includes: &[String],
    flag_sets: &BTreeMap<String, Vec<String>>,
    skip_includes: &[String],
    runner: Option<&str>,
) -> Result<BTreeMap<String, i128>, String> {
    let mut values = BTreeMap::new();
    let mut names: BTreeSet<&str> = flag_sets
        .values()
        .flatten()
        .map(String::as_str)
        .filter(|constant| is_c_identifier(constant))
        .collect();
    let dir = env::temp_dir().join(format!("binbun-typegen-probe-{}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let result = (|| {
        // Each attempt leaves out at least one name, or fails.
        loop {
            if names.is_empty() {
                return Ok(String::new());
            }
            let source = probe(includes, skip_includes, &names);
            match compile_and_run(&dir, &source, runner)? {
                Ok(output) => return Ok(output),
                Err(stderr) => {
                    let undeclared = undeclared(&stderr);
                    let before = names.len();
                    names.retain(|name| !undeclared.contains(name));
                    if names.len() == before {
                        return Err(format!("the probe does not compile:\n{stderr}"));
                    }
                }
            }
        }
    })();
    let _ = fs::remove_dir_all(&dir);
    for line in result?.lines() {
        if let Some((name, value)) = line.split_once('=')
            && let Ok(value) = value.parse()
        {
            values.insert(name.to_owned(), value);
        }
    }
    Ok(values)
}

/// A C program that prints `NAME=value` for each of `names`.
fn probe(includes: &[String], skip_includes: &[String], names: &BTreeSet<&str>) -> String {
    let mut source = String::from("#include <stdio.h>\n#include <stdint.h>\n");
    for include in includes {
        if skip_includes
            .iter()
            .any(|skip| include.contains(skip.as_str()))
        {
            continue;
        }
        // Kernel sources' `uapi/linux/bpf.h` is installed as `linux/bpf.h`.
        let include = include.strip_prefix("uapi/").unwrap_or(include);
        let _ = writeln!(
            source,
            "#if __has_include(<{include}>)\n#include <{include}>\n#endif"
        );
    }
    source.push_str("\nint main(void) {\n");
    for name in names {
        let _ = writeln!(source, "  printf(\"{name}=%lld\\n\", (long long)({name}));");
    }
    source.push_str("  return 0;\n}\n");
    source
}

/// The identifiers a compiler's errors call undeclared (GCC: `'X'
/// undeclared`; Clang: `undeclared identifier 'X'`).
fn undeclared(stderr: &str) -> BTreeSet<&str> {
    stderr
        .lines()
        .filter(|line| line.contains("undeclared"))
        .filter_map(|line| {
            let (_, quoted) = line.split_once(['\'', '\u{2018}'])?;
            let (name, _) = quoted.split_once(['\'', '\u{2019}'])?;
            Some(name)
        })
        .collect()
}

/// Compiles `source` in `dir` and runs it, with `runner` if given: its
/// output, or the compiler's errors.
fn compile_and_run(
    dir: &Path,
    source: &str,
    runner: Option<&str>,
) -> Result<Result<String, String>, String> {
    let c_path = dir.join("probe.c");
    let binary = dir.join("probe");
    fs::write(&c_path, source).map_err(|error| format!("{}: {error}", c_path.display()))?;
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let compile = Command::new(&cc)
        .arg(&c_path)
        .arg("-o")
        .arg(&binary)
        .arg("-w")
        .output()
        .map_err(|error| format!("{cc}: {error}"))?;
    if !compile.status.success() {
        return Ok(Err(String::from_utf8_lossy(&compile.stderr).into_owned()));
    }
    let (program, args) = match runner {
        Some(runner) => (Path::new(runner), Some(&binary)),
        None => (binary.as_path(), None),
    };
    let run = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("{}: {error}", program.display()))?;
    if !run.status.success() {
        return Err("the probe failed".to_owned());
    }
    Ok(Ok(String::from_utf8_lossy(&run.stdout).into_owned()))
}
