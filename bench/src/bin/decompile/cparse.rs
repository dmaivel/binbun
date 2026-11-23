//! C read alike from every tool and from the original source, with
//! tree-sitter's C grammar (which recovers from what it cannot parse, so
//! C a compiler rejects is still measured): a function definition's
//! prototype, locals, gotos, nesting and lines ([`facts`]), and which
//! top-level declarations of a file a function needs ([`Declarations`]).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tree_sitter::{Node, Parser, Tree};

/// Parses `text` as C.
pub fn parse(text: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .expect("the C grammar loads");
    let tree = parser.parse(text, None).expect("parsing is not cancelled");
    // binbun_defs.h expands this annotation to an assembler name. Without
    // expansion, the grammar can absorb subsequent declarations and the
    // next definition into a spurious K&R function definition. Keep byte
    // offsets unchanged: callers still read tokens from the original C.
    if !text.contains("BINBUN_SYMBOL") {
        return tree;
    }
    let mut expanded = text.as_bytes().to_vec();
    let mut changed = false;
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if matches!(node.kind(), "identifier" | "type_identifier")
            && text.get(node.byte_range()) == Some("BINBUN_SYMBOL")
        {
            expanded[node.byte_range()].copy_from_slice(b"__asm__      ");
            changed = true;
        } else {
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
    }
    if changed {
        parser
            .parse(expanded, None)
            .expect("parsing is not cancelled")
    } else {
        tree
    }
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or("")
}

/// A type as the scores compare them: its class and width in bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ty {
    Void,
    Bool(u64),
    Signed(u64),
    Unsigned(u64),
    Float(u64),
    /// Only a width (Hex-Rays' `_QWORD`, Ghidra's `undefined8`).
    Bits(u64),
    /// Any pointer, to data or code.
    Pointer,
    /// A struct or union by value.
    Struct,
    /// Anything else, or a name nothing defines.
    Other,
}

impl Ty {
    /// Its width in bytes, if known.
    pub fn bytes(&self) -> Option<u64> {
        match *self {
            Self::Void => Some(0),
            Self::Bool(n)
            | Self::Signed(n)
            | Self::Unsigned(n)
            | Self::Float(n)
            | Self::Bits(n) => Some(n),
            Self::Pointer => Some(8),
            Self::Struct | Self::Other => None,
        }
    }

    /// The same class and width (a width-only type never is).
    pub fn exact(&self, truth: &Self) -> bool {
        !matches!(self, Self::Bits(_) | Self::Other) && self == truth
    }

    /// The same width (a struct by value: both structs).
    pub fn width(&self, truth: &Self) -> bool {
        match (self, truth) {
            (Self::Struct, Self::Struct) => true,
            _ => self.bytes().is_some() && self.bytes() == truth.bytes(),
        }
    }
}

/// The C base types and the tools' own type names (`defs.h`'s, Ghidra's
/// built-ins) by name, on x86-64 Linux (LP64, signed `char`).
fn base(name: &str) -> Option<Ty> {
    use Ty::{Bits, Bool, Float, Signed, Unsigned, Void};
    Some(match name {
        "void" | "VOID" => Void,
        "_Bool" | "bool" | "_BOOL1" | "BOOLEAN" => Bool(1),
        "_BOOL2" => Bool(2),
        "_BOOL4" | "BOOL" => Bool(4),
        "_BOOL8" => Bool(8),
        "char" | "signed char" | "__int8" | "int8_t" | "int8" | "sint8" | "CHAR" | "__int8_t" => {
            Signed(1)
        }
        "unsigned char" | "unsigned __int8" | "uint8_t" | "uchar" | "uint8" | "byte" | "BYTE"
        | "UCHAR" | "__uint8_t" | "u_char" => Unsigned(1),
        "_BYTE" | "undefined" | "undefined1" => Bits(1),
        "short" | "short int" | "signed short" | "signed short int" | "__int16" | "int16_t"
        | "int16" | "sint16" | "SHORT" | "__int16_t" => Signed(2),
        "unsigned short" | "unsigned short int" | "short unsigned int" | "ushort"
        | "unsigned __int16" | "uint16_t" | "uint16" | "word" | "WORD" | "USHORT"
        | "__uint16_t" | "u_short" => Unsigned(2),
        "_WORD" | "undefined2" => Bits(2),
        "undefined3" => Bits(3),
        "int" | "signed" | "signed int" | "__int32" | "int32_t" | "int32" | "sint32" | "INT"
        | "LONG" | "wchar_t" | "pid_t" | "__pid_t" | "__int32_t" | "key_t" | "sig_atomic_t"
        | "clockid_t" | "__clockid_t" => Signed(4),
        "unsigned" | "unsigned int" | "uint" | "unsigned __int32" | "uint32_t" | "uint32"
        | "dword" | "DWORD" | "UINT" | "ULONG" | "uid_t" | "gid_t" | "__uid_t" | "__gid_t"
        | "mode_t" | "__mode_t" | "socklen_t" | "__socklen_t" | "wint_t" | "useconds_t"
        | "__uint32_t" | "u_int" | "speed_t" | "tcflag_t" => Unsigned(4),
        "_DWORD" | "undefined4" => Bits(4),
        "undefined5" => Bits(5),
        "undefined6" => Bits(6),
        "undefined7" => Bits(7),
        "long" | "long int" | "signed long" | "signed long int" | "long long" | "long long int"
        | "signed long long" | "__int64" | "int64_t" | "int64" | "sint64" | "longlong"
        | "ssize_t" | "__ssize_t" | "intptr_t" | "ptrdiff_t" | "off_t" | "__off_t" | "off64_t"
        | "__off64_t" | "time_t" | "__time_t" | "intmax_t" | "__intmax_t" | "clock_t"
        | "__clock_t" | "__int64_t" | "LONGLONG" | "__suseconds_t" | "suseconds_t" | "blkcnt_t"
        | "__blkcnt_t" => Signed(8),
        "unsigned long"
        | "unsigned long int"
        | "long unsigned int"
        | "unsigned long long"
        | "unsigned long long int"
        | "long long unsigned int"
        | "ulong"
        | "ulonglong"
        | "unsigned __int64"
        | "uint64_t"
        | "uint64"
        | "qword"
        | "size_t"
        | "__size_t"
        | "uintptr_t"
        | "uintmax_t"
        | "__uintmax_t"
        | "__uint64_t"
        | "ULONGLONG"
        | "dev_t"
        | "__dev_t"
        | "ino_t"
        | "__ino_t"
        | "nlink_t"
        | "__nlink_t"
        | "rlim_t"
        | "__rlim_t"
        | "u_long" => Unsigned(8),
        "_QWORD" | "undefined8" => Bits(8),
        "__int128" | "int128_t" | "__int128_t" | "signed __int128" => Signed(16),
        "unsigned __int128" | "__uint128_t" | "uint128_t" => Unsigned(16),
        "_OWORD" | "undefined16" | "unkbyte16" => Bits(16),
        "float" | "float32_t" => Float(4),
        "double" | "float64_t" => Float(8),
        "long double" | "float10" | "_TBYTE" => Float(16),
        _ => return None,
    })
}

/// What qualifies a type without changing it, dropped before looking it
/// up (with the tools' calling conventions and attributes).
const QUALIFIERS: [&str; 16] = [
    "const",
    "volatile",
    "restrict",
    "__restrict",
    "__restrict__",
    "static",
    "extern",
    "inline",
    "register",
    "__fastcall",
    "__cdecl",
    "__stdcall",
    "__noreturn",
    "__usercall",
    "__userpurge",
    "__thiscall",
];

/// The type spelled `spelling` (a type specifier, no declarator), with
/// `typedefs` of the file it is in (name to spelling).
fn classify(spelling: &str, typedefs: &BTreeMap<String, String>, depth: u32) -> Ty {
    let words: Vec<&str> = spelling
        .split(|c: char| c.is_whitespace())
        .filter(|w| !w.is_empty() && !QUALIFIERS.contains(w) && !w.starts_with("__attribute"))
        .collect();
    if let Some(&first) = words.first()
        && matches!(first, "struct" | "union")
    {
        return Ty::Struct;
    }
    if words.first() == Some(&"enum") {
        return Ty::Signed(4);
    }
    let joined = words.join(" ");
    if let Some(ty) = base(&joined) {
        return ty;
    }
    // C's own combinations in another order (`unsigned long int` and the
    // like) and `signed`/`unsigned` with a tool's type.
    let unsigned = words.contains(&"unsigned");
    let rest: Vec<&str> = words
        .iter()
        .copied()
        .filter(|&w| w != "unsigned" && w != "signed")
        .collect();
    if let Some(ty) = base(&rest.join(" ")) {
        return match (ty, unsigned) {
            (Ty::Signed(n), true) => Ty::Unsigned(n),
            (ty, _) => ty,
        };
    }
    if depth < 8
        && let [name] = words.as_slice()
        && let Some(spelling) = typedefs.get(*name)
    {
        return classify(spelling, typedefs, depth + 1);
    }
    Ty::Other
}

/// The types a file's typedefs stand for: name to spelling, `*` appended
/// for each pointer level (`typedef char *string_t;`: `char *`).
pub fn typedefs(tree: &Tree, source: &str) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_definition" {
            let Some(ty) = node.child_by_field_name("type") else {
                continue;
            };
            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                let (name, pointer) = declarator_shape(declarator, source);
                if let Some(name) = name {
                    let spelling = if pointer {
                        "void *".to_owned()
                    } else {
                        text(ty, source).to_owned()
                    };
                    found.insert(name, spelling);
                }
            }
            continue;
        }
        if matches!(
            node.kind(),
            "translation_unit"
                | "preproc_if"
                | "preproc_ifdef"
                | "preproc_else"
                | "linkage_specification"
                | "declaration_list"
        ) {
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
    }
    found
}

/// A declarator's name and whether it makes a pointer (a pointer, an
/// array, a function pointer) of its type.
fn declarator_shape(mut node: Node<'_>, source: &str) -> (Option<String>, bool) {
    let mut pointer = false;
    loop {
        match node.kind() {
            "identifier" | "type_identifier" | "field_identifier" => {
                return (Some(text(node, source).to_owned()), pointer);
            }
            "pointer_declarator"
            | "abstract_pointer_declarator"
            | "array_declarator"
            | "abstract_array_declarator" => pointer = true,
            "function_declarator" | "abstract_function_declarator" => {}
            "parenthesized_declarator" | "abstract_parenthesized_declarator" => {}
            "init_declarator" => {}
            _ => {}
        }
        let next = node.child_by_field_name("declarator").or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|c| c.kind().ends_with("declarator") || c.kind() == "identifier")
        });
        match next {
            Some(next) => node = next,
            None => return (None, pointer),
        }
    }
}

/// What one function definition states.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Facts {
    pub name: String,
    pub returns: Ty,
    pub parameters: Vec<Ty>,
    pub variadic: bool,
    /// Variables declared in its body.
    pub locals: usize,
    pub gotos: usize,
    /// The deepest nesting of `if`, loops and `switch` (`else if` at its
    /// `if`'s level).
    pub nesting: usize,
    /// Lines with something other than comments.
    pub lines: usize,
}

/// Which function definition of a file [`facts`] reads.
#[derive(Clone, Copy)]
pub enum Pick {
    /// The last (binbun's file: the function comes after what it uses).
    Last,
    /// The first (a tool's function on its own).
    First,
}

/// The facts of the function definition `pick` in `source`.
pub fn facts(source: &str, pick: Pick) -> Option<Facts> {
    let tree = parse(source);
    let typedefs = typedefs(&tree, source);
    let definitions = definitions(&tree);
    let function = match pick {
        Pick::First => definitions.first().copied(),
        Pick::Last => definitions.last().copied(),
    }?;
    Some(read(function, source, &typedefs))
}

/// The facts of every function definition in `source`, by name (the
/// first of a name).
pub fn all_facts(source: &str) -> BTreeMap<String, Facts> {
    let tree = parse(source);
    let typedefs = typedefs(&tree, source);
    let mut found = BTreeMap::new();
    for definition in definitions(&tree) {
        if let Some(name) = function_name(definition, source) {
            found
                .entry(name)
                .or_insert_with(|| read(definition, source, &typedefs));
        }
    }
    found
}

/// The function definitions of a file, in order (within preprocessor
/// conditionals and what the parser could not read too).
fn definitions(tree: &Tree) -> Vec<Node<'_>> {
    let mut definitions = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            definitions.push(node);
            continue;
        }
        if matches!(
            node.kind(),
            "translation_unit"
                | "preproc_if"
                | "preproc_ifdef"
                | "preproc_else"
                | "preproc_elif"
                | "linkage_specification"
                | "declaration_list"
                | "ERROR"
        ) {
            let mut cursor = node.walk();
            let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
            children.reverse();
            stack.extend(children);
        }
    }
    definitions
}

fn function_declarator(definition: Node<'_>) -> Option<Node<'_>> {
    let mut node = definition.child_by_field_name("declarator")?;
    loop {
        if node.kind() == "function_declarator" {
            // The innermost one: `int (*f(int a))(int)` returns a function
            // pointer; its own parameters are the inner list.
            let inner = node.child_by_field_name("declarator")?;
            if contains_function_declarator(inner) {
                node = inner;
                continue;
            }
            return Some(node);
        }
        node = node.child_by_field_name("declarator")?;
    }
}

fn contains_function_declarator(mut node: Node<'_>) -> bool {
    loop {
        if node.kind() == "function_declarator" {
            return true;
        }
        match node.child_by_field_name("declarator") {
            Some(next) => node = next,
            None => return false,
        }
    }
}

fn function_name(definition: Node<'_>, source: &str) -> Option<String> {
    let declarator = function_declarator(definition)?;
    declarator_shape(declarator.child_by_field_name("declarator")?, source).0
}

fn read(definition: Node<'_>, source: &str, typedefs: &BTreeMap<String, String>) -> Facts {
    let name = function_name(definition, source).unwrap_or_default();
    // The return type: the specifier, a pointer if any declarator level
    // between the definition and its function declarator is one.
    let specifier = definition
        .child_by_field_name("type")
        .map_or("int", |t| text(t, source));
    let mut returns_pointer = false;
    let declarator = function_declarator(definition);
    if let Some(mut node) = definition.child_by_field_name("declarator") {
        while Some(node) != declarator {
            if matches!(node.kind(), "pointer_declarator" | "function_declarator") {
                returns_pointer = true;
            }
            match node.child_by_field_name("declarator") {
                Some(next) => node = next,
                None => break,
            }
        }
    }
    let returns = if returns_pointer {
        Ty::Pointer
    } else {
        classify(specifier, typedefs, 0)
    };
    let mut parameters = Vec::new();
    let mut variadic = false;
    if let Some(list) = declarator.and_then(|d| d.child_by_field_name("parameters")) {
        let mut cursor = list.walk();
        for parameter in list.named_children(&mut cursor) {
            match parameter.kind() {
                "variadic_parameter" => variadic = true,
                "parameter_declaration" => {
                    let ty = parameter
                        .child_by_field_name("type")
                        .map_or("int", |t| text(t, source));
                    let pointer = parameter
                        .child_by_field_name("declarator")
                        .is_some_and(|d| declarator_shape(d, source).1);
                    parameters.push(if pointer {
                        Ty::Pointer
                    } else {
                        classify(ty, typedefs, 0)
                    });
                }
                _ => {}
            }
        }
        // `f(void)`.
        if parameters == [Ty::Void] {
            parameters.clear();
        }
    }
    let body = definition.child_by_field_name("body");
    let (mut locals, mut gotos, mut nesting) = (0, 0, 0);
    if let Some(body) = body {
        let mut stack = vec![(body, 0usize)];
        while let Some((node, depth)) = stack.pop() {
            let kind = node.kind();
            let mut inner = depth;
            match kind {
                "declaration" => {
                    let mut cursor = node.walk();
                    locals += node
                        .children_by_field_name("declarator", &mut cursor)
                        .count();
                }
                "goto_statement" => gotos += 1,
                "if_statement" => {
                    let else_if = node.parent().is_some_and(|p| {
                        p.kind() == "else_clause"
                            && p.parent().is_some_and(|q| q.kind() == "if_statement")
                    });
                    if !else_if {
                        inner += 1;
                    }
                }
                "while_statement" | "for_statement" | "do_statement" | "switch_statement" => {
                    inner += 1;
                }
                _ => {}
            }
            nesting = nesting.max(inner);
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push((child, inner));
            }
        }
    }
    Facts {
        name,
        returns,
        parameters,
        variadic,
        locals,
        gotos,
        nesting,
        lines: code_lines(definition),
    }
}

/// The lines of `node` holding a token other than a comment.
fn code_lines(node: Node<'_>) -> usize {
    let mut rows = BTreeSet::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "comment" {
            continue;
        }
        if node.child_count() == 0 {
            for row in node.start_position().row..=node.end_position().row {
                rows.insert(row);
            }
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    rows.len()
}

/// The top-level items of a file of declarations (Hex-Rays' file before
/// its functions, Ghidra's header), with the names each defines and
/// uses, to take those a function needs ([`Self::needed`]).
pub struct Declarations {
    /// Each item: its text, the names it defines, the names it uses.
    items: Vec<(String, BTreeSet<String>, BTreeSet<String>)>,
    /// Preprocessor lines (`#include`, `#define`), always kept.
    always: Vec<usize>,
    /// The items defining each name.
    by_name: BTreeMap<String, Vec<usize>>,
}

impl Declarations {
    /// The items of `source`, each read by the grammar on its own
    /// ([`pieces`]): what a tool writes that is no C (Binary Ninja's
    /// `__noreturn` after a prototype, Ghidra's `undefined1 [16] f(ulong
    /// a);`) then costs its own item only. Given the whole file, the
    /// grammar takes thousands of the lines after such a one for part of
    /// the error, and pieces of the line for declarations of the types it
    /// names; an item it cannot read as one declaration is kept whole and
    /// defines what its text names ([`unread_name`]) and nothing else.
    pub fn new(source: &str) -> Self {
        let mut items = Vec::new();
        let mut always = Vec::new();
        for piece in pieces(source) {
            let tree = parse(piece);
            let root = tree.root_node();
            let mut cursor = root.walk();
            let nodes: Vec<Node<'_>> = root
                .children(&mut cursor)
                .filter(|node| !matches!(node.kind(), "comment" | ";"))
                .collect();
            let (defines, uses) = match nodes.as_slice() {
                [] => continue,
                [node] if node.kind() != "ERROR" => {
                    if node.kind().starts_with("preproc") {
                        always.push(items.len());
                    }
                    names(*node, piece)
                }
                _ => {
                    let (found, used) = names(root, piece);
                    let mut uses: BTreeSet<String> = found.into_iter().chain(used).collect();
                    let defines: BTreeSet<String> = unread_name(piece).into_iter().collect();
                    for name in &defines {
                        uses.remove(name);
                    }
                    (defines, uses)
                }
            };
            items.push((piece.to_owned(), defines, uses));
        }
        let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, (_, defines, _)) in items.iter().enumerate() {
            for name in defines {
                by_name.entry(name.clone()).or_default().push(index);
            }
        }
        Self {
            items,
            always,
            by_name,
        }
    }

    /// Whether an item declares `name`.
    pub fn declares(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// The items `function` (C text) needs: those defining a name it uses,
    /// and what they need in turn, in the file's order.
    pub fn needed(&self, function: &str) -> String {
        let tree = parse(function);
        let (_, mut wanted) = names(tree.root_node(), function);
        let mut taken: BTreeSet<usize> = self.always.iter().copied().collect();
        let mut queue: Vec<String> = wanted.iter().cloned().collect();
        while let Some(name) = queue.pop() {
            for &index in self.by_name.get(name.as_str()).into_iter().flatten() {
                if taken.insert(index) {
                    for used in &self.items[index].2 {
                        if wanted.insert(used.clone()) {
                            queue.push(used.clone());
                        }
                    }
                }
            }
        }
        let mut out = String::new();
        for index in taken {
            out.push_str(&self.items[index].0);
            out.push('\n');
        }
        out
    }
}

/// The names an item defines (declared identifiers, typedef names, tags
/// as `struct X`, enumerators) and those it uses (identifiers, type names,
/// tags), parameter names in prototypes aside.
fn names(item: Node<'_>, source: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut defines = BTreeSet::new();
    let mut uses = BTreeSet::new();
    match item.kind() {
        "declaration" | "type_definition" => {
            let mut cursor = item.walk();
            for declarator in item.children_by_field_name("declarator", &mut cursor) {
                match declared_name(declarator, source) {
                    // Hex-Rays' `signed __int64 (__fastcall *f())(…)`: the
                    // grammar takes `signed` for the type and `__int64`
                    // for the name declared.
                    Some(name) if name.starts_with("__int") => {
                        defines.extend(pointer_returning(text(item, source)));
                    }
                    Some(name) => {
                        defines.insert(name);
                    }
                    None => {}
                }
            }
        }
        "function_definition" => {
            if let Some(name) = function_name(item, source) {
                defines.insert(name);
            }
        }
        "preproc_def" | "preproc_function_def" => {
            if let Some(name) = item.child_by_field_name("name") {
                defines.insert(text(name, source).to_owned());
            }
        }
        _ => {}
    }
    let mut stack = vec![item];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "struct_specifier" | "union_specifier" | "enum_specifier" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let tag = format!(
                        "{} {}",
                        &node.kind()[..node.kind().len() - 10],
                        text(name, source)
                    );
                    if node.child_by_field_name("body").is_some() {
                        defines.insert(tag);
                    } else {
                        uses.insert(tag);
                    }
                }
            }
            "enumerator" => {
                if let Some(name) = node.child_by_field_name("name") {
                    defines.insert(text(name, source).to_owned());
                }
            }
            // C's own types are names too where a tool's header defines one
            // (Ghidra's `typedef ulong size_t;`; the grammar knows `size_t`).
            "identifier" | "type_identifier" | "primitive_type" => {
                uses.insert(text(node, source).to_owned());
            }
            // A prototype's parameter: its type only (its name is no use
            // of a global).
            "parameter_declaration" => {
                if let Some(ty) = node.child_by_field_name("type") {
                    stack.push(ty);
                }
                continue;
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    for name in &defines {
        uses.remove(name);
    }
    // The tools' calling conventions and attributes, which the grammar
    // can take for names where it cannot parse them.
    defines.retain(|name| !stop_word(name));
    uses.retain(|name| !stop_word(name));
    (defines, uses)
}

/// A calling convention or attribute of a tool, which the grammar can take
/// for a name where it cannot parse it.
fn stop_word(name: &str) -> bool {
    QUALIFIERS.contains(&name)
        || matches!(
            name,
            "__spoils"
                | "__hidden"
                | "__return_ptr"
                | "__struct_ptr"
                | "__array_ptr"
                | "__unaligned"
                | "__ptr32"
                | "__ptr64"
                | "__high"
                | "__pure"
                | "__noinline"
        )
}

/// The top-level items of `source` by C's punctuation alone, comments
/// before each left out: a preprocessor line (with the lines it continues
/// on), or the text up to a `;` outside braces and parentheses, or up to
/// a `}` that closes the outermost brace at the end of its line (a
/// function's body). Comments and literals are passed over.
fn pieces(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut pieces = Vec::new();
    let (mut at, mut start) = (0, None::<usize>);
    let (mut braces, mut parentheses) = (0u32, 0u32);
    let line_end = |from: usize| source[from..].find('\n').map_or(source.len(), |n| from + n);
    while at < bytes.len() {
        let rest = &source[at..];
        if rest.starts_with("//") {
            at = line_end(at);
        } else if rest.starts_with("/*") {
            at = rest.find("*/").map_or(source.len(), |end| at + end + 2);
        } else if start.is_none() && bytes[at].is_ascii_whitespace() {
            at += 1;
        } else if start.is_none() && bytes[at] == b'#' {
            let mut end = line_end(at);
            while source[..end].ends_with('\\') && end < source.len() {
                end = line_end(end + 1);
            }
            pieces.push(&source[at..end]);
            at = end;
        } else if matches!(bytes[at], b'"' | b'\'') {
            let quote = bytes[at];
            start.get_or_insert(at);
            at += 1;
            while at < bytes.len() && bytes[at] != quote && bytes[at] != b'\n' {
                at += if bytes[at] == b'\\' { 2 } else { 1 };
            }
            at = (at + 1).min(bytes.len());
        } else {
            let from = *start.get_or_insert(at);
            match bytes[at] {
                b'{' => braces += 1,
                b'}' => braces = braces.saturating_sub(1),
                b'(' => parentheses += 1,
                b')' => parentheses = parentheses.saturating_sub(1),
                _ => {}
            }
            at += 1;
            let closed = bytes[at - 1] == b'}'
                && source[at..line_end(at)].trim().is_empty()
                && parentheses == 0;
            if braces == 0 && ((bytes[at - 1] == b';' && parentheses == 0) || closed) {
                pieces.push(&source[from..at]);
                start = None;
                parentheses = 0;
            }
        }
    }
    if let Some(from) = start {
        pieces.push(&source[from..]);
    }
    pieces
}

/// What an item the grammar cannot read as one declaration declares, by
/// its text: in `T (* const name[3])(…)` the last word of the first
/// parenthesis, in `T name(…) ATTRIBUTE;` the word before it, else the
/// last word before a `[`, `=` or `;`.
fn unread_name(item: &str) -> Option<String> {
    let word = |text: &str| {
        text.rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .find(|word| !word.is_empty() && !stop_word(word))
            .filter(|word| !word.starts_with(|c: char| c.is_ascii_digit()))
            .map(str::to_owned)
    };
    let Some(open) = item.find('(') else {
        let end = item.find(['[', '=', ';']).unwrap_or(item.len());
        return word(&item[..end]);
    };
    if !item[open + 1..].trim_start().starts_with('*') {
        return word(&item[..open]);
    }
    let close = item[open..].find(')').map_or(item.len(), |end| open + end);
    let end = item[open..close]
        .find('[')
        .map_or(close, |bracket| open + bracket);
    word(&item[open + 1..end])
}

/// The function `item` declares where it is one returning a pointer to a
/// function, `T (CONVENTION *f(…))(…)`: the identifier after the first
/// `*`, if a parenthesis follows it.
fn pointer_returning(item: &str) -> Option<String> {
    let rest = item[item.find('*')? + 1..].trim_start();
    let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
    (end > 0 && rest[end..].trim_start().starts_with('(')).then(|| rest[..end].to_owned())
}

/// The name a declarator declares: its first identifier that is no
/// [`stop_word`], outside parameter lists, array sizes and initial values.
fn declared_name(declarator: Node<'_>, source: &str) -> Option<String> {
    let mut stack = vec![declarator];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" | "type_identifier" | "field_identifier" | "primitive_type" => {
                let name = text(node, source);
                if !stop_word(name) {
                    return Some(name.to_owned());
                }
                continue;
            }
            "parameter_list" => continue,
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children = Vec::new();
        for (index, child) in node.named_children(&mut cursor).enumerate() {
            let field = node.field_name_for_named_child(u32::try_from(index).unwrap_or(u32::MAX));
            if !matches!(field, Some("size" | "value")) {
                children.push(child);
            }
        }
        children.reverse();
        stack.extend(children);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{Declarations, Pick, Ty, all_facts, facts, parse};

    /// Ghidra's export header writes a 16-byte return value as an array
    /// (`undefined1 [16] f(ulong);`), which is no C: the grammar reads the
    /// rest of the line as a declaration of `ulong`. Such a line is what
    /// declares `f` and nothing else, whole.
    #[test]
    fn a_prototype_the_grammar_cannot_read_defines_its_function_only() {
        let header = "typedef unsigned long    ulong;\nundefined1  [16] getentropy(ulong param_1,ulong param_2);\nvoid plain(ulong param_1);\n";
        let declarations = Declarations::new(header);
        let needed = declarations.needed("void f(void) { ulong x = 0; plain(x); }");
        assert!(
            needed.contains("typedef unsigned long    ulong;"),
            "{needed}"
        );
        assert!(needed.contains("void plain(ulong param_1);"), "{needed}");
        assert!(!needed.contains("getentropy"), "{needed}");
        let needed = declarations.needed("void g(void) { getentropy(1, 2); }");
        assert!(
            needed.contains("undefined1  [16] getentropy(ulong param_1,ulong param_2);"),
            "{needed}"
        );
    }

    /// Hex-Rays declares a function returning a pointer to one as `signed
    /// __int64 (__fastcall *f())(…)`, which the grammar reads as a
    /// declaration of `__int64`: the line declares `f`, and what uses
    /// `__int64` does not get it.
    #[test]
    fn a_function_returning_a_pointer_to_one_declares_itself() {
        let header = "signed __int64 (__fastcall *j_strlen())(const __m128i *a1);\n__int64 __fastcall plain(__int64 a1);\n";
        let declarations = Declarations::new(header);
        let needed = declarations.needed("void f(void) { __int64 x = plain(0); }");
        assert!(
            needed.contains("plain") && !needed.contains("j_strlen"),
            "{needed}"
        );
        let needed = declarations.needed("void g(void) { j_strlen(); }");
        assert!(needed.contains("j_strlen"), "{needed}");
    }

    /// Binary Ninja writes attributes after a declarator (`__noreturn`),
    /// which the grammar, given the whole file, reads as an error running
    /// on over the lines after it: each item is read on its own, so the
    /// next line's prototype is still there, and the line itself declares
    /// its own name (a pointer's, inside the parenthesis).
    #[test]
    fn a_line_the_grammar_cannot_read_costs_no_other_line() {
        let header = "extern void (* const exit_slot)() __noreturn;\nvoid leave(int32_t arg1) __noreturn;\nint64_t xmalloc(uint64_t arg1);\nstruct pair {\n    int32_t a;\n    __offset(0x8);\n    int32_t b;\n};\nextern struct pair both;\n";
        let declarations = Declarations::new(header);
        let needed = declarations.needed("void f(void) { xmalloc(8); }");
        assert_eq!(needed, "int64_t xmalloc(uint64_t arg1);\n");
        let needed = declarations.needed("void g(void) { exit_slot(); leave(1); }");
        assert!(needed.contains("exit_slot)() __noreturn;"), "{needed}");
        assert!(
            needed.contains("void leave(int32_t arg1) __noreturn;"),
            "{needed}"
        );
        assert!(!needed.contains("xmalloc"), "{needed}");
        let needed = declarations.needed("int32_t h(void) { return both.a; }");
        assert!(
            needed.contains("__offset(0x8);\n    int32_t b;\n};"),
            "{needed}"
        );
        assert!(needed.ends_with("extern struct pair both;\n"), "{needed}");
    }

    #[test]
    fn assembler_named_declarations_do_not_absorb_the_definition() {
        let body = "\nint example(int value) {\n int local = value;\n if (local) goto end;\n local++;\nend:\n return local;\n}\n";
        for annotation in ["__asm__(\"external\")", "BINBUN_SYMBOL(\"external\")"] {
            let source =
                format!("int alias(int, void *, void *) {annotation};\nvoid other(void);{body}");
            for pick in [Pick::First, Pick::Last] {
                let found = facts(&source, pick).expect("the definition is parsed");
                assert_eq!(found.name, "example");
                assert_eq!(found.parameters, [Ty::Signed(4)]);
                assert_eq!(found.returns, Ty::Signed(4));
                assert_eq!((found.locals, found.gotos, found.nesting), (1, 1, 1));
            }
            assert_eq!(all_facts(&source).len(), 1);
        }
    }

    #[test]
    fn annotation_tokens_do_not_match_identifier_prefixes() {
        let source =
            "/* BINBUN_SYMBOL */\nchar *BINBUN_SYMBOL_suffix(void) { return \"BINBUN_SYMBOL\"; }";
        let tree = parse(source);
        assert!(!tree.root_node().has_error());
        let found = facts(source, Pick::Last).expect("the definition is parsed");
        assert_eq!(found.name, "BINBUN_SYMBOL_suffix");
        assert!(found.parameters.is_empty());
        assert_eq!(found.returns, Ty::Pointer);
    }
}
