//! GCC's table of the functions it knows, `builtins.def`, with the types
//! of `builtin-types.def` and the attributes of `builtin-attrs.def` (GCC
//! installs all three with its plugin headers, `gcc
//! -print-file-name=plugin` / `include`): here, the object-size checking
//! library functions, `DEF_LIB_BUILTIN` and `DEF_EXT_LIB_BUILTIN` entries
//! whose code ends in `_CHK` (`BUILT_IN_MEMCPY_CHK`, `"__memcpy_chk"`),
//! which code built with `_FORTIFY_SOURCE` calls. glibc's headers call the
//! string and memory ones as GCC builtins (`__builtin___memcpy_chk`, in
//! `bits/string_fortified.h`) and declare none of them, so a database of
//! the headers alone lacks their prototypes.
//!
//! [`fortified`] gives them as C declarations, to be read after the
//! headers (`headers::Options::extra`, feature `headers`):
//! clang then spells their types for the target (`size_t`, the signedness
//! of `char`) as it does the headers' own. The attributes kept are those
//! the database records: `nothrow` and `noreturn`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// The C spelling of the GCC type nodes `DEF_PRIMITIVE_TYPE` names (GCC's
/// `tree.cc` `build_common_tree_nodes` and the C front end's
/// `c_common_nodes_and_builtins` build them): those the checking
/// builtins use, and the plain integers. Any other is refused where a
/// declaration needs it. `va_list` as a parameter
/// (`va_list_arg_type_node`) is spelled as the headers spell it (glibc
/// declares `vprintf (const char *, __gnuc_va_list)`): the target's (a
/// decayed array on x86-64, a structure on AArch64).
const PRIMITIVES: [(&str, &str); 14] = [
    ("void_type_node", "void"),
    ("integer_type_node", "int"),
    ("unsigned_type_node", "unsigned int"),
    ("long_integer_type_node", "long"),
    ("long_unsigned_type_node", "unsigned long"),
    ("long_long_integer_type_node", "long long"),
    ("long_long_unsigned_type_node", "unsigned long long"),
    ("size_type_node", "size_t"),
    ("ptr_type_node", "void *"),
    ("const_ptr_type_node", "const void *"),
    ("string_type_node", "char *"),
    ("const_string_type_node", "const char *"),
    ("fileptr_type_node", "FILE *"),
    ("va_list_arg_type_node", "__gnuc_va_list"),
];

/// The object-size checking library functions of the GCC table in `dir`
/// (`builtins.def`, `builtin-types.def`, `builtin-attrs.def`) for which
/// `wanted` holds, as C declarations.
///
/// # Errors
///
/// If a file cannot be read, or a wanted function's type or attributes
/// are not defined in a form this reader spells (see [`declarations`]).
pub fn fortified(dir: &Path, wanted: impl Fn(&str) -> bool) -> Result<String, String> {
    let read = |file: &str| {
        let path = dir.join(file);
        fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))
    };
    declarations(
        &read("builtins.def")?,
        &read("builtin-types.def")?,
        &read("builtin-attrs.def")?,
        wanted,
    )
}

/// The object-size checking library functions `builtins` defines for
/// which `wanted` holds, as C declarations, each after a comment naming
/// its entry; `types` and `attributes` are `builtin-types.def` and
/// `builtin-attrs.def`.
///
/// # Errors
///
/// If a wanted function's entry is malformed, its type is not a function
/// type of primitives and pointers [`PRIMITIVES`] spells, or its
/// attribute list is not built of `DEF_ATTR_TREE_LIST`s (GCC defines some
/// through macros, which this reader does not expand).
pub fn declarations(
    builtins: &str,
    types: &str,
    attributes: &str,
    wanted: impl Fn(&str) -> bool,
) -> Result<String, String> {
    let types = Types::new(types);
    let attributes = Attributes::new(attributes);
    let mut out = String::new();
    for invocation in invocations(builtins) {
        if !matches!(
            invocation.name.as_str(),
            "DEF_LIB_BUILTIN" | "DEF_EXT_LIB_BUILTIN"
        ) {
            continue;
        }
        let [code, name, ty, list] = invocation.args.as_slice() else {
            return Err(format!(
                "builtins.def: {} with {} arguments",
                invocation.name,
                invocation.args.len()
            ));
        };
        if !code.ends_with("_CHK") {
            continue;
        }
        let name = name
            .strip_prefix('"')
            .and_then(|name| name.strip_suffix('"'))
            .ok_or_else(|| format!("builtins.def: {code}: the name {name} is not a string"))?;
        if !wanted(name) {
            continue;
        }
        let declaration = types
            .declaration(ty, name)
            .map_err(|error| format!("builtin-types.def: {code}: {error}"))?;
        let mut specifiers = String::new();
        for purpose in attributes
            .purposes(list)
            .map_err(|error| format!("builtin-attrs.def: {code}: {error}"))?
        {
            if matches!(purpose, "nothrow" | "noreturn") {
                let _ = write!(specifiers, " __attribute__((__{purpose}__))");
            }
        }
        let _ = writeln!(
            out,
            "/* builtins.def {code} */\nextern {declaration}{specifiers};"
        );
    }
    Ok(out)
}

/// One macro invocation of a `.def` file: the macro and its arguments,
/// each as its tokens joined by spaces (a string keeps its quotes).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Invocation {
    name: String,
    args: Vec<String>,
}

/// A token of a `.def` file.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    /// An identifier or number.
    Word(String),
    /// A string literal's contents.
    Text(String),
    /// Any other character.
    Punct(char),
}

impl Token {
    /// How an argument spells it.
    fn spelling(&self) -> String {
        match self {
            Self::Word(word) => word.clone(),
            Self::Text(text) => format!("\"{text}\""),
            Self::Punct(c) => c.to_string(),
        }
    }
}

/// The tokens of `text`, without comments and preprocessor directives (a
/// directive's continued lines included: `#define DEF_LIB_BUILTIN(…) \`).
fn tokens(text: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    let mut line_start = true;
    while let Some(c) = chars.next() {
        match c {
            '\n' => {
                line_start = true;
                continue;
            }
            '#' if line_start => {
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            chars.next();
                        }
                        '\n' => break,
                        _ => {}
                    }
                }
                continue;
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut star = false;
                for c in chars.by_ref() {
                    if star && c == '/' {
                        break;
                    }
                    star = c == '*';
                }
                continue;
            }
            '/' if chars.peek() == Some(&'/') => {
                chars.by_ref().find(|&c| c == '\n');
                line_start = true;
                continue;
            }
            // A continued line outside a directive (GCC writes them in
            // invocations too) is whitespace.
            '\\' if chars.peek() == Some(&'\n') => {
                chars.next();
                continue;
            }
            c if c.is_whitespace() => continue,
            _ => {}
        }
        line_start = false;
        if c.is_ascii_alphanumeric() || c == '_' {
            let mut word = String::from(c);
            while let Some(&next) = chars.peek() {
                if !(next.is_ascii_alphanumeric() || next == '_') {
                    break;
                }
                word.push(next);
                chars.next();
            }
            out.push(Token::Word(word));
        } else if c == '"' {
            let mut text = String::new();
            while let Some(next) = chars.next() {
                match next {
                    '\\' => text.extend(chars.next()),
                    '"' => break,
                    _ => text.push(next),
                }
            }
            out.push(Token::Text(text));
        } else {
            out.push(Token::Punct(c));
        }
    }
    out
}

/// The top-level invocations of `DEF_*` macros in `text`.
fn invocations(text: &str) -> Vec<Invocation> {
    let tokens = tokens(text);
    let mut found = Vec::new();
    let mut rest = tokens.iter().peekable();
    while let Some(token) = rest.next() {
        let Token::Word(name) = token else {
            continue;
        };
        if !name.starts_with("DEF_") || rest.peek() != Some(&&Token::Punct('(')) {
            continue;
        }
        rest.next();
        let mut args = vec![String::new()];
        let mut depth = 0_usize;
        for token in rest.by_ref() {
            match token {
                Token::Punct(')') if depth == 0 => break,
                Token::Punct(',') if depth == 0 => {
                    args.push(String::new());
                    continue;
                }
                Token::Punct('(') => depth += 1,
                Token::Punct(')') => depth -= 1,
                Token::Word(_) | Token::Text(_) | Token::Punct(_) => {}
            }
            if let Some(arg) = args.last_mut() {
                if !arg.is_empty() {
                    arg.push(' ');
                }
                arg.push_str(&token.spelling());
            }
        }
        found.push(Invocation {
            name: name.clone(),
            args,
        });
    }
    found
}

/// A type `builtin-types.def` defines.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Definition {
    /// `DEF_PRIMITIVE_TYPE`: the GCC expression of its type node.
    Primitive(String),
    /// `DEF_POINTER_TYPE`: a pointer to this type.
    Pointer(String),
    /// `DEF_FUNCTION_TYPE_n` and `DEF_FUNCTION_TYPE_VAR_n`.
    Function {
        ret: String,
        params: Vec<String>,
        variadic: bool,
    },
}

/// The types of `builtin-types.def`, by enumerator (`BT_SIZE`).
#[derive(Debug)]
struct Types(BTreeMap<String, Definition>);

impl Types {
    fn new(text: &str) -> Self {
        let mut types = BTreeMap::new();
        for invocation in invocations(text) {
            let Some((key, operands)) = invocation.args.split_first() else {
                continue;
            };
            let definition = match invocation.name.as_str() {
                "DEF_PRIMITIVE_TYPE" => Definition::Primitive(operands.join(", ")),
                "DEF_POINTER_TYPE" => match operands {
                    [target] => Definition::Pointer(target.clone()),
                    _ => continue,
                },
                name if name.starts_with("DEF_FUNCTION_TYPE_") => {
                    let Some((ret, params)) = operands.split_first() else {
                        continue;
                    };
                    Definition::Function {
                        ret: ret.clone(),
                        params: params.to_vec(),
                        variadic: name.starts_with("DEF_FUNCTION_TYPE_VAR_"),
                    }
                }
                _ => continue,
            };
            types.insert(key.clone(), definition);
        }
        Self(types)
    }

    /// The C spelling of value type `key`.
    fn spell(&self, key: &str) -> Result<String, String> {
        match self.0.get(key) {
            Some(Definition::Primitive(node)) => PRIMITIVES
                .iter()
                .find(|(known, _)| known == node)
                .map(|(_, spelling)| (*spelling).to_owned())
                .ok_or_else(|| format!("{key} ({node}) has no C spelling here")),
            Some(Definition::Pointer(target)) => {
                if matches!(self.0.get(target), Some(Definition::Function { .. })) {
                    return Err(format!("{key} points to a function"));
                }
                let target = self.spell(target)?;
                Ok(if target.ends_with('*') {
                    format!("{target}*")
                } else {
                    format!("{target} *")
                })
            }
            Some(Definition::Function { .. }) => Err(format!("{key} is a function type")),
            None => Err(format!("{key} is not defined")),
        }
    }

    /// The C declaration of function `name` of function type `key`.
    fn declaration(&self, key: &str, name: &str) -> Result<String, String> {
        let Some(Definition::Function {
            ret,
            params,
            variadic,
        }) = self.0.get(key)
        else {
            return Err(format!("{key} is not a function type"));
        };
        let mut spelled = params
            .iter()
            .map(|param| self.spell(param))
            .collect::<Result<Vec<_>, _>>()?;
        if *variadic {
            spelled.push("...".to_owned());
        } else if spelled.is_empty() {
            spelled.push("void".to_owned());
        }
        let ret = self.spell(ret)?;
        let space = if ret.ends_with('*') { "" } else { " " };
        Ok(format!("{ret}{space}{name}({})", spelled.join(", ")))
    }
}

/// The attribute lists of `builtin-attrs.def`.
#[derive(Debug)]
struct Attributes {
    /// `DEF_ATTR_IDENT (ATTR_NOTHROW, "nothrow")`: the identifiers.
    idents: BTreeMap<String, String>,
    /// `DEF_ATTR_TREE_LIST (ENUM, PURPOSE, VALUE, CHAIN)`: each list's
    /// first attribute (its purpose) and the list it continues with.
    lists: BTreeMap<String, (String, String)>,
}

impl Attributes {
    fn new(text: &str) -> Self {
        let mut idents = BTreeMap::new();
        let mut lists = BTreeMap::new();
        for invocation in invocations(text) {
            match (invocation.name.as_str(), invocation.args.as_slice()) {
                ("DEF_ATTR_IDENT", [key, ident]) => {
                    if let Some(ident) = ident.strip_prefix('"').and_then(|i| i.strip_suffix('"')) {
                        idents.insert(key.clone(), ident.to_owned());
                    }
                }
                ("DEF_ATTR_TREE_LIST", [key, purpose, _value, chain]) => {
                    lists.insert(key.clone(), (purpose.clone(), chain.clone()));
                }
                _ => {}
            }
        }
        Self { idents, lists }
    }

    /// The attributes (`nothrow`, `nonnull`, `leaf`) of list `key`, first
    /// first.
    fn purposes(&self, key: &str) -> Result<Vec<&str>, String> {
        let mut found = Vec::new();
        let mut list = key;
        // A chain is at most as long as the lists defined.
        for _ in 0..=self.lists.len() {
            if list == "ATTR_NULL" {
                return Ok(found);
            }
            let (purpose, chain) = self
                .lists
                .get(list)
                .ok_or_else(|| format!("{list} is not a DEF_ATTR_TREE_LIST"))?;
            let ident = self
                .idents
                .get(purpose)
                .ok_or_else(|| format!("{purpose} is not a DEF_ATTR_IDENT"))?;
            found.push(ident.as_str());
            list = chain;
        }
        Err(format!("{key} is circular"))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
mod tests {
    use super::{Invocation, declarations, invocations};

    /// Excerpts of GCC 16's files, in their own layout.
    const TYPES: &str = r"
/* Before including this header, you must define the following macros:
   DEF_PRIMITIVE_TYPE (ENUM, TYPE) */
DEF_PRIMITIVE_TYPE (BT_VOID, void_type_node)
DEF_PRIMITIVE_TYPE (BT_INT, integer_type_node)
DEF_PRIMITIVE_TYPE (BT_PTR, ptr_type_node)
DEF_PRIMITIVE_TYPE (BT_FILEPTR, fileptr_type_node)
DEF_PRIMITIVE_TYPE (BT_CONST_PTR, const_ptr_type_node)
DEF_PRIMITIVE_TYPE (BT_SIZE, size_type_node)
DEF_PRIMITIVE_TYPE (BT_STRING, string_type_node)
DEF_PRIMITIVE_TYPE (BT_CONST_STRING, const_string_type_node)
DEF_PRIMITIVE_TYPE (BT_WORD, (*lang_hooks.types.type_for_mode) (word_mode, 1))
DEF_PRIMITIVE_TYPE (BT_VALIST_ARG, va_list_arg_type_node)
DEF_POINTER_TYPE (BT_PTR_CONST_STRING, BT_CONST_STRING)
DEF_FUNCTION_TYPE_0 (BT_FN_VOID, BT_VOID)
DEF_FUNCTION_TYPE_3 (BT_FN_STRING_STRING_CONST_STRING_SIZE,
		     BT_STRING, BT_STRING, BT_CONST_STRING, BT_SIZE)
DEF_FUNCTION_TYPE_4 (BT_FN_PTR_PTR_CONST_PTR_SIZE_SIZE,
		     BT_PTR, BT_PTR, BT_CONST_PTR, BT_SIZE, BT_SIZE)
DEF_FUNCTION_TYPE_4 (BT_FN_PTR_PTR_INT_SIZE_SIZE,
		     BT_PTR, BT_PTR, BT_INT, BT_SIZE, BT_SIZE)
DEF_FUNCTION_TYPE_VAR_3 (BT_FN_INT_FILEPTR_INT_CONST_STRING_VAR,
			 BT_INT, BT_FILEPTR, BT_INT, BT_CONST_STRING)
DEF_FUNCTION_TYPE_1 (BT_FN_WORD_PTR, BT_WORD, BT_PTR)
DEF_FUNCTION_TYPE_1 (BT_FN_SIZE_PTR_CONST_STRING, BT_SIZE, BT_PTR_CONST_STRING)
";

    const ATTRIBUTES: &str = r#"
#define DEF_ATTR_FOR_INT(VALUE)					\
  DEF_ATTR_INT (ATTR_##VALUE, VALUE)			\
  DEF_ATTR_TREE_LIST (ATTR_LIST_##VALUE, ATTR_NULL,	\
		      ATTR_##VALUE, ATTR_NULL)
DEF_ATTR_NULL_TREE (ATTR_NULL)
DEF_ATTR_IDENT (ATTR_LEAF, "leaf")
DEF_ATTR_IDENT (ATTR_NONNULL, "nonnull")
DEF_ATTR_IDENT (ATTR_NOTHROW, "nothrow")
DEF_ATTR_IDENT (ATTR_NORETURN, "noreturn")
DEF_ATTR_TREE_LIST (ATTR_NOTHROW_LIST, ATTR_NOTHROW, ATTR_NULL, ATTR_NULL)
DEF_ATTR_TREE_LIST (ATTR_NOTHROW_LEAF_LIST, ATTR_LEAF, ATTR_NULL, ATTR_NOTHROW_LIST)
/* Nothrow functions whose pointer parameter(s) are all nonnull.  */
DEF_ATTR_TREE_LIST (ATTR_NOTHROW_NONNULL, ATTR_NONNULL, ATTR_NULL, \
			ATTR_NOTHROW_LIST)
DEF_ATTR_TREE_LIST (ATTR_NOTHROW_NONNULL_LEAF, ATTR_NONNULL, ATTR_NULL, \
			ATTR_NOTHROW_LEAF_LIST)
DEF_ATTR_TREE_LIST (ATTR_NORETURN_NOTHROW_LIST, ATTR_NORETURN,	\
			ATTR_NULL, ATTR_NOTHROW_LIST)
DEF_ATTR_TREE_LIST (ATTR_LOOP_A, ATTR_LEAF, ATTR_NULL, ATTR_LOOP_B)
DEF_ATTR_TREE_LIST (ATTR_LOOP_B, ATTR_LEAF, ATTR_NULL, ATTR_LOOP_A)
"#;

    const BUILTINS: &str = r#"
#undef DEF_LIB_BUILTIN
#define DEF_LIB_BUILTIN(ENUM, NAME, TYPE, ATTRS)	\
  DEF_BUILTIN (ENUM, "__builtin_" NAME, BUILT_IN_NORMAL, TYPE, TYPE,	\
	       true, true, false, ATTRS, true, true)
DEF_LIB_BUILTIN        (BUILT_IN_MEMCPY, "memcpy", BT_FN_PTR_PTR_CONST_PTR_SIZE_SIZE, ATTR_NOTHROW_NONNULL_LEAF)
/* Object size checking builtins.  */
DEF_GCC_BUILTIN	       (BUILT_IN_OBJECT_SIZE, "object_size", BT_FN_SIZE_PTR_CONST_STRING, ATTR_NOTHROW_LEAF_LIST)
DEF_EXT_LIB_BUILTIN    (BUILT_IN_MEMCPY_CHK, "__memcpy_chk", BT_FN_PTR_PTR_CONST_PTR_SIZE_SIZE, ATTR_NOTHROW_NONNULL_LEAF)
DEF_EXT_LIB_BUILTIN    (BUILT_IN_MEMSET_CHK, "__memset_chk", BT_FN_PTR_PTR_INT_SIZE_SIZE, ATTR_NOTHROW_NONNULL_LEAF)
DEF_EXT_LIB_BUILTIN    (BUILT_IN_STRCPY_CHK, "__strcpy_chk", BT_FN_STRING_STRING_CONST_STRING_SIZE, ATTR_NOTHROW_NONNULL)
DEF_EXT_LIB_BUILTIN    (BUILT_IN_FPRINTF_CHK, "__fprintf_chk", BT_FN_INT_FILEPTR_INT_CONST_STRING_VAR, ATTR_NONNULL_1_FORMAT_PRINTF_3_4)
"#;

    #[test]
    fn invocations_skip_comments_and_directives() {
        let found = invocations(BUILTINS);
        assert_eq!(found.len(), 6, "{found:#?}");
        assert_eq!(
            found[2],
            Invocation {
                name: "DEF_EXT_LIB_BUILTIN".to_owned(),
                args: [
                    "BUILT_IN_MEMCPY_CHK",
                    "\"__memcpy_chk\"",
                    "BT_FN_PTR_PTR_CONST_PTR_SIZE_SIZE",
                    "ATTR_NOTHROW_NONNULL_LEAF"
                ]
                .map(str::to_owned)
                .to_vec(),
            }
        );
        // A nested call is one argument, spelled by its tokens.
        let types = invocations(TYPES);
        assert!(types.iter().any(|invocation| invocation.args[1]
            == "( * lang_hooks . types . type_for_mode ) ( word_mode , 1 )"));
    }

    #[test]
    fn the_checking_functions_are_declared_as_gcc_types_them() {
        let text =
            declarations(BUILTINS, TYPES, ATTRIBUTES, |name| name != "__fprintf_chk").unwrap();
        assert_eq!(
            text,
            "/* builtins.def BUILT_IN_MEMCPY_CHK */\n\
             extern void *__memcpy_chk(void *, const void *, size_t, size_t) __attribute__((__nothrow__));\n\
             /* builtins.def BUILT_IN_MEMSET_CHK */\n\
             extern void *__memset_chk(void *, int, size_t, size_t) __attribute__((__nothrow__));\n\
             /* builtins.def BUILT_IN_STRCPY_CHK */\n\
             extern char *__strcpy_chk(char *, const char *, size_t) __attribute__((__nothrow__));\n"
        );
    }

    #[test]
    fn what_is_not_spelled_is_refused() {
        // `__fprintf_chk`'s attributes come from a macro this reader does
        // not expand.
        let error =
            declarations(BUILTINS, TYPES, ATTRIBUTES, |name| name == "__fprintf_chk").unwrap_err();
        assert!(
            error.contains("ATTR_NONNULL_1_FORMAT_PRINTF_3_4 is not a DEF_ATTR_TREE_LIST"),
            "{error}"
        );
        let entry = |ty: &str, list: &str| {
            format!("DEF_EXT_LIB_BUILTIN (BUILT_IN_X_CHK, \"__x_chk\", {ty}, {list})")
        };
        for (ty, list, expected) in [
            ("BT_FN_WORD_PTR", "ATTR_NOTHROW_LIST", "BT_WORD"),
            (
                "BT_FN_NONE",
                "ATTR_NOTHROW_LIST",
                "BT_FN_NONE is not a function type",
            ),
            ("BT_FN_VOID", "ATTR_LOOP_A", "ATTR_LOOP_A is circular"),
        ] {
            let error = declarations(&entry(ty, list), TYPES, ATTRIBUTES, |_| true).unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
        // A pointer to a pointer, a function of no parameters, `noreturn`.
        let text = declarations(
            &format!(
                "{}\n{}",
                entry("BT_FN_SIZE_PTR_CONST_STRING", "ATTR_NULL"),
                entry("BT_FN_VOID", "ATTR_NORETURN_NOTHROW_LIST")
            ),
            TYPES,
            ATTRIBUTES,
            |_| true,
        )
        .unwrap();
        assert!(
            text.contains("extern size_t __x_chk(const char **);\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "extern void __x_chk(void) __attribute__((__noreturn__)) __attribute__((__nothrow__));\n"
            ),
            "{text}"
        );
    }
}
