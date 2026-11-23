//! A function's declared prototype as one line of C, for the comment above
//! its header, from the type library's declaration.

use binbun_typedb::types::{FloatFormat, Signature};
use binbun_typedb::{Type, TypeId, TypeLibrary};

/// The deepest type nesting written out (a recursive type stops here).
const DEPTH: usize = 16;

/// `name` declared with `signature`: `int sleep(unsigned int seconds)`.
pub(crate) fn prototype(
    library: &TypeLibrary,
    name: &str,
    signature: &Signature<TypeId>,
) -> String {
    function(library, name, signature, 0)
}

fn function(
    library: &TypeLibrary,
    inner: &str,
    signature: &Signature<TypeId>,
    depth: usize,
) -> String {
    let mut parameters: Vec<String> = signature
        .params
        .iter()
        .map(|p| declare(library, p.ty, p.name.as_deref().unwrap_or(""), depth + 1))
        .collect();
    if signature.variadic {
        parameters.push("...".to_owned());
    }
    if parameters.is_empty() {
        parameters.push("void".to_owned());
    }
    declare(
        library,
        signature.ret,
        &format!("{inner}({})", parameters.join(", ")),
        depth + 1,
    )
}

/// `inner` (a declarator: a name, `*p`, `f(int)`) declared of type `ty`.
fn declare(library: &TypeLibrary, ty: TypeId, inner: &str, depth: usize) -> String {
    let base = |text: &str| join(text, inner);
    if depth > DEPTH {
        return base("...");
    }
    match library.ty(ty) {
        None => base("?"),
        Some(Type::Void) => base("void"),
        Some(Type::Bool) => base("_Bool"),
        Some(Type::Char { .. }) => base("char"),
        Some(&Type::Int { signed, size }) => base(&integer(signed, size)),
        Some(&Type::Float(format)) => base(match format {
            FloatFormat::Half => "_Float16",
            FloatFormat::Single => "float",
            FloatFormat::Double => "double",
            FloatFormat::X87 => "long double",
            FloatFormat::Quad => "__float128",
        }),
        Some(&Type::Pointer(to)) => {
            let starred = format!("*{inner}");
            let wrapped = if matches!(library.ty(to), Some(Type::Array { .. } | Type::Function(_)))
            {
                format!("({starred})")
            } else {
                starred
            };
            declare(library, to, &wrapped, depth + 1)
        }
        Some(&Type::Array { element, count }) => {
            let count = count.map(|n| n.to_string()).unwrap_or_default();
            declare(library, element, &format!("{inner}[{count}]"), depth + 1)
        }
        Some(Type::Function(signature)) => function(library, inner, signature, depth + 1),
        Some(Type::Record(record)) => base(&record.key),
        Some(Type::Enum(definition)) => base(&definition.key),
        Some(Type::Typedef(typedef)) => base(&typedef.name),
        Some(Type::Opaque(opaque)) => base(&opaque.name),
    }
}

fn join(base: &str, inner: &str) -> String {
    if inner.is_empty() {
        base.to_owned()
    } else {
        format!("{base} {inner}")
    }
}

fn integer(signed: bool, size: u8) -> String {
    let name = match size {
        1 => "char",
        2 => "short",
        4 => "int",
        8 => "long long",
        16 => "__int128",
        _ => {
            return format!(
                "{}int{}_t",
                if signed { "" } else { "u" },
                u32::from(size) * 8
            );
        }
    };
    match (signed, size) {
        (true, 1) => "signed char".to_owned(),
        (true, _) => name.to_owned(),
        (false, _) => format!("unsigned {name}"),
    }
}
