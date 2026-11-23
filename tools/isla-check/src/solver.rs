//! Running z3 on an SMT-LIB script and reading its answers back.

use std::io::Write as _;
use std::process::{Command, Stdio};

/// Runs `z3 -in -smt2` on `script` and returns what it prints. The script
/// is written from another thread: z3 answers as it reads, and a full
/// output pipe would otherwise stop both.
///
/// # Errors
///
/// If z3 cannot be run.
pub fn run(script: &str) -> Result<String, String> {
    let mut child = Command::new("z3")
        .args(["-in", "-smt2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run z3: {error}"))?;
    let mut stdin = child.stdin.take().ok_or("z3 has no input")?;
    let output = std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(script.as_bytes()));
        let output = child.wait_with_output();
        let written = writer.join();
        match (output, written) {
            (Ok(output), Ok(Ok(()))) => Ok(output),
            (Err(error), _) => Err(format!("waiting for z3: {error}")),
            (_, Ok(Err(error))) => Err(format!("writing to z3: {error}")),
            (_, Err(_)) => Err("the thread writing to z3 panicked".to_owned()),
        }
    })?;
    String::from_utf8(output.stdout).map_err(|error| format!("z3's output: {error}"))
}

/// The top-level items of a solver's output: atoms (`sat`, an `echo`ed
/// marker) and parenthesised groups, as text.
pub fn items(output: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut quoted = false;
    let mut string = false;
    for c in output.chars() {
        if depth == 0 && !quoted && !string && c.is_whitespace() {
            if !current.is_empty() {
                items.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(c);
        match c {
            '|' if !string => quoted = !quoted,
            '"' if !quoted => string = !string,
            '(' if !quoted && !string => depth += 1,
            ')' if !quoted && !string => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    items.push(std::mem::take(&mut current));
                }
            }
            _ => {}
        }
    }
    if !current.is_empty() {
        items.push(current);
    }
    items
}

/// The value in a `get-value` answer for one symbol, `((symbol value))`.
pub fn value(item: &str) -> Option<&str> {
    let inner = item.strip_prefix("((")?.strip_suffix("))")?;
    let value = if let Some(quoted) = inner.strip_prefix('|') {
        quoted.split_once('|')?.1
    } else {
        inner.split_once(char::is_whitespace)?.1
    };
    Some(value.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_split_atoms_and_groups() {
        let output = "sat\n((|s.x0| #x0000000000000001))\n((|a b| (_ bv3 8)))\n(error \"line 3: no (model)\")\n@@\nunsat\n";
        let items = items(output);
        assert_eq!(
            items,
            [
                "sat",
                "((|s.x0| #x0000000000000001))",
                "((|a b| (_ bv3 8)))",
                "(error \"line 3: no (model)\")",
                "@@",
                "unsat"
            ]
        );
        assert_eq!(value(&items[1]), Some("#x0000000000000001"));
        assert_eq!(value(&items[2]), Some("(_ bv3 8)"));
        assert_eq!(value("((|d| false))"), Some("false"));
        assert_eq!(value("((v12 #b1))"), Some("#b1"));
    }
}
