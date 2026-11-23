//! Decompiler quick start: open a binary, decompile a function, print its
//! C, then one line's provenance: the addresses of the machine
//! instructions it came from. It decompiles classify, a switch compiled
//! to a jump table, in the checked-in test program
//! (`tests/fixtures/program-x86_64.elf`), with nothing saved.
//!
//! ```text
//! cargo run --release -p binbun-session --example decompiler_quick_start
//! ```

use binbun_session::{Options, Session, Stage};

const PROGRAM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/program-x86_64.elf"
);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options {
        ephemeral: true,
        ..Options::default()
    };
    let session = Session::open(PROGRAM, options)?;
    session.wait(Stage::Analysed, None);
    let database = session.database().ok_or("not analysed")?;
    let c = session.document(database.find_function("classify")?)?;
    print!("{}", c.text);

    for (n, line) in c.lines().iter().enumerate() {
        if c.line_text(n).contains("return") {
            print!("line {} came from", n + 1);
            for address in &line.addresses {
                print!(" {address:#x}");
            }
            println!();
        }
    }
    Ok(())
}
