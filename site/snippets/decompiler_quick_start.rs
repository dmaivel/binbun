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
