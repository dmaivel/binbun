# binbun

The engine of [binbun](https://binbun.org), an open-source interactive disassembler and decompiler: one loaded executable as a program database, from its recovered functions and cross-references to their decompiled C, with each line's provenance.

```rust
use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::Options;
use binbun_loader::Image;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read("/usr/bin/bash")?;
    let image = Image::parse(&data)?;
    let database = Database::new(&image, Seeds::ALL)?;
    let function = database.find_function("main")?;
    // A style asks for C; without one, only the intermediate forms are made.
    let options = Options {
        style: Some("kr".to_owned()),
        ..Options::default()
    };
    let decompiled = database.decompile(function, &options).result?;
    if let Some(c) = decompiled.c {
        println!("{}", c.text);
    }
    Ok(())
}
```

This needs [`binbun-loader`](https://crates.io/crates/binbun-loader) beside it. For an interactive tool, [`binbun-session`](https://crates.io/crates/binbun-session) runs the engine in the background with projects and undoable edits, as the app and the Python package do. More examples are in the [repository](https://github.com/dmaivel/binbun/tree/main/examples/rust), and the API is unstable while binbun is 0.x.

Licensed under either of [Apache License, Version 2.0](https://github.com/dmaivel/binbun/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/dmaivel/binbun/blob/main/LICENSE-MIT) at your option.
