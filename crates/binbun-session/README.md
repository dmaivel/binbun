# binbun-session

The engine of [binbun](https://binbun.org) as its app and Python package use it: one binary open, analysed on worker threads, each function's C on request with each line's provenance, and the user's edits (names, types, comments) as undoable steps saved in a project.

```rust
use binbun_session::{Options, Session, Stage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options {
        ephemeral: true,
        ..Options::default()
    };
    let session = Session::open("/usr/bin/bash", options)?;
    session.wait(Stage::Analysed, None);
    let database = session.database().ok_or("not analysed")?;
    let c = session.document(database.find_function("main")?)?;
    print!("{}", c.text);
    Ok(())
}
```

For the engine without threads or projects, see [`binbun`](https://crates.io/crates/binbun). More examples are in the [repository](https://github.com/dmaivel/binbun/tree/main/examples/rust), and the API is unstable while binbun is 0.x.

Licensed under either of [Apache License, Version 2.0](https://github.com/dmaivel/binbun/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/dmaivel/binbun/blob/main/LICENSE-MIT) at your option.
