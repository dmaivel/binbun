# binbun-cli

The `binbun` command: the command line of [binbun](https://binbun.org), an open-source interactive disassembler and decompiler. It lists a binary's functions, strings and cross-references, prints functions' C, and checks the C against the machine code.

```sh
cargo install binbun-cli
binbun decompile /usr/bin/bash main    # one function's C
binbun verify /usr/bin/bash            # each function's C against its machine code
```

The app, which includes this command, is on [binbun.org](https://binbun.org/download/); the [command-line documentation](https://binbun.org/docs/command-line/) lists every command.

Licensed under either of [Apache License, Version 2.0](https://github.com/dmaivel/binbun/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/dmaivel/binbun/blob/main/LICENSE-MIT) at your option.
