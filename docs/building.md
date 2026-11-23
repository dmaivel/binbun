# Building

The toolchain is pinned in `rust-toolchain.toml`, so `rustup` installs the right version on the first build. The app is built on [GPUI](https://www.gpui.rs) and needs its platform libraries on Linux:

```sh
# Debian, Ubuntu
sudo apt install build-essential pkg-config libfontconfig-dev libxcb1-dev libxkbcommon-dev libxkbcommon-x11-dev
# Fedora
sudo dnf install gcc pkgconf-pkg-config fontconfig-devel libxcb-devel libxkbcommon-devel libxkbcommon-x11-devel
# Arch
sudo pacman -S base-devel fontconfig libxcb libxkbcommon libxkbcommon-x11
```

```sh
cargo build --release -p binbun-cli    # binbun without the GUI: target/release/binbun
(cd gui && cargo build --release)      # binbun with the GUI: gui/target/release/binbun
maturin build --release                # the Python wheel: target/wheels
```

## Running from the tree

```sh
cargo run --release -p binbun-cli -- functions /usr/lib/libc.so.6
cargo run --release -p binbun-cli -- cfg /usr/lib/libc.so.6 abort --dot | dot -Tsvg > abort.svg
cargo run --release -p binbun-cli -- eval --seeds entry /usr/lib/libc.so.6 /usr/bin/bash
cargo run --release -p binbun-cli -- strings /usr/bin/bash --referenced
cargo run --release -p binbun-cli -- xrefs /usr/lib/libc.so.6 _IO_2_1_stdout_
cargo run --release -p binbun-cli -- xrefs /usr/lib/libc.so.6 --from abort
```

`eval` compares the recovered functions with those the file states (function symbols and unwind table entries): `--seeds entry` starts only from the entry point and exports, as for a stripped binary, and measures how many functions following the code finds; `--seeds all` starts from everything the file states. It also checks the graph's invariants (no unexplained overlapping blocks, a block at every direct jump target).
