+++
title = "Platforms and files"
weight = 120
+++

## Desktop and headless installations

Linux desktop archives contain the app and command line in one executable. The glibc release build targets glibc 2.28 or later. The desktop requires its window-system and graphics libraries; the installer checks for `libxcb`, `libxkbcommon` and `libxkbcommon-x11`. Use the CLI-only archive on a headless host. Musl targets use the CLI-only build.

The macOS app is packaged as a DMG for the selected architecture, with macOS 12.0 as the packaging deployment target. The app is ad-hoc signed, not Developer ID signed or notarised. After opening a browser-downloaded app, Gatekeeper can require **System Settings → Privacy & Security → Open Anyway**. Only approve a download whose origin and digest you have checked.

Windows uses a portable zip with the app, `binbun.exe`, the command, `bin\binbun.exe`, their data and licences. Open the app from `binbun.exe`; it shows no console window. Run commands with `bin\binbun.exe`, and add the `bin` folder to `PATH` to type `binbun` in a shell; `binbun FILE` there opens the file in the app. The C runtime is linked into both executables; no Visual C++ redistributable is required. The executables are unsigned. SmartScreen may show **Windows protected your PC**; **More info → Run anyway** is the override if you checked the download's checksum. Managed machines may not allow that override.

Keep the archive's folders together rather than copying an executable alone. Signature packs are separate files. Use the [download page](/download/) for the assets, checksums and installation instructions for the release.

## Files binbun analyses

The loader reads ELF, PE and Mach-O, including universal Mach-O files. The disassemblers cover x86 and x86-64 and AArch64 A64; decompilation requires supported x86-64 or AArch64 instruction semantics. Being able to list a 32-bit x86 executable does not mean its C can be recovered.

The app chooses a universal file's slice on opening. **File → Reopen as Slice…** switches to another. Each slice has its own content-keyed project. A shared session's ticket identifies the slice so another machine opens the same image.

Debug information can come from DWARF, PDB or dSYM. Separate debug files must match the binary's identifiers. The GUI can ask before fetching from a symbol server; the CLI only fetches when explicitly requested. Symbol-server requests reveal which binary's debug information is wanted.

## Find the actual directories

```sh
binbun paths
binbun paths cache
binbun paths --json
```

The full listing includes directory sizes. The named form prints one path; the JSON form gives each directory's `path` and `size`. **Help → Files and Folders…** exposes them in the GUI, and **File → Reveal Projects** opens the project directory.

Without overrides, the base directories are:

| Kind | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Config | `~/.config/binbun` | `~/.config/binbun` | `%APPDATA%\binbun` |
| Data | `~/.local/share/binbun` | `~/Library/Application Support/binbun` | `%LOCALAPPDATA%\binbun` |
| State | `~/.local/state/binbun` | `~/Library/Application Support/binbun/state` | `%LOCALAPPDATA%\binbun\state` |
| Cache | `~/.cache/binbun` | `~/Library/Caches/binbun` | `%LOCALAPPDATA%\binbun\cache` |
| Runtime | `$XDG_RUNTIME_DIR/binbun` | `$TMPDIR/binbun` | `%LOCALAPPDATA%\binbun\run` |

`BINBUN_HOME` relocates config, data, state and cache into subdirectories of that name. It deliberately does not relocate runtime sockets and discovery files. Otherwise the corresponding XDG variable overrides each base directory, on all platforms. Overrides must be absolute paths; empty or relative values are ignored. On Windows, `HOME` does not replace the Windows user directories.

## What belongs where

- **Config** holds `settings.toml`, `startup.py` and user themes in `themes`.
- **Data** holds `projects`, the identity's private keys in `identity` and user packs in `signatures`.
- **State** holds recent files, remembered universal slices, console history, the skipped-update choice and the agents not to offer setup to (`quiet-agents`).
- **Cache** holds downloaded symbols in `symbols`. Clearing it can require another download, but it is not where your project edits live.
- **Runtime** holds live-server sockets or named-pipe discovery files used by Python connections.

A project contains edits, its log, layout, hex overlays, the Pathfinder question and saved example states. Private bookmarks and the processor choice stay local. Exported `.binbun` projects do not include the analysed binary, private bookmarks or active sharing state.

Back up data, not just config, if you want to retain projects and identity. Do not sync the identity's private key through a public configuration repository. A file moved or renamed finds its existing project by content; a changed file starts a new project. Deleting a cache is not the same as deleting that project's data.
