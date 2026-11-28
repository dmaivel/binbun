//! The coding agents a window knows by name ([`HARNESSES`], the one table):
//! each harness's name as shown, the names its MCP client reports, its
//! official mark (the files in the app's `assets/agents/`, drawn large on
//! the avatar's circle in place of the initial; an agent not among them
//! has the Bot glyph), and how it is told to start `binbun mcp` (File ›
//! Connect an Agent…, with the binbun [`setup_binbun`] chooses).

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use crate::collab::{AVATAR_INK, avatar_rgb, luminance};

/// A harness's official mark as an avatar shows it: large on the
/// avatar's circle in place of the initial, as a person's default picture
/// has their initial.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Mark {
    /// Its single-colour form (its shape: the file is drawn as a mask in
    /// the avatar's ink, white or near-black, as initials are).
    pub mono: &'static str,
    /// Its file in the vendor's own colours and those colours, if it may
    /// show them: only where every one of them reads on the circle.
    pub colours: Option<(&'static str, &'static [u32])>,
    /// Its ink's bounds in its file's units (x, y, width, height), as
    /// rendered: a file's box may pad its drawing unevenly, so the mark
    /// is centred and sized by its ink ([`Mark::frame`]).
    pub ink: [f32; 4],
    /// How much of the circle's diameter its ink's longer side takes, in
    /// percent.
    pub across: u8,
}

// Its numbers are the table's constants, never NaN.
impl Eq for Mark {}

impl Mark {
    /// The `viewBox` its file is drawn with (x, y, width, height): a
    /// square centred on the ink, the ink's longer side `across` percent
    /// of it. Drawn over the whole circle, the ink is centred on it to
    /// the subpixel, whatever device pixels the circle falls on.
    pub fn frame(&self) -> [f32; 4] {
        let [x, y, w, h] = self.ink;
        let side = w.max(h) * 100.0 / f32::from(self.across);
        [
            x + w / 2.0 - side / 2.0,
            y + h / 2.0 - side / 2.0,
            side,
            side,
        ]
    }
}

/// `svg` (an SVG file's text) with its root element's `viewBox` set to
/// `frame` and its `width` and `height` dropped (its size then the
/// frame's); `None` if it has no root element.
pub fn framed(svg: &str, frame: [f32; 4]) -> Option<String> {
    let start = svg.find("<svg")?;
    let end = start + svg[start..].find('>')?;
    let mut tag = String::from("<svg");
    let mut rest = &svg[start + 4..end];
    while let Some((name, after)) = rest.split_once("=\"") {
        let (value, after) = after.split_once('"')?;
        let name = name.trim();
        if !matches!(name, "viewBox" | "width" | "height") {
            let _ = write!(tag, " {name}=\"{value}\"");
        }
        rest = after;
    }
    let [x, y, w, h] = frame;
    Some(format!(
        "{}{tag} viewBox=\"{x} {y} {w} {h}\"{rest}{}",
        &svg[..start],
        &svg[end..]
    ))
}

/// How a harness is told to start binbun's MCP server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setup {
    /// A shell command, `{bin}` standing for binbun's path.
    Shell(&'static str),
    /// A JSON config entry for the file named, `{bin}` standing for
    /// binbun's path as a JSON string.
    Json {
        /// Where it goes.
        file: &'static str,
        /// The entry, pretty-printed.
        entry: &'static str,
    },
}

/// A coding agent's harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Harness {
    /// Its name, as shown.
    pub name: &'static str,
    /// The other names it reports (its MCP client's `clientInfo.name`).
    pub aliases: &'static [&'static str],
    /// Its mark; `None`: the Bot glyph.
    pub mark: Option<Mark>,
    /// How it starts `binbun mcp`, if the Connect dialog says it.
    pub setup: Option<Setup>,
}

/// The `mcpServers` entry of Cursor's and omp's config files.
const MCP_SERVERS: &str = r#"{
  "mcpServers": {
    "binbun": {
      "type": "stdio",
      "command": {bin},
      "args": ["mcp"]
    }
  }
}"#;

/// A mark drawn in one ink, the shape of `agents/<file>` (`ink` its
/// ink's bounds), its ink's longer side `across` percent of the circle.
macro_rules! mono {
    ($file:literal, $ink:expr, $across:expr) => {
        Mark {
            mono: concat!("agents/", $file),
            colours: None,
            ink: $ink,
            across: $across,
        }
    };
}

/// The harnesses known by name, in the Connect dialog's order (those with
/// a setup). Their marks' files are bundled by the app (`icons.rs`) under
/// these paths. A single-colour
/// form is the `-light` file of a pair (the shape is the same), or one
/// made of the vendor's paths (`kiro-mono.svg`, `opencode-mono.svg`).
pub const HARNESSES: &[Harness] = &[
    Harness {
        name: "Codex",
        aliases: &["codex-mcp-client"],
        mark: Some(mono!(
            "codex-light.svg",
            [105.24, 105.24, 400.52, 400.52],
            66
        )),
        setup: Some(Setup::Shell("codex mcp add binbun -- {bin} mcp")),
    },
    Harness {
        name: "Claude Code",
        aliases: &["claude-code"],
        mark: Some(Mark {
            colours: Some(("agents/claude-code.svg", &[0x00d9_7757])),
            ..mono!("claude-code.svg", [0.0, 0.0, 256.0, 256.19], 66)
        }),
        setup: Some(Setup::Shell(
            "claude mcp add --scope user binbun -- {bin} mcp",
        )),
    },
    Harness {
        name: "Cursor",
        aliases: &["cursor-vscode"],
        mark: Some(mono!("cursor-light.svg", [0.0, 0.0, 466.73, 532.09], 64)),
        setup: Some(Setup::Json {
            file: "~/.cursor/mcp.json",
            entry: MCP_SERVERS,
        }),
    },
    Harness {
        name: "Grok",
        aliases: &[],
        mark: Some(mono!("grok-light.svg", [0.0, 0.43, 24.0, 23.15], 66)),
        setup: Some(Setup::Shell("grok mcp add binbun -- {bin} mcp")),
    },
    Harness {
        name: "Fx",
        aliases: &["fx"],
        mark: Some(mono!("fx-light.svg", [166.241, 0.0, 155.861, 155.78], 64)),
        setup: Some(Setup::Shell("fx mcp add binbun -- {bin} mcp")),
    },
    Harness {
        name: "OpenCode",
        aliases: &[],
        mark: Some(mono!("opencode-mono.svg", [0.0, 0.0, 32.0, 40.0], 60)),
        setup: Some(Setup::Shell(
            "opencode mcp add binbun --global -- {bin} mcp",
        )),
    },
    Harness {
        name: "Antigravity",
        aliases: &["antigravity-client"],
        mark: Some(Mark {
            colours: Some((
                "agents/antigravity.svg",
                &[
                    0x00ff_e432,
                    0x00fc_413d,
                    0x0000_b95c,
                    0x0031_86ff,
                    0x0074_9bff,
                    0x00fb_bc04,
                    0x00ff_ee48,
                ],
            )),
            ..mono!("antigravity.svg", [0.0, 1.0, 24.0, 22.12], 68)
        }),
        setup: Some(Setup::Shell("agy mcp add binbun {bin} mcp")),
    },
    Harness {
        name: "Kiro",
        aliases: &["Q DEV CLI"],
        mark: Some(mono!("kiro-mono.svg", [272.86, 202.54, 653.91, 795.36], 64)),
        setup: Some(Setup::Shell(
            "kiro-cli mcp add --name binbun --scope global --command {bin} --args mcp",
        )),
    },
    Harness {
        name: "Muse",
        aliases: &["tbh"],
        mark: Some(mono!("muse.svg", [0.0, 0.0, 287.56, 191.0], 72)),
        setup: Some(Setup::Json {
            file: "~/.config/muse/settings.json",
            entry: MCP_SERVERS,
        }),
    },
    Harness {
        name: "Pi",
        aliases: &[],
        mark: Some(mono!("pi-light.svg", [165.29, 165.29, 469.43, 469.43], 56)),
        setup: Some(Setup::Shell("pi mcp add binbun -- {bin} mcp")),
    },
    Harness {
        name: "omp",
        aliases: &["omp-coding-agent"],
        mark: Some(mono!("omp.svg", [0.0, 0.0, 12.0, 10.0], 66)),
        setup: Some(Setup::Json {
            file: "~/.omp/agent/mcp.json",
            entry: MCP_SERVERS,
        }),
    },
    // Known by name, drawn as the Bot.
    Harness {
        name: "Gemini CLI",
        aliases: &["gemini-cli-mcp-client", "gemini"],
        mark: None,
        setup: Some(Setup::Shell("gemini mcp add -s user binbun {bin} mcp")),
    },
];

/// `name` folded for matching: lower case, without spaces, `-` and `_`,
/// and without what a proxy appends (`cursor-vscode (via mcp-remote 0.1)`).
fn folded(name: &str) -> String {
    let name = name.split(" (via ").next().unwrap_or(name);
    name.chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// The harness an agent named `name` runs in, if a known one.
pub fn harness(name: &str) -> Option<&'static Harness> {
    let name = folded(name);
    HARNESSES.iter().find(|harness| {
        folded(harness.name) == name || harness.aliases.iter().any(|a| folded(a) == name)
    })
}

/// An agent named `name` as shown: its harness's name if known, else as
/// it said.
pub fn shown_name(name: &str) -> String {
    harness(name).map_or_else(|| name.trim().to_owned(), |h| h.name.to_owned())
}

/// A participant that is an agent: what it said of itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Agent {
    /// Its harness's version, if it said.
    pub version: Option<String>,
}

/// An agent's face on its avatar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Face {
    /// Its harness's mark.
    Mark(Mark),
    /// The Bot glyph in the avatar's ink (an unknown agent, or a harness
    /// whose mark is not shown).
    Bot,
}

/// The face of an agent named `name`.
pub fn face(name: &str) -> Face {
    harness(name)
        .and_then(|h| h.mark)
        .map_or(Face::Bot, Face::Mark)
}

/// WCAG contrast of two colours (`0xRRGGBB`).
fn contrast(a: u32, b: u32) -> f32 {
    let (a, b) = (luminance(a), luminance(b));
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

/// The least contrast a mark's colours keep with the circle to show.
const LEGIBLE: f32 = 3.0;

/// How a mark is drawn on an avatar.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Drawn {
    /// The file.
    pub file: &'static str,
    /// The ink (`0xRRGGBB`) its shape is drawn in; `None`: in its own
    /// colours.
    pub tint: Option<u32>,
}

/// How `mark` is drawn on an avatar of palette slot `slot` on a dark
/// theme or a light one: in its own colours where every one reads on the
/// circle, else its single-colour form in the ink initials take
/// ([`AVATAR_INK`]); drawn over the whole circle in its [`Mark::frame`].
pub fn drawn(mark: &Mark, slot: usize, dark: bool) -> Drawn {
    let circle = avatar_rgb(slot, dark);
    let (file, tint) = match mark.colours {
        Some((file, colours)) if colours.iter().all(|&c| contrast(c, circle) >= LEGIBLE) => {
            (file, None)
        }
        Some(_) | None => (mark.mono, Some(AVATAR_INK)),
    };
    Drawn { file, tint }
}

/// `path` as a shell word: as it is if it needs no quoting, else quoted
/// (single quotes on Unix, double on Windows).
pub fn shell_word(path: &str) -> String {
    let plain = !path.is_empty()
        && path.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '/' | '\\' | '.' | '_' | '-' | '+' | ':' | '@' | ',' | '=' | '%'
                )
        });
    if plain {
        path.to_owned()
    } else if cfg!(windows) {
        format!("\"{path}\"")
    } else {
        format!("'{}'", path.replace('\'', r"'\''"))
    }
}

/// A row of the Connect dialog: a harness and its setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupRow {
    /// The harness's name.
    pub name: &'static str,
    /// The file the text goes in, if it is a config entry.
    pub file: Option<&'static str>,
    /// The command, or the config entry.
    pub text: String,
}

/// The Connect dialog's rows for binbun at `bin` (absolute).
pub fn setup_rows(bin: &Path) -> Vec<SetupRow> {
    let bin = bin.to_string_lossy();
    HARNESSES
        .iter()
        .filter_map(|harness| Some((harness.name, harness.setup?)))
        .map(|(name, setup)| match setup {
            Setup::Shell(template) => SetupRow {
                name,
                file: None,
                text: template.replace("{bin}", &shell_word(&bin)),
            },
            Setup::Json { file, entry } => SetupRow {
                name,
                file: Some(file),
                text: entry.replace(
                    "{bin}",
                    &serde_json::to_string(bin.as_ref()).unwrap_or_default(),
                ),
            },
        })
        .collect()
}

/// The command's file name, as `PATH` lists it.
const COMMAND: &str = if cfg!(windows) {
    "binbun.exe"
} else {
    "binbun"
};

/// This installation's command, for the app at `exe`: on Windows the
/// console `bin\binbun.exe` beside the app (the release zip's; the app is
/// a GUI program, and a harness runs a console one) when it is there;
/// else `exe`.
pub fn own_command(exe: PathBuf) -> PathBuf {
    if cfg!(windows) {
        let command = exe.with_file_name("bin").join(COMMAND);
        if command.is_file() {
            return command;
        }
    }
    exe
}

/// The binbun the Connect dialog's setups name, `own` being this
/// installation's command ([`own_command`]) and `path` the value of
/// `PATH`: the first `binbun` on `path` (`binbun.exe` on Windows; an
/// executable file in an absolute folder), by the path found, links not
/// followed, when with links followed it is `own`. An update replaces the
/// versioned folder `own` is in, and the link on `PATH` follows it. Else
/// `own` with links followed (without Windows' `\\?\`).
pub fn setup_binbun(own: &Path, path: Option<&OsStr>) -> PathBuf {
    let own_real = fs::canonicalize(own).ok();
    let found = path
        .into_iter()
        .flat_map(std::env::split_paths)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(COMMAND))
        .find(|file| executable(file));
    if let Some(found) = found
        && own_real.is_some()
        && fs::canonicalize(&found).ok() == own_real
    {
        return found;
    }
    binbun_paths::canonical(own).unwrap_or_else(|_| own.to_path_buf())
}

/// The binbun this process's setups name: [`setup_binbun`] for its own
/// command and `PATH`; `binbun` if it cannot say where it is.
pub fn this_binbun() -> PathBuf {
    std::env::current_exe().map_or_else(
        |_| PathBuf::from("binbun"),
        |exe| setup_binbun(&own_command(exe), std::env::var_os("PATH").as_deref()),
    )
}

/// Runs a harness's setup `command` (a [`Setup::Shell`]'s) as the user's
/// shell runs it in a terminal: a login, interactive one, so that its
/// `PATH` is the one the harness was found on; on Windows through `cmd`.
///
/// # Errors
///
/// The last line it wrote if it fails, or why it did not run.
pub fn run_setup(command: &str) -> Result<(), String> {
    #[cfg(windows)]
    let mut shell = {
        use std::os::windows::process::CommandExt as _;
        /// No console window flashing up for it.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut shell = std::process::Command::new("cmd");
        shell
            .arg("/C")
            .raw_arg(command)
            .creation_flags(CREATE_NO_WINDOW);
        shell
    };
    #[cfg(not(windows))]
    let mut shell = {
        let program = std::env::var_os("SHELL")
            .filter(|shell| !shell.is_empty())
            .unwrap_or_else(|| "sh".into());
        let mut shell = std::process::Command::new(program);
        shell.args(["-l", "-i", "-c", command]);
        shell
    };
    let out = shell
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    Err(crate::python_env::last_said(&out))
}

/// Where the harnesses not to offer binbun's setup to are kept
/// ([`binbun_paths::Place::QuietAgents`]).
pub fn quiet_path() -> Option<PathBuf> {
    binbun_paths::Place::QuietAgents.path()
}

/// A `binbun mcp` an agent's harness started, as it announces itself to
/// the windows (`agent-<pid>.json` in [`binbun_paths::Place::Servers`],
/// written by `binbun-cli`'s `mcp::announce`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announced {
    /// The agent it serves (`Claude Code`).
    pub agent: String,
    /// When it started, in Unix milliseconds.
    pub started: u64,
    /// How its interpreter's start went.
    pub start: Start,
}

/// How an announced server's interpreter's start went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    /// Not yet known.
    Starting,
    /// Its interpreter runs (the agent joins the window).
    Ready,
    /// It failed, saying this.
    Failed(String),
}

/// The servers announced in `dir`, in no order (a file that does not
/// read as one skipped).
pub fn announced(dir: &Path) -> Vec<Announced> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|e| e == "json")
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("agent-"))
        })
        .filter_map(|path| {
            let value: serde_json::Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
            let text = |key| value.get(key).and_then(serde_json::Value::as_str);
            let start = match text("state")? {
                "starting" => Start::Starting,
                "ready" => Start::Ready,
                "failed" => Start::Failed(text("error").unwrap_or("no reason given").to_owned()),
                _ => return None,
            };
            Some(Announced {
                agent: text("agent")?.to_owned(),
                started: value.get("started")?.as_u64()?,
                start,
            })
        })
        .collect()
}

/// The harnesses named in the file at `path`, one a line (none if it is
/// not there).
pub fn read_quiet(path: &Path) -> BTreeSet<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `names` written to the file at `path`, one a line, its folder made.
///
/// # Errors
///
/// The folder or the file that could not be written, and why.
pub fn write_quiet(path: &Path, names: &BTreeSet<String>) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let text = names.iter().fold(String::new(), |mut text, name| {
        let _ = writeln!(text, "{name}");
        text
    });
    fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Whether `file` is a file this user may run (on Windows, any file).
fn executable(file: &Path) -> bool {
    let Ok(metadata) = fs::metadata(file) else {
        return false;
    };
    #[cfg(unix)]
    let runs = {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let runs = true;
    metadata.is_file() && runs
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// The single-colour file of the mark of agent `name`.
    fn mono_file(name: &str) -> &'static str {
        match face(name) {
            Face::Mark(mark) => mark.mono,
            Face::Bot => "bot",
        }
    }

    #[test]
    fn agents_are_known_by_their_names_and_their_clients_names() {
        for (name, shown) in [
            ("Codex", "Codex"),
            ("codex-mcp-client", "Codex"),
            ("Claude Code", "Claude Code"),
            ("claude-code", "Claude Code"),
            ("cursor-vscode (via mcp-remote 0.1.37)", "Cursor"),
            ("Gemini CLI", "Gemini CLI"),
            ("opencode", "OpenCode"),
            ("pi", "Pi"),
            ("omp-coding-agent", "omp"),
            ("grok", "Grok"),
            ("antigravity", "Antigravity"),
            ("kiro", "Kiro"),
        ] {
            assert_eq!(shown_name(name), shown, "{name}");
        }
        assert_eq!(mono_file("codex-mcp-client"), "agents/codex-light.svg");
        assert_eq!(mono_file("Claude Code"), "agents/claude-code.svg");
        assert_eq!(mono_file("OpenCode"), "agents/opencode-mono.svg");
        assert_eq!(mono_file("omp-coding-agent"), "agents/omp.svg");
        // Gemini CLI is known by name but drawn as the Bot, as is an
        // unknown agent, named as it said.
        assert_eq!(face("Gemini CLI"), Face::Bot);
        assert_eq!(face("Aider"), Face::Bot);
        assert_eq!(harness("Aider"), None);
        assert_eq!(shown_name("Aider"), "Aider");
    }

    #[test]
    fn a_mark_is_large_in_the_initials_ink_or_its_colours_where_they_read() {
        // A single-colour mark is drawn in the initials' ink, on any
        // circle.
        let codex = mono!("codex.svg", [0.0, 0.0, 10.0, 10.0], 64);
        let on_amber = drawn(&codex, 2, true);
        assert_eq!(on_amber.tint, Some(AVATAR_INK));
        assert_eq!(on_amber.file, "agents/codex.svg");
        // Its own colours only where every one reads on the circle: a
        // white mark on the deep blue, not on the dark theme's light amber;
        // never a many-coloured
        // one whose colours clash with any circle.
        let white = Mark {
            colours: Some(("agents/white.svg", &[0x00ff_ffff])),
            ..codex
        };
        assert_eq!(drawn(&white, 6, false).tint, None);
        assert_eq!(drawn(&white, 6, false).file, "agents/white.svg");
        assert_eq!(drawn(&white, 2, true).file, "agents/codex.svg");
        let Face::Mark(antigravity) = face("Antigravity") else {
            panic!("Antigravity has its mark");
        };
        assert!((0..20).all(|slot| drawn(&antigravity, slot, slot % 2 == 0).tint.is_some()));
    }

    #[test]
    fn a_mark_is_framed_square_on_its_ink_at_its_share() {
        let close = |a: [f32; 4], b: [f32; 4]| a.iter().zip(b).all(|(a, b)| (a - b).abs() < 1e-4);
        // Ink 20 by 10 at (10, 30): a square 20 / 0.6 on its centre (20,
        // 35), whatever box the file had.
        let wide = mono!("wide.svg", [10.0, 30.0, 20.0, 10.0], 60);
        let side = 20.0 / 0.6;
        assert!(close(
            wide.frame(),
            [20.0 - side / 2.0, 35.0 - side / 2.0, side, side]
        ));
        // A tall one by its height.
        let tall = mono!("tall.svg", [0.0, 0.0, 30.0, 40.0], 80);
        assert!(close(tall.frame(), [-10.0, -5.0, 50.0, 50.0]));
    }

    #[test]
    fn framing_replaces_the_root_box_and_drops_its_size() {
        let svg = "<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"256\" height=\"257\" viewBox=\"0 0 256 257\" fill=\"none\"><rect width=\"4\" height=\"4\"/></svg>";
        assert_eq!(
            framed(svg, [-1.5, 2.0, 30.0, 30.0]).as_deref(),
            Some(
                "<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" fill=\"none\" viewBox=\"-1.5 2 30 30\"><rect width=\"4\" height=\"4\"/></svg>"
            )
        );
        assert_eq!(framed("<g/>", [0.0, 0.0, 1.0, 1.0]), None);
    }

    #[test]
    fn connect_rows_embed_binbuns_absolute_path() {
        let bin = PathBuf::from("/opt/binbun/bin/binbun");
        let rows = setup_rows(&bin);
        let row = |name: &str| {
            rows.iter()
                .find(|r| r.name == name)
                .unwrap_or_else(|| panic!("{name} has a row"))
        };
        assert_eq!(
            row("Codex").text,
            "codex mcp add binbun -- /opt/binbun/bin/binbun mcp"
        );
        assert_eq!(
            row("Claude Code").text,
            "claude mcp add --scope user binbun -- /opt/binbun/bin/binbun mcp"
        );
        assert_eq!(
            row("Gemini CLI").text,
            "gemini mcp add -s user binbun /opt/binbun/bin/binbun mcp"
        );
        let cursor: serde_json::Value = serde_json::from_str(&row("Cursor").text).unwrap();
        assert_eq!(
            cursor["mcpServers"]["binbun"]["command"],
            "/opt/binbun/bin/binbun"
        );
        assert_eq!(row("Cursor").file, Some("~/.cursor/mcp.json"));
        assert!(
            rows.iter()
                .all(|r| r.text.contains("/opt/binbun/bin/binbun"))
        );
        // A path with a space is quoted for the shell, and escaped in JSON.
        let spaced = setup_rows(&PathBuf::from("/home/a b/binbun"));
        if !cfg!(windows) {
            assert_eq!(
                spaced[0].text,
                "codex mcp add binbun -- '/home/a b/binbun' mcp"
            );
        }
        assert!(spaced[2].text.contains("\"/home/a b/binbun\""));
    }

    /// A folder of its own for `name`, empty.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("binbun-setup-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `dir/binbun` (`binbun.exe` on Windows), executable, made.
    fn command_in(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let file = dir.join(COMMAND);
        fs::write(&file, b"binbun").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        }
        file
    }

    fn path_of(dirs: &[&Path]) -> std::ffi::OsString {
        std::env::join_paths(dirs).unwrap()
    }

    #[test]
    fn a_binbun_on_path_other_than_this_one_is_not_named() {
        let dir = scratch("other");
        let own = command_in(&dir.join("lib").join("1.0").join("bin"));
        let own_real = binbun_paths::canonical(&own).unwrap();
        // No PATH, or none on it.
        assert_eq!(setup_binbun(&own, None), own_real);
        assert_eq!(
            setup_binbun(&own, Some(&path_of(&[&dir.join("none")]))),
            own_real
        );
        // Another binbun first on PATH: this one, by its own path.
        let other = dir.join("other");
        command_in(&other);
        let own_dir = own.parent().unwrap();
        assert_eq!(
            setup_binbun(&own, Some(&path_of(&[&other, own_dir]))),
            own_real
        );
        // This one first on PATH: named as PATH has it.
        assert_eq!(setup_binbun(&own, Some(&path_of(&[own_dir, &other]))), own);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_on_path_to_this_binbun_is_named_as_the_link() {
        let dir = scratch("link");
        let own = command_in(&dir.join("lib").join("1.0").join("bin"));
        let bin = dir.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let link = bin.join(COMMAND);
        std::os::unix::fs::symlink(&own, &link).unwrap();
        // A `binbun` that is not executable comes first: passed over.
        let first = dir.join("first");
        fs::create_dir_all(&first).unwrap();
        fs::write(first.join(COMMAND), b"data").unwrap();
        let path = path_of(&[&first, &bin]);
        assert_eq!(setup_binbun(&own, Some(&path)), link);
        // The link leads elsewhere once this binbun is another version's.
        let newer = command_in(&dir.join("lib").join("2.0").join("bin"));
        assert_eq!(
            setup_binbun(&newer, Some(&path)),
            binbun_paths::canonical(&newer).unwrap()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn the_app_names_the_command_in_bin_beside_it() {
        let dir = scratch("app");
        let app = dir.join("binbun.exe");
        fs::write(&app, b"app").unwrap();
        assert_eq!(own_command(app.clone()), app);
        let command = command_in(&dir.join("bin"));
        assert_eq!(own_command(app), command);
        let _ = fs::remove_dir_all(&dir);
    }
}
