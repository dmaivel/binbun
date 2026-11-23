//! `binbun paths`: where binbun keeps its files ([`binbun_paths`]), each
//! folder with its size; `--json` as one object, the folders in order;
//! `binbun paths NAME` one folder's path alone, for scripts.

use std::fmt::Write as _;

use binbun_paths::{Dir, Folder, folders, size_text};

use super::USAGE;

/// `paths [NAME] [--json]`.
pub fn paths(args: &[String]) -> Result<String, String> {
    let mut json = false;
    let mut named = None;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            name if named.is_none() && !name.starts_with('-') => {
                named = Some(Dir::named(name).ok_or_else(|| {
                    format!(
                        "binbun paths: no folder {name}: one of {}",
                        Dir::ALL.map(Dir::name).join(", ")
                    )
                })?);
            }
            _ => return Err(USAGE.to_owned()),
        }
    }
    let Some(dir) = named else {
        let listed = folders(true);
        return Ok(if json {
            format!("{}\n", json_object(&listed))
        } else {
            text(&listed)
        });
    };
    if json {
        let listed: Vec<Folder> = folders(true)
            .into_iter()
            .filter(|folder| folder.dir == dir)
            .collect();
        return Ok(format!("{}\n", json_object(&listed)));
    }
    let path = dir.path().ok_or_else(|| dir.missing())?;
    Ok(format!("{}\n", path.display()))
}

/// The folders a line each: name, path, size (`-` for a folder without a
/// place, and why).
fn text(listed: &[Folder]) -> String {
    let width = listed
        .iter()
        .filter_map(|folder| folder.path.as_ref())
        .map(|path| path.display().to_string().chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for folder in listed {
        let name = folder.dir.name();
        let _ = match &folder.path {
            Some(path) => writeln!(
                out,
                "{name:<8} {:<width$}  {}",
                path.display().to_string(),
                size_text(folder.size.unwrap_or(0))
            ),
            None => writeln!(out, "{name:<8} -  ({})", folder.dir.missing()),
        };
    }
    out
}

/// The folders as one JSON object, keyed by name in order:
/// `{"config": {"path": "…", "size": 123}, …}`, a folder without a place
/// `{"path": null, "size": null}`.
fn json_object(listed: &[Folder]) -> String {
    let entries: Vec<String> = listed
        .iter()
        .map(|folder| {
            let path = folder
                .path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned());
            let size = folder.path.as_ref().and(folder.size);
            format!(
                "{}: {{\"path\": {}, \"size\": {}}}",
                serde_json::Value::from(folder.dir.name()),
                serde_json::Value::from(path),
                serde_json::Value::from(size)
            )
        })
        .collect();
    format!("{{{}}}", entries.join(", "))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use binbun_paths::{Dir, Folder};

    use super::{json_object, text};

    /// The JSON is an object of the folders in order, paths escaped, a
    /// folder without a place null.
    #[test]
    fn json_keeps_the_order_and_escapes_paths() {
        let listed = [
            Folder {
                dir: Dir::State,
                path: Some(PathBuf::from(r#"C:\Users\a "b"\state"#)),
                size: Some(12),
            },
            Folder {
                dir: Dir::Config,
                path: None,
                size: Some(0),
            },
        ];
        let json = json_object(&listed);
        assert_eq!(
            json,
            r#"{"state": {"path": "C:\\Users\\a \"b\"\\state", "size": 12}, "config": {"path": null, "size": null}}"#
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["state"]["path"], r#"C:\Users\a "b"\state"#);
    }

    /// The text aligns the paths and reads the sizes.
    #[test]
    fn text_aligns_paths_and_reads_sizes() {
        let listed = [
            Folder {
                dir: Dir::Config,
                path: Some(PathBuf::from("/c")),
                size: Some(1_500),
            },
            Folder {
                dir: Dir::Cache,
                path: Some(PathBuf::from("/cache")),
                size: Some(0),
            },
        ];
        assert_eq!(
            text(&listed),
            "config   /c      1.5 KB\ncache    /cache  0 bytes\n"
        );
    }
}
