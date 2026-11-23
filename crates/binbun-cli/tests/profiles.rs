//! Processor profiles through the CLI, on `tests/fixtures/undefined-x86_64.s`, whose
//! functions read flags SHRD leaves undefined: `run`, `verify` and
//! `stages` on a profile, `verify --compare`, and (ignored, pinned to one
//! core type) the functions run natively against `binbun run` on the
//! profile measured there.
//!
//! ```sh
//! sh scripts/fixture-call.sh
//! for cpus in 0 16; do
//!   BINBUN_FIXTURE_CALL=$PWD/target/fixture-call taskset -c $cpus \
//!     cargo test --release -p binbun-cli --test profiles -- --ignored
//! done
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The fixture.
fn fixture() -> String {
    format!(
        "{}/../../tests/fixtures/undefined-x86_64.elf",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// A scratch directory of this test's own, emptied.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("profiles-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `binbun ARGS`' standard output; it must succeed.
fn binbun(args: &[&str]) -> String {
    exits(args, 0)
}

/// `binbun ARGS`' standard output; it must exit with `status`.
fn exits(args: &[&str], status: i32) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(status), "{args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// A state file in `dir` for `arguments`.
fn state(dir: &Path, name: &str, arguments: &[u64]) -> String {
    let path = dir.join(format!("{name}.toml"));
    let list: Vec<String> = arguments
        .iter()
        .map(|argument| format!("\"{argument:#x}\""))
        .collect();
    std::fs::write(
        &path,
        format!(
            "format = 1\nname = \"{name}\"\narguments = [{}]\n",
            list.join(", ")
        ),
    )
    .unwrap();
    path.to_str().unwrap().to_owned()
}

/// What `binbun run` printed: L2's return value (as printed: decimal if
/// small, else hexadecimal), and whether the machine code agrees.
fn returned(out: &str) -> (Option<u64>, bool) {
    let line = out
        .lines()
        .find(|line| line.starts_with("/* run "))
        .unwrap_or_else(|| panic!("{out}"));
    let value = line
        .split_once("): returned ")
        .and_then(|(_, rest)| rest.split_once(';'))
        .and_then(|(value, _)| match value.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => value.parse().ok(),
        });
    (value, out.contains("agrees with the C: true"))
}

/// The run's C without the values at the lines' ends.
fn c_of(out: &str) -> String {
    out.lines()
        .take_while(|line| !line.starts_with("/* run "))
        .map(|line| line.split_once("  //").map_or(line, |(c, _)| c).trim_end())
        .collect::<Vec<_>>()
        .join("\n")
}

const PROFILES: [&str; 2] = ["intel-raptor-cove", "intel-gracemont"];

#[test]
fn runs_take_the_profiles_values_and_the_c_does_not_change() {
    let dir = scratch("runs");
    let path = fixture();
    // The post's input: OF 1 on the P-cores, 0 on the E-cores; so `jo`
    // returns 1 on the first, 2 on the second. The probe's 0x4780000000:
    // OF 0 on both.
    for (input, expected) in [(0x8f, [1, 2]), (0x47_8000_0000, [2, 2])] {
        let state = state(&dir, &format!("jo-{input:x}"), &[input]);
        for view in ["exact", "reading"] {
            let none = binbun(&["run", &path, "shrd_jo", "--state", &state, "--view", view]);
            assert!(
                none.contains("architecture (any processor)): undetermined"),
                "{none}"
            );
            for (profile, expected) in PROFILES.iter().zip(expected) {
                let out = binbun(&[
                    "run",
                    &path,
                    "shrd_jo",
                    "--state",
                    &state,
                    "--view",
                    view,
                    "--profile",
                    profile,
                ]);
                assert_eq!(returned(&out), (Some(expected), true), "{profile}: {out}");
                assert!(out.contains(&format!("{profile} r2): returned")), "{out}");
                // The decision the profile's value made is marked.
                assert!(out.contains(&format!("[{profile}]")), "{out}");
                assert_eq!(c_of(&out), c_of(&none), "{profile}, {view}");
            }
        }
    }
}

#[test]
fn verify_on_a_profile_checks_what_depends_on_the_sites() {
    let path = fixture();
    // Every state skipped: nothing checked, exit status 3.
    let skipped = exits(&["verify", &path, "shrd_jo"], 3);
    assert!(
        skipped.contains("L1 depends on undefined bits"),
        "{skipped}"
    );
    // No such function: an error, 2.
    exits(&["verify", &path, "no_such_function"], 2);
    for name in ["shrd_jo", "shrd_seto", "shrd_lahf", "two_shrds"] {
        for profile in PROFILES {
            for view in ["exact", "reading"] {
                let out = binbun(&["verify", &path, name, "--profile", profile, "--view", view]);
                assert!(
                    out.contains(&format!(
                        "on {profile} r2: agreed on 24 of 24 sampled states\n"
                    )),
                    "{out}"
                );
                assert!(!out.contains("skipped"), "{out}");
            }
        }
    }
}

#[test]
fn stages_names_each_sites_rule() {
    let path = fixture();
    let plain = binbun(&["stages", &path, "shrd_jo", "--stage", "c"]);
    let p = binbun(&[
        "stages",
        &path,
        "shrd_jo",
        "--stage",
        "c",
        "--profile",
        "intel-raptor-cove",
    ]);
    let e = binbun(&[
        "stages",
        &path,
        "shrd_jo",
        "--stage",
        "c",
        "--profile",
        "intel-gracemont",
    ]);
    // The stage's text first, unchanged; then the sites.
    assert!(p.starts_with(&plain) && e.starts_with(&plain), "{p}\n{e}");
    assert!(
        p.contains("sites on intel-raptor-cove r2:\n  0x20116a  shrd.af: 0\n  0x20116a  shrd.of: msb(dst) ^ bit(src, 0)\n"),
        "{p}"
    );
    assert!(
        e.contains("  0x20116a  shrd.of: msb(defined.dst) ^ bit(defined.dst, osz - 2)\n"),
        "{e}"
    );
    // A file by its path; a name that is neither, refused.
    let file = format!(
        "{}/../binbun-x86-lift/profiles/intel-gracemont.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    let by_path = binbun(&[
        "stages",
        &path,
        "shrd_jo",
        "--stage",
        "c",
        "--profile",
        &file,
    ]);
    assert_eq!(by_path, e);
    let output = Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(["stages", &path, "shrd_jo", "--profile", "intel-pentium"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

/// It differs: exit status 1.
#[test]
fn compare_finds_where_the_processors_differ() {
    let dir = scratch("compare");
    let path = fixture();
    let save = dir.to_str().unwrap();
    let compare = [
        "verify",
        &path,
        "shrd_jo",
        "--compare",
        "intel-raptor-cove,intel-gracemont",
        "--save",
        save,
    ];
    let out = exits(&compare, 1);
    let first = out.lines().next().unwrap();
    assert!(
        first.starts_with(
            "shrd_jo at 0x201167 on intel-raptor-cove r2, intel-gracemont r2: differs: 24 states"
        ),
        "{out}"
    );
    assert!(first.ends_with("(shrd.af 24, shrd.of 24)"), "{out}");
    // OF is 1 on one processor and 0 on the other, either way round: two
    // ways the states differ, each shown once by its first state (the
    // return values per processor, the site that decided with each rule)
    // and how many more differ that way; no state's registers.
    let shown: Vec<(u64, u64)> = out
        .lines()
        .filter_map(|line| line.strip_prefix("    intel-raptor-cove r2: returns 0x"))
        .zip(
            out.lines()
                .filter_map(|line| line.strip_prefix("    intel-gracemont r2: returns 0x")),
        )
        .map(|(p, e)| {
            let parse = |text: &str| u64::from_str_radix(text.trim_end_matches(":32"), 16).unwrap();
            (parse(p), parse(e))
        })
        .collect();
    assert_eq!(
        shown.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([(1, 2), (2, 1)]),
        "{out}"
    );
    assert_eq!(
        out.matches("    decided by shrd.of at 0x20116a: intel-raptor-cove ")
            .count(),
        2,
        "{out}"
    );
    assert!(
        out.contains(" by `msb(dst) ^ bit(src, 0)`; intel-gracemont "),
        "{out}"
    );
    let more: usize = out
        .lines()
        .filter_map(|line| line.strip_prefix("    "))
        .filter_map(|line| line.split_once(" more state"))
        .map(|(n, rest)| {
            assert!(rest.ends_with(" the same way"), "{out}");
            n.parse::<usize>().unwrap()
        })
        .sum();
    let count = |what: &str| -> usize {
        let (before, _) = first.split_once(what).unwrap();
        before.rsplit(' ').next().unwrap().parse().unwrap()
    };
    assert_eq!(
        more + shown.len(),
        24 - count(" same,") - count(" skipped,"),
        "{out}"
    );
    assert!(!out.contains("    state: "), "{out}");
    // Every state kept is saved, and opens as a run returning, on each
    // processor, what the comparison said (the first shown: exactly).
    let saved: Vec<&str> = out
        .lines()
        .filter_map(|line| line.split_once("saved: ").map(|(_, file)| file))
        .collect();
    assert_eq!(saved.len(), 4, "{out}");
    for (n, file) in saved.iter().enumerate() {
        let returns: Vec<u64> = PROFILES
            .iter()
            .map(|profile| {
                let run = binbun(&[
                    "run",
                    &path,
                    "shrd_jo",
                    "--state",
                    file,
                    "--profile",
                    profile,
                ]);
                let (value, agrees) = returned(&run);
                assert!(agrees, "{profile}: {run}");
                value.unwrap()
            })
            .collect();
        if n == 0 {
            assert_eq!(returns, [shown[0].0, shown[0].1], "{out}");
        } else {
            assert!(
                returns == [1, 2] || returns == [2, 1],
                "{file}: {returns:?}"
            );
        }
    }
}

/// With `--states-full`, each differing state kept is described, with
/// its registers.
#[test]
fn compare_states_full_shows_each_state_kept() {
    let path = fixture();
    let full = exits(
        &[
            "verify",
            &path,
            "shrd_jo",
            "--compare",
            "intel-raptor-cove,intel-gracemont",
            "--states-full",
        ],
        1,
    );
    assert_eq!(full.matches("\n    state: ").count(), 4, "{full}");
    assert!(full.contains("\n    state: rax="), "{full}");
}

#[test]
fn compare_says_same_and_not_reached() {
    let path = fixture();
    // The same function on one processor twice: the same.
    let twice = binbun(&[
        "verify",
        &path,
        "shrd_jo",
        "--compare",
        "intel-gracemont,intel-gracemont",
    ]);
    assert!(
        twice.contains(": same: 24 states, 24 same, 0 skipped, 24 reached a site"),
        "{twice}"
    );
    // AF: 0 on both.
    let lahf = binbun(&[
        "verify",
        &path,
        "shrd_lahf",
        "--compare",
        "intel-raptor-cove,intel-gracemont",
    ]);
    assert!(lahf.contains(": same: 24 states"), "{lahf}");
    // A function that reaches no site before its first call: no answer.
    let start = binbun(&[
        "verify",
        &path,
        "_start",
        "--compare",
        "intel-raptor-cove,intel-gracemont",
    ]);
    assert!(
        start.contains(": same: no state reached a site:"),
        "{start}"
    );
    // The whole file: the functions that differ (exit status 1).
    let all = exits(
        &[
            "verify",
            &path,
            "--compare",
            "intel-raptor-cove,intel-gracemont",
        ],
        1,
    );
    assert!(
        all.lines()
            .next()
            .unwrap()
            .contains(": 7 functions: differ "),
        "{all}"
    );
    assert!(all.contains("\nshrd_jo at 0x201167 on "), "{all}");
}

/// The CPUs this process may run on.
fn allowed_cpus() -> BTreeSet<u32> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    cpu_list(
        status
            .lines()
            .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
            .unwrap()
            .trim(),
    )
}

/// The CPUs of a Linux CPU list (`0-15,20`).
fn cpu_list(text: &str) -> BTreeSet<u32> {
    text.split(',')
        .filter(|range| !range.is_empty())
        .flat_map(|range| {
            let (first, last) = range.split_once('-').unwrap_or((range, range));
            first.parse().unwrap()..=last.parse().unwrap()
        })
        .collect()
}

/// A 64-bit random number generator (`SplitMix64`).
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut x = self.0;
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    /// A value biased to edges: a quarter of them one bit, all ones, a
    /// sign bit or small.
    fn value(&mut self) -> u64 {
        let raw = self.next();
        match raw % 8 {
            0 => 1 << (self.next() % 64),
            1 => u64::MAX >> (self.next() % 64),
            _ => raw,
        }
    }
}

/// The fixture's `function` called natively (`fixture-call`, pinned as
/// this process is) on each input pair.
fn native(call: &str, function: &str, inputs: &[(u64, u64)]) -> Vec<u64> {
    let mut child = Command::new(call)
        .args([&fixture(), function])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut text = String::new();
    for (rdi, rsi) in inputs {
        let _ = writeln!(text, "{rdi:x} {rsi:x}");
    }
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| u64::from_str_radix(line, 16).unwrap())
        .collect()
}

/// The fixture's functions that read what SHRD leaves undefined return,
/// called natively on this core type, exactly what `binbun run` returns
/// on the profile measured on it, for 1,000 random inputs each.
#[test]
#[ignore = "needs BINBUN_FIXTURE_CALL (scripts/fixture-call.sh), run pinned to one core type"]
fn the_fixture_runs_as_the_processor_does() {
    let call = std::env::var("BINBUN_FIXTURE_CALL").expect("BINBUN_FIXTURE_CALL");
    let count: usize = std::env::var("BINBUN_FIXTURE_INPUTS").map_or(1000, |n| n.parse().unwrap());
    let allowed = allowed_cpus();
    let profile = binbun::profile::embedded()
        .iter()
        .find(|profile| allowed.is_subset(&cpu_list(&profile.measured.cpus)))
        .unwrap_or_else(|| {
            panic!("pin to the CPUs a shipped profile was measured on (allowed: {allowed:?})")
        });
    let dir = scratch(&profile.id);
    let mut random = Random(0x5eed_f00d);
    for (function, arguments) in [("shrd_jo", 1), ("shrd_seto", 2), ("shrd_lahf", 2)] {
        let inputs: Vec<(u64, u64)> = (0..count)
            .map(|_| (random.value(), random.value()))
            .collect();
        let expected = native(&call, function, &inputs);
        assert_eq!(expected.len(), inputs.len());
        let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
        let chunk = inputs.len().div_ceil(threads);
        let got: Vec<(Option<u64>, bool)> = std::thread::scope(|scope| {
            let handles: Vec<_> = inputs
                .chunks(chunk)
                .enumerate()
                .map(|(part, inputs)| {
                    let dir = &dir;
                    let id = &profile.id;
                    scope.spawn(move || {
                        inputs
                            .iter()
                            .enumerate()
                            .map(|(k, &(rdi, rsi))| {
                                let name = format!("{function}-{part}-{k}");
                                let pair = [rdi, rsi];
                                let state = state(dir, &name, &pair[..arguments]);
                                let out = binbun(&[
                                    "run",
                                    &fixture(),
                                    function,
                                    "--state",
                                    &state,
                                    "--profile",
                                    id,
                                ]);
                                returned(&out)
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap())
                .collect()
        });
        for ((input, native), (run, agrees)) in inputs.iter().zip(&expected).zip(&got) {
            assert_eq!(
                (*run, *agrees),
                (Some(*native), true),
                "{} {function}{input:x?}: native {native:#x}",
                profile.id
            );
        }
        println!(
            "{}: {function}: {count} inputs, all as the processor",
            profile.id
        );
    }
}
