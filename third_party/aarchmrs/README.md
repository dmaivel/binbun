# AARCHMRS (Arm A-profile Machine Readable Specification), BSD package

`AARCHMRS_OPENSOURCE_A_profile_FAT-2026-09.tar.gz` is Arm's open-source
machine-readable A-profile specification, vendored unchanged. binbun's AArch64
decoder generator (`cargo xtask codegen`, through `xtask/src/aarchmrs.rs`)
reads it directly; the 208 MB of JSON inside never enters the repository.

| | |
|---|---|
| URL | <https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-OS-Machine-Readable-Data/AARCHMRS_BSD/AARCHMRS_OPENSOURCE_A_profile_FAT-2026-09.tar.gz> |
| release | 2026-09 (`_meta.version`: architecture `vFATAp2-A`, build 868, ref `2026-09_rel`, schema 2.9.6, 2026-09-21) |
| downloaded | 2026-11-07 |
| size | 5,748,433 bytes |
| sha256 | `d5bf3f538663fb18be081ba8e9f08b188ed06f81dd19d4aa2da5b2795103a4ec` |
| md5 | `6001b6543a331506bec1833ac75c8b20` |

`scripts/update-aarchmrs.sh [release]` downloads a release, checks it and
replaces the tarball; update the checksums here and in the script with it.

## Licence

BSD 3-Clause, Copyright 2010-2026 Arm Limited or its affiliates. The package
has no LICENSE file: the licence text is `docs/notice.html` inside the
tarball, extracted here as `notice.html`, and every JSON file's
`_meta.license` says "This document is Non-confidential and licensed under
the BSD 3-clause license." Redistribution needs the copyright notice, the
conditions and the disclaimer; Arm's name may not be used to endorse derived
products. Code generated from the package carries a notice saying so.

The package is published only as the FAT ("Future Architecture
Technologies") build, which includes features of unannounced architecture
versions; the decoder decodes their encodings and tags them.
