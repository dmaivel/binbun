# Security policy

## Reporting a vulnerability

Please don't report security vulnerabilities in public issues. Report them privately through GitHub's [private vulnerability reporting](https://github.com/dmaivel/binbun/security/advisories/new), or by email to [security@binbun.org](mailto:security@binbun.org).

Include the binbun version or commit you used, how you ran it, and the input that triggers the problem.

## What counts as a vulnerability

binbun is meant to open binaries that may be hostile. A file is a security issue if opening or analysing it makes binbun

- run code supplied by the file,
- read or write files outside binbun's own project and cache directories, or
- contact the network when you haven't asked it to.

These are not vulnerabilities, and should be reported as ordinary issues:

- crashes, panics, hangs, high memory use and other kinds of denial of service,
- wrong disassembly or wrong decompiled C, and
- `binbun verify` reporting a function as verified when its C is wrong. Verification compares the C with the machine code from sampled states, so it can miss a difference; it is a test, not a proof.

## Supported versions

While binbun is in preview, only the latest release and the main branch receive security fixes.
