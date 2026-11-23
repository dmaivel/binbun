"""Print a buffer's instructions coloured by what each piece of text is
(mnemonic, register, number, address...), as a listing view colours them,
from the decoder's tokens. ANSI colours for a terminal, or HTML.

With no bytes given it colours a load, a call and a return.

    python color_tokens.py
    python color_tokens.py 488b4310 e800000000 c3
    python color_tokens.py --arch aarch64 200440f9 00000094
    python color_tokens.py --html 488b4310 > listing.html
"""

from __future__ import annotations

import argparse
import html

import binbun
from binbun import aarch64, x86

TokenKind = binbun.TokenKind
# ANSI SGR colours per token kind; kinds not listed are left plain.
ANSI = {
    TokenKind.MNEMONIC: "1;34",  # bold blue
    TokenKind.PREFIX: "34",
    TokenKind.REGISTER: "32",  # green
    TokenKind.IMMEDIATE: "33",  # yellow
    TokenKind.INTEGER: "33",
    TokenKind.FLOAT: "33",
    TokenKind.DISPLACEMENT: "33",
    TokenKind.ADDRESS: "35",  # magenta
    TokenKind.SYMBOL: "36",  # cyan
}
# What is coloured when no bytes are given: a load, a call, a return.
EXAMPLES = {
    "x86-64": "488b4310 e800000000 c3",
    "x86-32": "8b4310 e800000000 c3",
    "aarch64": "200440f9 00000094 c0035fd6",
}


def colour(tokens: list[binbun.Token], as_html: bool) -> str:
    out = []
    for token in tokens:
        if as_html:
            text = html.escape(token.text)
            out.append(f'<span class="{token.kind.name.lower()}">{text}</span>')
        elif token.kind in ANSI:
            out.append(f"\x1b[{ANSI[token.kind]}m{token.text}\x1b[0m")
        else:
            out.append(token.text)
    return "".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("hex", nargs="*", help="the bytes, in hexadecimal (default: a load, a call, a return)")
    parser.add_argument("--arch", choices=["x86-64", "x86-32", "aarch64"], default="x86-64")
    parser.add_argument("--address", type=lambda s: int(s, 0), default=0x1000)
    parser.add_argument("--html", action="store_true", help="write HTML spans, one class per kind")
    args = parser.parse_args()
    try:
        code = bytes.fromhex("".join(args.hex or [EXAMPLES[args.arch]]))
    except ValueError:
        parser.error("the bytes must be hexadecimal digits, two per byte")

    if args.arch == "aarch64":
        items = aarch64.Decoder(code, args.address)
    else:
        mode = x86.Mode.BITS64 if args.arch == "x86-64" else x86.Mode.BITS32
        items = x86.Decoder(code, args.address, mode)
    if args.html:
        print("<pre>")
    for item in items:
        if isinstance(item, binbun.Invalid):
            line = f"(bad: {item.bytes.hex(' ')})"
        else:
            line = colour(item.tokens(), args.html).replace("\t", " ")
        print(f"{item.address:#010x}  {line}")
    if args.html:
        print("</pre>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
