//! Prints AArch64 instructions coloured by what each piece of text is
//! (mnemonic, register, immediate, address), as a listing view colours
//! them: the decoder writes its text into a [`Sink`] as tokens, and this
//! one wraps each kind in an ANSI colour.
//!
//! With no bytes given it colours a load, a call and a return.
//!
//! ```text
//! cargo run -p binbun-aarch64 --example color_tokens
//! cargo run -p binbun-aarch64 --example color_tokens -- 200440f9 00000094 c0035fd6
//! ```

use std::env;
use std::fmt::{self, Write as _};
use std::process::ExitCode;

use binbun_aarch64::{Decoder, Sink, TokenKind};

/// What is coloured when no bytes are given: `ldr x0, [x1, #0x8]`, `bl`,
/// `ret`.
const EXAMPLE: &str = "200440f900000094c0035fd6";

/// A line of text with ANSI colours.
#[derive(Debug, Default)]
struct Coloured(String);

impl Sink for Coloured {
    fn token(&mut self, kind: TokenKind, text: &str) -> fmt::Result {
        let colour = match kind {
            TokenKind::Mnemonic => "1;34",
            TokenKind::Register => "32",
            TokenKind::Immediate => "33",
            TokenKind::Address => "35",
            TokenKind::Text => "36",
            TokenKind::Punctuation | TokenKind::Whitespace => {
                // A tab separates the mnemonic from the operands.
                self.0.push_str(&text.replace('\t', " "));
                return Ok(());
            }
        };
        write!(self.0, "\x1b[{colour}m{text}\x1b[0m")
    }
}

fn main() -> ExitCode {
    let mut hex: String = env::args().skip(1).collect();
    if hex.is_empty() {
        hex.push_str(EXAMPLE);
    }
    let code: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect();
    let Some(code) = code.filter(|code| !code.is_empty() && hex.len().is_multiple_of(2)) else {
        eprintln!("usage: color_tokens [HEX] (little-endian instruction words)");
        return ExitCode::FAILURE;
    };
    for (address, decoded) in Decoder::new(&code, 0x1000) {
        match decoded {
            Ok(instruction) => {
                let mut line = Coloured::default();
                if instruction.format(address, &mut line).is_ok() {
                    println!("{address:#010x}  {}", line.0);
                }
            }
            Err(error) => println!("{address:#010x}  ({error})"),
        }
    }
    ExitCode::SUCCESS
}
