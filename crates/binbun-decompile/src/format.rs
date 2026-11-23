//! Format strings of the `printf` and `scanf` families: the arguments a
//! constant format string makes a call pass after it, and their C types.
//!
//! C's conversion specifications (ISO/IEC 9899:2018 §7.21.6.1 and
//! §7.21.6.2): flags, a field width (`*`: an `int` argument first), a
//! precision (likewise), a length modifier (`hh h l ll j z t`), the
//! conversion. Only what GCC's format checking accepts without a warning
//! (its tables in `gcc/c-family/c-format.cc`: which flags, widths,
//! precisions and lengths each conversion takes, the flag pairs one of
//! which is ignored) is parsed; everything else is a [`Refusal`], and a
//! call whose format is refused is taken as if it had no format string:
//! positional arguments (`%1$d`, POSIX), glibc's `%m` (the text of `errno`,
//! no argument), wide characters and strings (`%lc`, `%ls`, `%C`, `%S`:
//! their types depend on the target), `long double` (`%Lf`: passed in
//! memory on x86-64 System V), and extensions (glibc's `I` flag, `%ms`
//! allocation and `scanf`'s `'` flag, which Clang does not take; `q`,
//! `Z`, C23's `%b` and `wN`).

use alloc::vec::Vec;

/// Which family's conversion specifications a format string has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    /// `printf`'s: the arguments are values.
    Printf,
    /// `scanf`'s: the arguments are pointers to where values are stored.
    Scanf,
}

/// An integer type a conversion names: C's, whose widths a data model
/// gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Integer {
    /// `char` (`hh`: `signed char` or `unsigned char`).
    Char,
    /// `short` (`h`).
    Short,
    /// `int` (no length modifier).
    Int,
    /// `long` (`l`).
    Long,
    /// `long long` (`ll`).
    LongLong,
    /// `intmax_t` (`j`).
    IntMax,
    /// `size_t` (`z`).
    Size,
    /// `ptrdiff_t` (`t`).
    PtrDiff,
}

/// A C scalar type a conversion takes, or points to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scalar {
    /// An integer.
    Integer {
        /// Its rank.
        rank: Integer,
        /// Whether it is signed.
        signed: bool,
    },
    /// `float` (only pointed to: `scanf`'s `%f`).
    Float,
    /// `double`.
    Double,
    /// Plain `char` (only pointed to: `%s`, `scanf`'s `%c` and `%[`).
    Char,
    /// `void *`.
    VoidPointer,
}

/// An argument a conversion takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Argument {
    /// A value of the type (after the default argument promotions: `%hd`
    /// takes an `int`).
    Value(Scalar),
    /// A pointer to the type.
    Pointer(Scalar),
}

/// Why a format string is not parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Refusal {
    /// A positional argument (`%1$d`, `%*2$d`).
    Positional,
    /// glibc's `%m`.
    Errno,
    /// A wide character or string (`%lc`, `%ls`, `%C`, `%S`, `%l[`).
    Wide,
    /// A `long double` (`%Lf`).
    LongDouble,
    /// An extension: glibc's `I` flag, `scanf`'s allocating `m` and `a`
    /// and its `'` flag, the length modifiers `q`, `Z`, `L` on an
    /// integer, C23's `H`, `D`, `wN`, `%b`.
    Extension,
    /// Not a conversion specification GCC accepts without a warning: an
    /// unknown conversion, a flag, width, precision or length the
    /// conversion does not take, a repeated flag, a flag another makes
    /// ignored, a zero `scanf` width, an unterminated `%[`, a `%` at the
    /// end.
    Invalid,
}

impl Refusal {
    /// Every refusal, in order.
    pub const ALL: [Self; 6] = [
        Self::Positional,
        Self::Errno,
        Self::Wide,
        Self::LongDouble,
        Self::Extension,
        Self::Invalid,
    ];

    /// Its name, for statistics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Positional => "positional",
            Self::Errno => "errno",
            Self::Wide => "wide",
            Self::LongDouble => "long-double",
            Self::Extension => "extension",
            Self::Invalid => "invalid",
        }
    }

    /// Its index in [`ALL`](Self::ALL).
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// The arguments format string `format` (its bytes before the NUL) of
/// `family` makes a call pass after it, in order.
///
/// # Errors
///
/// A [`Refusal`] where it has a conversion specification this parser does
/// not take.
pub fn parse(family: Family, format: &[u8]) -> Result<Vec<Argument>, Refusal> {
    let mut arguments = Vec::new();
    let mut cursor = Cursor {
        bytes: format,
        at: 0,
    };
    while let Some(byte) = cursor.bump() {
        if byte != b'%' {
            continue;
        }
        match family {
            Family::Printf => printf(&mut cursor, &mut arguments)?,
            Family::Scanf => scanf(&mut cursor, &mut arguments)?,
        }
    }
    Ok(arguments)
}

/// A position in a format string.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }

    /// Takes `byte` if it is next.
    fn eat(&mut self, byte: u8) -> bool {
        let next = self.peek() == Some(byte);
        if next {
            self.at += 1;
        }
        next
    }

    /// Takes the decimal digits next: whether there were any, and whether
    /// any was not `0`.
    fn digits(&mut self) -> (bool, bool) {
        let (mut any, mut nonzero) = (false, false);
        while let Some(byte) = self.peek().filter(u8::is_ascii_digit) {
            any = true;
            nonzero |= byte != b'0';
            self.at += 1;
        }
        (any, nonzero)
    }

    /// Refuses a positional argument number next (digits and `$`).
    fn positional(&self) -> Result<(), Refusal> {
        let rest = self.bytes.get(self.at..).unwrap_or_default();
        let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if digits > 0 && rest.get(digits) == Some(&b'$') {
            return Err(Refusal::Positional);
        }
        Ok(())
    }

    /// The length modifier next.
    fn length(&mut self) -> Result<Length, Refusal> {
        let length = match self.peek() {
            Some(b'h') => {
                self.at += 1;
                if self.eat(b'h') {
                    Length::Char
                } else {
                    Length::Short
                }
            }
            Some(b'l') => {
                self.at += 1;
                if self.eat(b'l') {
                    Length::LongLong
                } else {
                    Length::Long
                }
            }
            Some(b'j') => Length::IntMax,
            Some(b'z') => Length::Size,
            Some(b't') => Length::PtrDiff,
            Some(b'L') => Length::LongDouble,
            Some(b'q' | b'Z' | b'H' | b'D' | b'w') => return Err(Refusal::Extension),
            _ => return Ok(Length::None),
        };
        if matches!(
            length,
            Length::IntMax | Length::Size | Length::PtrDiff | Length::LongDouble
        ) {
            self.at += 1;
        }
        Ok(length)
    }
}

/// A length modifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Length {
    None,
    Char,
    Short,
    Long,
    LongLong,
    IntMax,
    Size,
    PtrDiff,
    LongDouble,
}

impl Length {
    /// The integer an integer conversion with it names (`None`: none;
    /// `L` on an integer is GNU's `long long`).
    fn integer(self) -> Result<Integer, Refusal> {
        Ok(match self {
            Self::None => Integer::Int,
            Self::Char => Integer::Char,
            Self::Short => Integer::Short,
            Self::Long => Integer::Long,
            Self::LongLong => Integer::LongLong,
            Self::IntMax => Integer::IntMax,
            Self::Size => Integer::Size,
            Self::PtrDiff => Integer::PtrDiff,
            Self::LongDouble => return Err(Refusal::Extension),
        })
    }

    /// The floating-point type a conversion with it takes, `float` (or
    /// `double`, promoted) without one.
    fn float(self, plain: Scalar) -> Result<Scalar, Refusal> {
        match self {
            Self::None => Ok(plain),
            Self::Long => Ok(Scalar::Double),
            Self::LongDouble => Err(Refusal::LongDouble),
            Self::Char
            | Self::Short
            | Self::LongLong
            | Self::IntMax
            | Self::Size
            | Self::PtrDiff => Err(Refusal::Invalid),
        }
    }

    /// A character or string conversion: plain `char` without one.
    fn character(self) -> Result<(), Refusal> {
        match self {
            Self::None => Ok(()),
            Self::Long => Err(Refusal::Wide),
            Self::Char
            | Self::Short
            | Self::LongLong
            | Self::IntMax
            | Self::Size
            | Self::PtrDiff
            | Self::LongDouble => Err(Refusal::Invalid),
        }
    }

    /// A conversion that takes none.
    fn none(self) -> Result<(), Refusal> {
        if self == Self::None {
            Ok(())
        } else {
            Err(Refusal::Invalid)
        }
    }
}

/// The flags, field width and precision of a conversion specification, as
/// GCC's tables name them (`w`: a width, `p`: a precision).
#[derive(Default)]
struct Flags {
    seen: Vec<u8>,
}

impl Flags {
    /// Adds `flag`; a repeated one is refused.
    fn add(&mut self, flag: u8) -> Result<(), Refusal> {
        if self.seen.contains(&flag) {
            return Err(Refusal::Invalid);
        }
        self.seen.push(flag);
        Ok(())
    }

    fn has(&self, flag: u8) -> bool {
        self.seen.contains(&flag)
    }

    /// Refuses a flag not in `allowed`.
    fn within(&self, allowed: &[u8]) -> Result<(), Refusal> {
        if self.seen.iter().all(|flag| allowed.contains(flag)) {
            Ok(())
        } else {
            Err(Refusal::Invalid)
        }
    }
}

/// One `printf` conversion specification after its `%`.
fn printf(cursor: &mut Cursor<'_>, arguments: &mut Vec<Argument>) -> Result<(), Refusal> {
    if cursor.eat(b'%') {
        return Ok(());
    }
    cursor.positional()?;
    let mut flags = Flags::default();
    while let Some(flag) = cursor.peek() {
        match flag {
            b'-' | b'+' | b' ' | b'#' | b'0' | b'\'' => flags.add(flag)?,
            b'I' => return Err(Refusal::Extension),
            _ => break,
        }
        cursor.at += 1;
    }
    let int = Argument::Value(Scalar::Integer {
        rank: Integer::Int,
        signed: true,
    });
    let mut stars = Vec::new();
    if cursor.eat(b'*') {
        cursor.positional()?;
        flags.add(b'w')?;
        stars.push(int);
    } else if cursor.digits().0 {
        flags.add(b'w')?;
    }
    if cursor.eat(b'.') {
        flags.add(b'p')?;
        if cursor.eat(b'*') {
            cursor.positional()?;
            stars.push(int);
        } else {
            cursor.digits();
        }
    }
    let length = cursor.length()?;
    let conversion = cursor.bump().ok_or(Refusal::Invalid)?;
    let integer = |signed| -> Result<Argument, Refusal> {
        let rank = match length.integer()? {
            Integer::Char | Integer::Short => Integer::Int,
            rank @ (Integer::Int
            | Integer::Long
            | Integer::LongLong
            | Integer::IntMax
            | Integer::Size
            | Integer::PtrDiff) => rank,
        };
        Ok(Argument::Value(Scalar::Integer { rank, signed }))
    };
    let (allowed, argument): (&[u8], _) = match conversion {
        b'd' | b'i' => (b"-wp0 +'", integer(true)?),
        b'o' | b'x' | b'X' => (b"-wp0#", integer(false)?),
        b'u' => (b"-wp0'", integer(false)?),
        b'f' | b'F' | b'g' | b'G' => (b"-wp0 +#'", Argument::Value(length.float(Scalar::Double)?)),
        b'e' | b'E' | b'a' | b'A' => (b"-wp0 +#", Argument::Value(length.float(Scalar::Double)?)),
        b'c' => {
            length.character()?;
            (b"-w", int)
        }
        b's' => {
            length.character()?;
            (b"-wp", Argument::Pointer(Scalar::Char))
        }
        b'p' => {
            length.none()?;
            (b"-w", Argument::Value(Scalar::VoidPointer))
        }
        b'n' => (
            b"",
            Argument::Pointer(Scalar::Integer {
                rank: length.integer()?,
                signed: true,
            }),
        ),
        b'm' => return Err(Refusal::Errno),
        b'C' | b'S' => return Err(Refusal::Wide),
        b'b' | b'B' => return Err(Refusal::Extension),
        _ => return Err(Refusal::Invalid),
    };
    flags.within(allowed)?;
    // GCC's flag pairs: ' ' is ignored with '+', '0' with '-', and '0'
    // with a precision on an integer conversion.
    let integral = matches!(conversion, b'd' | b'i' | b'o' | b'x' | b'X' | b'u');
    if (flags.has(b' ') && flags.has(b'+'))
        || (flags.has(b'0') && (flags.has(b'-') || (integral && flags.has(b'p'))))
    {
        return Err(Refusal::Invalid);
    }
    arguments.extend(stars);
    arguments.push(argument);
    Ok(())
}

/// One `scanf` conversion specification after its `%`.
fn scanf(cursor: &mut Cursor<'_>, arguments: &mut Vec<Argument>) -> Result<(), Refusal> {
    if cursor.eat(b'%') {
        return Ok(());
    }
    cursor.positional()?;
    let mut flags = Flags::default();
    loop {
        match cursor.peek() {
            Some(b'*') => flags.add(b'*')?,
            Some(b'I' | b'm' | b'\'') => return Err(Refusal::Extension),
            // GNU's allocating `a` before `s`, `S` or `[` (else `%a` is
            // the conversion).
            Some(b'a') if matches!(cursor.bytes.get(cursor.at + 1), Some(b's' | b'S' | b'[')) => {
                return Err(Refusal::Extension);
            }
            _ => break,
        }
        cursor.at += 1;
    }
    let (width, nonzero) = cursor.digits();
    if width {
        if !nonzero {
            return Err(Refusal::Invalid);
        }
        flags.add(b'w')?;
    }
    let length = cursor.length()?;
    let conversion = cursor.bump().ok_or(Refusal::Invalid)?;
    let integer = |signed| -> Result<Argument, Refusal> {
        Ok(Argument::Pointer(Scalar::Integer {
            rank: length.integer()?,
            signed,
        }))
    };
    let (allowed, argument): (&[u8], _) = match conversion {
        b'd' | b'i' => (b"*w", integer(true)?),
        b'u' | b'o' | b'x' | b'X' => (b"*w", integer(false)?),
        b'e' | b'f' | b'g' | b'E' | b'G' | b'F' | b'a' | b'A' => {
            (b"*w", Argument::Pointer(length.float(Scalar::Float)?))
        }
        b'c' | b's' => {
            length.character()?;
            (b"*w", Argument::Pointer(Scalar::Char))
        }
        b'[' => {
            length.character()?;
            cursor.eat(b'^');
            cursor.eat(b']');
            while cursor.bump().ok_or(Refusal::Invalid)? != b']' {}
            (b"*w", Argument::Pointer(Scalar::Char))
        }
        b'p' => {
            length.none()?;
            (b"*w", Argument::Pointer(Scalar::VoidPointer))
        }
        b'n' => (b"", integer(true)?),
        b'C' | b'S' => return Err(Refusal::Wide),
        b'b' => return Err(Refusal::Extension),
        _ => return Err(Refusal::Invalid),
    };
    flags.within(allowed)?;
    let suppressed = flags.has(b'*');
    // GCC's flag pair: assignment suppression with a length modifier.
    if suppressed && length != Length::None {
        return Err(Refusal::Invalid);
    }
    if !suppressed {
        arguments.push(argument);
    }
    Ok(())
}
