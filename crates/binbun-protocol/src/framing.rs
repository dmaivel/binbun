//! Messages on a stream: each a little-endian `u32` length, then that many
//! bytes of JSON.

use std::io::{self, ErrorKind, Read, Write};

/// The longest message read: anything longer is refused, never allocated.
pub const MAX_MESSAGE: u32 = 256 << 20;

/// Writes `payload` as one message, then flushes.
///
/// # Errors
///
/// `payload` is longer than [`MAX_MESSAGE`]; the stream's errors.
pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let length = u32::try_from(payload.len())
        .ok()
        .filter(|&length| length <= MAX_MESSAGE)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "a message too long to send"))?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

/// Reads one message; `None` if the stream ended before one began.
///
/// # Errors
///
/// It ended within one, it is longer than [`MAX_MESSAGE`], or the stream's
/// errors.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0; 4];
    let mut read = 0;
    while read < length.len() {
        let Some(rest) = length.get_mut(read..) else {
            break;
        };
        match reader.read(rest) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
            Ok(n) => read += n,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let length = u32::from_le_bytes(length);
    if length > MAX_MESSAGE {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("a message of {length} bytes (at most {MAX_MESSAGE})"),
        ));
    }
    let length = usize::try_from(length)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "a message too long here"))?;
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{MAX_MESSAGE, read_frame, write_frame};

    #[test]
    fn frames_read_back_as_written_and_bad_ones_are_refused() {
        let mut stream = Vec::new();
        write_frame(&mut stream, b"{}").unwrap();
        write_frame(&mut stream, b"").unwrap();
        assert_eq!(&stream[..6], &[2, 0, 0, 0, b'{', b'}']);
        let mut reader = Cursor::new(stream.clone());
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), b"{}");
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), b"");
        assert!(read_frame(&mut reader).unwrap().is_none());
        // Cut within the length, within the payload.
        assert!(read_frame(&mut Cursor::new(&stream[..2])).is_err());
        assert!(read_frame(&mut Cursor::new(&stream[..5])).is_err());
        // Too long: refused before anything is allocated.
        let huge = (MAX_MESSAGE + 1).to_le_bytes();
        assert!(read_frame(&mut Cursor::new(huge)).is_err());
    }
}
