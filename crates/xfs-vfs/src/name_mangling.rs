//! Reversible presentation encoding for XFS byte names on Windows.
//!
//! XFS names are arbitrary bytes (except NUL and `/`), while WinFsp requires
//! valid UTF-16 and reserves several characters. Valid UTF-8 names are kept
//! unchanged unless they contain a Windows separator/reserved character.
//! Invalid bytes and the escape marker use a private-use escape sequence.

use fs_abstraction::{FsError, FsResult};

const ESCAPE: char = '\u{F001}';

fn push_ascii_escape(output: &mut String, value: char) {
    output.push(ESCAPE);
    output.push(char::from_u32(0xF100 + u32::from(value)).expect("ASCII escapes fit in BMP"));
}

fn push_escaped_char(output: &mut String, value: char) {
    if value == ESCAPE {
        output.push(ESCAPE);
        output.push('\u{F130}');
    } else if ('\u{F100}'..='\u{F17F}').contains(&value) {
        // The private-use tag range is reserved for escape markers. A literal
        // name character from that range must not decode as a marker, so spell
        // it with the generic code-point escape instead.
        push_codepoint_escape(output, value);
    } else if matches!(value, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        || value <= '\u{1F}'
    {
        // Replace the character itself, rather than merely prefixing it:
        // backslash and slash must not remain path separators.
        push_ascii_escape(output, value);
    } else {
        output.push(value);
    }
}

fn push_codepoint_escape(output: &mut String, value: char) {
    use std::fmt::Write;

    // `value` is always a BMP scalar here; the fallback keeps the signature
    // total without panicking on a hypothetical surrogate.
    let _ = write!(output, "{ESCAPE}u{:04X}", u32::from(value));
}

/// Encode arbitrary XFS name bytes as valid, Windows-safe UTF-8.
pub(crate) fn mangle_bytes(bytes: &[u8]) -> FsResult<String> {
    if bytes.is_empty() || bytes.len() > 255 || bytes.contains(&0) {
        return Err(FsError::InvalidArgument);
    }

    let mut output = String::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        match std::str::from_utf8(&bytes[offset..]) {
            Ok(valid) => {
                for value in valid.chars() {
                    push_escaped_char(&mut output, value);
                }
                break;
            }
            Err(error) => {
                let valid_len = error.valid_up_to();
                if valid_len != 0 {
                    let valid = std::str::from_utf8(&bytes[offset..offset + valid_len])
                        .map_err(|_| FsError::Corrupted)?;
                    for value in valid.chars() {
                        push_escaped_char(&mut output, value);
                    }
                    offset += valid_len;
                }

                // One invalid byte is escaped losslessly, then validation
                // resumes at the next byte. Incomplete trailing sequences are
                // therefore handled one byte at a time as well.
                use std::fmt::Write;
                write!(&mut output, "{ESCAPE}x{:02X}", bytes[offset])
                    .map_err(|_| FsError::ArithmeticOverflow)?;
                offset += 1;
            }
        }
    }
    escape_windows_special_name(&mut output);
    Ok(output)
}

fn escape_windows_special_name(output: &mut String) {
    while output.ends_with('.') || output.ends_with(' ') {
        let last = output.pop().expect("checked non-empty");
        push_ascii_escape(output, last);
    }

    let base = output.split('.').next().unwrap_or("");
    let upper = base.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && matches!(upper.as_bytes()[3], b'1'..=b'9'));
    if reserved {
        let first = output.chars().next().expect("checked non-empty");
        output.remove(0);
        let escape = char::from_u32(0xF100 + u32::from(first)).expect("ASCII reserved name");
        output.insert_str(0, &format!("{ESCAPE}{escape}"));
    }
}

pub(crate) fn mangle_str(name: &str) -> FsResult<String> {
    mangle_bytes(name.as_bytes())
}

/// Decode the presentation encoding back to the original XFS bytes.
pub(crate) fn unmangle(name: &str) -> FsResult<Vec<u8>> {
    let mut output = Vec::with_capacity(name.len());
    let mut chars = name.chars();
    while let Some(value) = chars.next() {
        if value != ESCAPE {
            let mut buffer = [0u8; 4];
            output.extend_from_slice(value.encode_utf8(&mut buffer).as_bytes());
            continue;
        }
        let tag = chars.next().ok_or(FsError::Corrupted)?;
        match tag {
            'x' => {
                let high = chars.next().and_then(char_hex).ok_or(FsError::Corrupted)?;
                let low = chars.next().and_then(char_hex).ok_or(FsError::Corrupted)?;
                output.push((high << 4) | low);
            }
            'u' => {
                let mut code = 0u32;
                for _ in 0..4 {
                    let digit = chars.next().and_then(char_hex).ok_or(FsError::Corrupted)?;
                    code = (code << 4) | u32::from(digit);
                }
                let original = char::from_u32(code).ok_or(FsError::Corrupted)?;
                let mut buffer = [0u8; 4];
                output.extend_from_slice(original.encode_utf8(&mut buffer).as_bytes());
            }
            '\u{F130}' => {
                let mut buffer = [0u8; 4];
                output.extend_from_slice(ESCAPE.encode_utf8(&mut buffer).as_bytes());
            }
            '\u{F100}'..='\u{F17F}' => {
                let original = char::from_u32(u32::from(tag) - 0xF100).ok_or(FsError::Corrupted)?;
                let mut buffer = [0u8; 4];
                output.extend_from_slice(original.encode_utf8(&mut buffer).as_bytes());
            }
            _ => return Err(FsError::Corrupted),
        }
    }
    Ok(output)
}

fn char_hex(value: char) -> Option<u8> {
    match value {
        '0'..='9' => Some(value as u8 - b'0'),
        'a'..='f' => Some(value as u8 - b'a' + 10),
        'A'..='F' => Some(value as u8 - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_bytes_round_trip_without_lossy_replacements() {
        for bytes in [
            &b"plain.txt"[..],
            &b"bad\xFF\xFEname"[..],
            &b"incomplete\xE2\x82"[..],
            &b"windows\\:*?\"<>|"[..],
            "private\u{F001}marker".as_bytes(),
            &b"CON.txt"[..],
            &b"trailing. "[..],
            &b"..."[..],
            "literal\u{F100}tag\u{F130}".as_bytes(),
            "escape\u{F001}marker".as_bytes(),
        ] {
            let encoded = mangle_bytes(bytes).unwrap();
            assert_eq!(unmangle(&encoded).unwrap(), bytes);
            let wide: Vec<u16> = encoded.encode_utf16().collect();
            assert!(
                fs_abstraction::unicode::is_valid_filename(&wide),
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn distinct_invalid_bytes_have_distinct_windows_names() {
        assert_ne!(
            mangle_bytes(b"a\xFF").unwrap(),
            mangle_bytes(b"a\xFE").unwrap()
        );
    }
}
