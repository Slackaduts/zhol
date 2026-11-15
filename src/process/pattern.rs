use crate::memory::Byte;

/// Top-level function for performing memory AOB scans.
///
/// # Arguments
/// * `handle`: WinAPI handle (*mut c_void) with PROCESS_VM_READ
/// * `pattern`: IDA byte pattern
/// * `origin`: Address to begin searching at
/// * `size`: Size (in bytes) of search area
/// # Returns
/// * `crate::MemOpResult<Vec<(usize, Vec<u8>)>>`: Anyhow result of a vector of addresses where a match was found, including bytes found at matches
pub fn pattern_scan(
    handle: &crate::process::SafeHandle,
    pattern: &str,
    origin: usize,
    size: usize,
) -> crate::MemOpResult<Vec<(usize, Vec<u8>)>> {
    use crate::process::pattern::{find_pattern_in_bytes, prepare_pattern};


    let bytes = crate::memory::read::read_bytes(handle, origin, size - 0x04, None)?;
    let pattern_bytes = prepare_pattern(pattern);
    find_pattern_in_bytes(bytes, pattern_bytes)
}

/// Turns a pattern into a vector of Option<u8>.
///
/// # Arguments
/// * `pattern`: IDA-style byte pattern
/// # Returns
/// * `Vec<Option<u8>>`: Vector of optional bytes, where None represents an IDA wildcard (??).
pub fn prepare_pattern(pattern: &str) -> Vec<Byte> {
    pattern
        .split_whitespace()
        .map(|s| match s {
            "?" | "??" => None,
            hex => Some(u8::from_str_radix(hex, 16).unwrap_or(0)),
        })
        .collect()
}

/// Determines when a byte matches a pattern byte.
///
/// # Arguments
/// * `byte`: The byte to match against the pattern
/// * `pattern`: The optional byte to use to match
/// # Returns
/// * `bool`: Whether or not this byte matches the pattern byte
fn byte_matches(byte: &u8, pattern: Byte) -> bool {
    return match pattern {
        None => return true,
        Some(b) => &b == byte,
    };
}

/// Finds all matches of a given pattern in a byte vector.
///
/// # Arguments
/// * `bytes`: Vector of bytes to search
/// * `pattern`: Vec of optional bytes to find
/// # Returns
/// * `crate::MemOpResult<Vec<(usize, Vec<usize>)>>`: Vector of addresses relative to the provided bytes, with a byte vector of the bytes found at the pattern.
pub fn find_pattern_in_bytes(bytes: Vec<u8>, pattern: Vec<Byte>) -> crate::MemOpResult<Vec<(usize, Vec<u8>)>> {
    let pattern_length = pattern.len();
    let mut matches: Vec<(usize, Vec<u8>)> = Vec::new();

    // Only iterate up to where a full pattern could still fit
    for i in 0..=bytes.len().saturating_sub(pattern_length) {
        let mut match_found = true;

        // Compare each byte in the pattern
        for (j, pattern_byte) in pattern.iter().copied().enumerate() {
            if !byte_matches(&bytes[i + j], pattern_byte) {
                match_found = false;
                break;
            }
        }

        if match_found {
            matches.push((i, Vec::from(&bytes[i..i + pattern_length])));
        }
    }

    Ok(matches)
}

pub fn create_unhook_bytes(pattern: &[Byte], found_bytes: &[u8]) -> Vec<u8> {
    // For every None in the pattern, we need to use the found byte at that index. Otherwise, we use the pattern byte.
    let unhook_bytes: Vec<u8> = pattern
        .iter()
        .zip(found_bytes.iter())
        .map(|(pattern_byte, found_byte)| match pattern_byte {
            None => *found_byte,
            Some(b) => *b,
        })
        .collect();

    return unhook_bytes;
}

#[macro_export]
macro_rules! byte_pattern {
    ($pattern:expr) => {{
        const fn hex_to_byte(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'A'..=b'F' => c - b'A' + 10,
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("Invalid hex character"),
            }
        }

        const fn parse_byte_pair(first: u8, second: u8) -> Byte {
            if first == b'?' && second == b'?' {
                None
            } else {
                Some(hex_to_byte(first) << 4 | hex_to_byte(second))
            }
        }

        const PATTERN_STR: &[u8] = $pattern.as_bytes();
        const LEN: usize = PATTERN_STR.len() / 3; // "XX " format

        const PATTERN: [Byte; LEN] = {
            let mut arr = [None; LEN];
            let mut i = 0;
            while i < LEN {
                let first = PATTERN_STR[i * 3];
                let second = PATTERN_STR[i * 3 + 1];
                arr[i] = parse_byte_pair(first, second);
                i += 1;
            }
            arr
        };

        &PATTERN
    }};
}
