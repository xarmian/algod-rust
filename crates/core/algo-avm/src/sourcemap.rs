//! Source map generation for TEAL programs.
//!
//! Implements the Source Map v3 format matching go-algorand's `sourcemap.go`.
//! Maps program counter offsets to source file locations using VLQ encoding.

use std::collections::HashMap;

use serde::Serialize;

use crate::assembler::SourceLocation;

const SOURCE_MAP_VERSION: i32 = 3;
const B64_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Source map for a TEAL program, following the Source Map v3 specification.
#[derive(Debug, Clone, Serialize)]
pub struct SourceMap {
    pub version: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub file: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(rename = "sourceRoot")]
    pub source_root: String,
    pub sources: Vec<String>,
    pub names: Vec<String>,
    pub mappings: String,
}

/// Generate a source map from assembled program metadata.
///
/// `source_names` is the list of source file names (typically just one).
/// `offset_to_location` maps program counter offsets to source locations.
pub fn get_source_map(
    source_names: Vec<String>,
    offset_to_location: &HashMap<usize, SourceLocation>,
) -> SourceMap {
    let max_pc = offset_to_location.keys().copied().max().unwrap_or(0);

    let mut prev_location = SourceLocation { line: 0, col: 0 };
    let mut pc_to_line: Vec<String> = Vec::with_capacity(max_pc + 1);

    for pc in 0..=max_pc {
        if let Some(location) = offset_to_location.get(&pc) {
            let line_delta = location.line as isize - prev_location.line as isize;
            let col_delta = location.col as isize - prev_location.col as isize;
            pc_to_line.push(make_source_map_line(
                0,
                0,
                line_delta as i32,
                col_delta as i32,
            ));
            prev_location = *location;
        } else {
            pc_to_line.push(String::new());
        }
    }

    SourceMap {
        version: SOURCE_MAP_VERSION,
        file: String::new(),
        source_root: String::new(),
        sources: source_names,
        names: Vec::new(),
        mappings: pc_to_line.join(";"),
    }
}

/// Encode an integer as a VLQ (Variable Length Quantity) using base64 characters.
pub fn int_to_vlq(v: i32) -> String {
    let mut buf = Vec::new();
    int_to_vlq_buf(v, &mut buf);
    String::from_utf8(buf).unwrap()
}

fn int_to_vlq_buf(v: i32, buf: &mut Vec<u8>) {
    // Use unsigned arithmetic to avoid overflow on i32::MIN.
    // Signed-magnitude: LSB is sign bit, remaining bits are magnitude.
    let sign_bit = if v < 0 { 1u32 } else { 0u32 };
    let mut uval = (v.unsigned_abs() << 1) | sign_bit;
    loop {
        if uval >= 32 {
            buf.push(B64_TABLE[(32 | (uval & 31)) as usize]);
            uval >>= 5;
        } else {
            buf.push(B64_TABLE[uval as usize]);
            break;
        }
    }
}

/// Create a source map mapping line entry from the given values.
///
/// - `tcol`: target column (usually 0 for TEAL)
/// - `sindex`: source index (usually 0)
/// - `sline`: source line delta
/// - `scol`: source column delta
pub fn make_source_map_line(tcol: i32, sindex: i32, sline: i32, scol: i32) -> String {
    let mut buf = Vec::new();
    int_to_vlq_buf(tcol, &mut buf);
    int_to_vlq_buf(sindex, &mut buf);
    int_to_vlq_buf(sline, &mut buf);
    int_to_vlq_buf(scol, &mut buf);
    String::from_utf8(buf).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_to_vlq() {
        // VLQ(0) = "A" (B64[0])
        assert_eq!(int_to_vlq(0), "A");
        // VLQ(1) = "C" (B64[2], since 1 << 1 = 2)
        assert_eq!(int_to_vlq(1), "C");
        // VLQ(-1) = "D" (B64[3], since (-1 << 1) sign-adjusted = 3)
        assert_eq!(int_to_vlq(-1), "D");
    }

    #[test]
    fn test_make_source_map_line() {
        let line = make_source_map_line(0, 0, 1, 0);
        // Should encode (0, 0, 1, 0) as VLQ
        assert!(!line.is_empty());
    }

    #[test]
    fn test_get_source_map() {
        let mut offset_to_location = HashMap::new();
        offset_to_location.insert(0, SourceLocation { line: 0, col: 0 });
        offset_to_location.insert(3, SourceLocation { line: 1, col: 0 });
        offset_to_location.insert(5, SourceLocation { line: 2, col: 0 });

        let sm = get_source_map(vec!["test.teal".to_string()], &offset_to_location);
        assert_eq!(sm.version, 3);
        assert_eq!(sm.sources, vec!["test.teal"]);
        assert!(sm.names.is_empty());
        // Mappings should have entries separated by semicolons
        assert!(sm.mappings.contains(';'));
    }

    #[test]
    fn test_source_map_serializes() {
        let sm = SourceMap {
            version: 3,
            file: String::new(),
            source_root: String::new(),
            sources: vec!["test.teal".to_string()],
            names: Vec::new(),
            mappings: "AAAA;AACA".to_string(),
        };
        let json = serde_json::to_string(&sm).unwrap();
        assert!(json.contains("\"version\":3"));
        assert!(json.contains("\"mappings\":\"AAAA;AACA\""));
        // Empty file and sourceRoot should be omitted
        assert!(!json.contains("\"file\""));
        assert!(!json.contains("\"sourceRoot\""));
    }
}
