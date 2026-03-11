/// A stored block entry with named fields, replacing the previous
/// `(String, Vec<u8>, Vec<u8>, Option<Vec<u8>>)` tuple.
#[derive(Debug, Clone)]
pub struct BlockEntry {
    pub proto: String,
    pub hdrdata: Vec<u8>,
    pub blkdata: Vec<u8>,
    pub certdata: Option<Vec<u8>>,
}
