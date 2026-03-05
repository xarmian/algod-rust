mod compare;
mod report;

pub use compare::{compare_block, ComparisonResult, ComparisonStatus, Mismatch, TxnTypeCoverage};
pub use report::{print_summary, write_report, ConformanceReport};
