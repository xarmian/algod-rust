mod compare;
mod report;

pub use compare::{compare_block, ComparisonResult, ComparisonStatus, Mismatch};
pub use report::{print_summary, write_report, ConformanceReport};
