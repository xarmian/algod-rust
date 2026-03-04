mod compare;
mod report;

pub use compare::{compare_block, ComparisonResult, Mismatch};
pub use report::{print_summary, write_report, ConformanceReport};
