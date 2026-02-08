/// A source location span tracking byte offsets, line, and column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Byte offset of the start of the span in the source.
    pub start: usize,
    /// Byte offset of the end of the span in the source (exclusive).
    pub end: usize,
    /// 1-based line number where the span starts.
    pub line: usize,
    /// 1-based column number where the span starts.
    pub col: usize,
}

impl Span {
    pub fn new(start: usize, end: usize, line: usize, col: usize) -> Self {
        Self {
            start,
            end,
            line,
            col,
        }
    }
}
