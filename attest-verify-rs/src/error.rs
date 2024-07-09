use core::fmt;
use std::io;

#[derive(Debug, Clone)]
pub enum ParseError {
    FileNotFound(String),
    InvalidArg(usize),
    IoError(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ParseError::*;
        match self {
            FileNotFound(file) => write!(f, "File '{:?}' not found", file),
            InvalidArg(pos) => write!(
                f,
                "Invalid arg at position {}. Please provide a filename \
            \nFor example. ./hsmattest attestation.dat",
                pos
            ),
            IoError(e) => write!(f, "IoError = {}", e),
        }
    }
}
impl std::error::Error for ParseError {}

impl From<io::Error> for ParseError {
    fn from(value: io::Error) -> Self {
        ParseError::IoError(value.to_string())
    }
}
