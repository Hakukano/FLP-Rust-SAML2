// This library provides SAML2 implementation in Rust
// Copyright (C) 2026  Hakukaze Shikano
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use openssl::error::ErrorStack;
use quick_xml::DeError;
use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    IOError(String),
    InvalidCert(String),
    InvalidResponse(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::IOError(s) => write!(f, "IO Error: {}", s),
            Self::InvalidCert(s) => write!(f, "Invalid Cert: {}", s),
            Self::InvalidResponse(s) => write!(f, "Invalid Response: {}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::IOError(err.to_string())
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Self::InvalidCert(err.to_string())
    }
}

impl From<DeError> for Error {
    fn from(err: DeError) -> Self {
        Self::InvalidResponse(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
