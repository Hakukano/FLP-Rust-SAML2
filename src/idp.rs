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

use openssl::x509::X509;
use std::{fs::read, path::Path};
use url::Url;

use crate::error::Result;

pub mod authn_response;
pub mod logout_response;

#[derive(Clone, Debug)]
pub struct IdentityProvider {
    pub login: Url,
    pub logout: Url,
    pub certificates: Vec<X509>,
}

impl IdentityProvider {
    pub fn new(login: Url, logout: Url, certificates: Vec<X509>) -> Self {
        Self {
            login,
            logout,
            certificates,
        }
    }

    pub fn new_from_files(login: Url, logout: Url, certificate_paths: &[&Path]) -> Result<Self> {
        let mut certificates = Vec::with_capacity(certificate_paths.len());
        for certificate_path in certificate_paths {
            certificates.push(X509::from_pem(read(certificate_path)?.as_slice())?);
        }
        Ok(Self::new(login, logout, certificates))
    }
}
