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

use lazy_static::lazy_static;
use openssl::x509::X509;
use regex::Regex;

pub mod error;
pub mod idp;
pub mod sp;

lazy_static! {
    static ref REGEX_CERTIFICATE: Regex =
        Regex::new(r#"-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----"#).unwrap();
}

pub fn get_cert_data(cert: &X509) -> String {
    REGEX_CERTIFICATE
        .captures_iter(&String::from_utf8(cert.to_pem().unwrap()).unwrap())
        .next()
        .map(|capture| capture[1].into())
        .unwrap_or_default()
}
