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

use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::X509,
};
use std::{fs::read, path::Path};
use url::Url;

use crate::error::Result;

pub mod authn_redirect;
pub mod logout_redirect;
pub mod metadata;

#[derive(Clone, Debug)]
pub struct ServiceProvider {
    pub entity_id: Url,
    pub private_key: PKey<Private>,
    pub certificate: X509,
    pub assert_login: Url,
    pub assert_logout: Url,
    pub relay_state: Option<String>,
    pub name_id_format: Option<String>,
    pub authn_context: Option<authn_redirect::RequestedAuthnContext>,
}

impl ServiceProvider {
    pub fn new(
        entity_id: Url,
        private_key: PKey<Private>,
        certificate: X509,
        assert_login: Url,
        assert_logout: Url,
    ) -> Self {
        Self {
            entity_id,
            private_key,
            certificate,
            assert_login,
            assert_logout,
            relay_state: None,
            name_id_format: None,
            authn_context: None,
        }
    }

    pub fn new_from_files(
        entity_id: Url,
        private_key_path: &Path,
        certificate_path: &Path,
        assert_login: Url,
        assert_logout: Url,
    ) -> Result<Self> {
        Ok(Self::new(
            entity_id,
            PKey::from_rsa(Rsa::private_key_from_pem(
                read(private_key_path)?.as_slice(),
            )?)?,
            X509::from_pem(read(certificate_path)?.as_slice())?,
            assert_login,
            assert_logout,
        ))
    }

    pub fn with_relay_state(mut self, relay_state: String) -> Self {
        self.relay_state = Some(relay_state);
        self
    }

    pub fn with_name_id_format(mut self, name_id_format: String) -> Self {
        self.name_id_format = Some(name_id_format);
        self
    }

    pub fn with_auth_context(
        mut self,
        auth_context: authn_redirect::RequestedAuthnContext,
    ) -> Self {
        self.authn_context = Some(auth_context);
        self
    }
}
