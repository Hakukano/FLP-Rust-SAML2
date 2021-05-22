use chrono::{SecondsFormat, Utc};
use flate2::{read::DeflateEncoder, Compression};
use openssl::{hash::MessageDigest, sign::Signer};
use quick_xml::se::to_string as to_xml_string;
use rand::{thread_rng, Rng};
use serde::Serialize;
use std::io::Read;
use url::Url;

use crate::{error::Result, idp::IdentityProvider, sp::ServiceProvider};

#[derive(Serialize)]
pub struct SessionIndex {
    #[serde(rename = "$value")]
    value: String,
}

#[derive(Serialize)]
pub struct NameID {
    #[serde(rename = "SPNameQualifier")]
    sp_name_qualifier: String,
    #[serde(rename = "Format")]
    format: String,
    #[serde(rename = "$value")]
    value: String,
}

#[derive(Serialize)]
pub struct Issuer {
    #[serde(rename = "$value")]
    value: String,
}

#[derive(Serialize)]
#[serde(rename = "samlp:LogoutRequest")]
pub struct LogoutRequest {
    #[serde(rename = "xmlns:samlp")]
    samlp: String,
    #[serde(rename = "xmlns:saml")]
    saml: String,
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "IssueInstant")]
    issue_instant: String,
    #[serde(rename = "Destination")]
    destination: String,
    #[serde(rename = "saml:Issuer")]
    issuer: Issuer,
    #[serde(rename = "saml:NameID")]
    name_id: NameID,
    #[serde(rename = "samlp:SessionIndex")]
    session_index: SessionIndex,
}

impl ServiceProvider {
    pub fn logout_redirect(
        &self,
        idp: &IdentityProvider,
        name_id: String,
        session_index: String,
    ) -> Result<Url> {
        let random_bytes = thread_rng().gen::<[u8; 21]>();
        let now = Utc::now();

        let authn = to_xml_string(&LogoutRequest {
            samlp: "urn:oasis:names:tc:SAML:2.0:protocol".into(),
            saml: "urn:oasis:names:tc:SAML:2.0:assertion".into(),
            id: format!("_{}", hex::encode(random_bytes)),
            version: "2.0".into(),
            issue_instant: now.to_rfc3339_opts(SecondsFormat::Millis, true),
            destination: idp.logout.to_string(),
            issuer: Issuer {
                value: self.entity_id.to_string(),
            },
            name_id: NameID {
                sp_name_qualifier: self.entity_id.to_string(),
                format: self.name_id_format.clone().unwrap_or_else(|| {
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".into()
                }),
                value: name_id,
            },
            session_index: SessionIndex {
                value: session_index,
            },
        })
        .unwrap();

        let mut deflater = DeflateEncoder::new(authn.as_bytes(), Compression::fast());
        let mut deflated = Vec::new();
        deflater.read_to_end(&mut deflated)?;
        let saml_request = base64::encode(deflated);
        let mut url = idp.logout.clone();
        url.query_pairs_mut()
            .clear()
            .append_pair("SAMLRequest", &saml_request);
        if let Some(relay_state) = self.relay_state.as_ref() {
            url.query_pairs_mut().append_pair("RelayState", relay_state);
        }
        url.query_pairs_mut().append_pair(
            "SigAlg",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        );
        let query_all = url.query().unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &self.private_key)?;
        signer.update(query_all.as_bytes())?;
        url.query_pairs_mut()
            .append_pair("Signature", &base64::encode(signer.sign_to_vec()?));
        Ok(url)
    }
}
