use chrono::{SecondsFormat, Utc};
use flate2::{read::DeflateEncoder, Compression};
use openssl::{hash::MessageDigest, sign::Signer};
use quick_xml::se::to_string as to_xml_string;
use rand::{thread_rng, Rng};
use serde::Serialize;
use std::io::Read;
use url::Url;

use crate::{
    idp::IdentityProvider,
    sp::{Result, ServiceProvider},
};

#[derive(Clone, Debug, Serialize)]
pub struct AuthnContextClassRef {
    #[serde(rename = "$value")]
    value: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RequestedAuthnContext {
    #[serde(rename = "Comparison")]
    comparison: String,
    #[serde(rename = "saml:AuthnContextClassRef")]
    authn_context_class_ref: AuthnContextClassRef,
}

#[derive(Serialize)]
pub struct NameIDPolicy {
    #[serde(rename = "Format")]
    format: String,
    #[serde(rename = "AllowCreate")]
    allow_create: String,
}

#[derive(Serialize)]
pub struct Issuer {
    #[serde(rename = "$value")]
    value: String,
}

#[derive(Serialize)]
#[serde(rename = "samlp:AuthnRequest")]
pub struct AuthnRequest {
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
    #[serde(rename = "ProtocolBinding")]
    protocol_binding: String,
    #[serde(rename = "AssertionConsumerServiceURL")]
    assertion_consumer_service_url: String,
    #[serde(rename = "saml:Issuer")]
    issuer: Issuer,
    #[serde(rename = "samlp:NameIDPolicy")]
    name_id_policy: NameIDPolicy,
    #[serde(
        rename = "samlp:RequestedAuthnContext",
        skip_serializing_if = "Option::is_none"
    )]
    requested_authn_context: Option<RequestedAuthnContext>,
}

impl ServiceProvider {
    pub fn authn_redirect(&self, idp: &IdentityProvider) -> Result<Url> {
        let random_bytes = thread_rng().gen::<[u8; 21]>();
        let now = Utc::now();

        let authn = to_xml_string(&AuthnRequest {
            samlp: "urn:oasis:names:tc:SAML:2.0:protocol".into(),
            saml: "urn:oasis:names:tc:SAML:2.0:assertion".into(),
            id: format!("_{}", hex::encode(random_bytes)),
            version: "2.0".into(),
            issue_instant: now.to_rfc3339_opts(SecondsFormat::Millis, true),
            destination: idp.login.to_string(),
            protocol_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
            assertion_consumer_service_url: self.assert_login.to_string(),
            issuer: Issuer {
                value: self.entity_id.to_string(),
            },
            name_id_policy: NameIDPolicy {
                format: self.name_id_format.clone().unwrap_or_else(|| {
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".into()
                }),
                allow_create: "true".into(),
            },
            requested_authn_context: self.authn_context.clone(),
        })
        .unwrap();

        let mut deflater = DeflateEncoder::new(authn.as_bytes(), Compression::fast());
        let mut deflated = Vec::new();
        deflater.read_to_end(&mut deflated)?;
        let saml_request = base64::encode(deflated);
        let mut url = idp.login.clone();
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
