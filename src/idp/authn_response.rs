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

use base64::prelude::*;
use flate2::read::DeflateDecoder;
use openssl::x509::X509;
use quick_xml::de::from_str as from_xml_str;
use serde::Deserialize;
use std::io::Read;

use crate::{
    error::{Error, Result},
    idp::IdentityProvider,
};

#[derive(Deserialize)]
pub struct AttributeValue {
    #[serde(rename = "xsi:type")]
    pub typ: String,
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct Attribute {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "NameFormat")]
    pub name_format: String,
    #[serde(rename = "AttributeValue")]
    pub attribute_values: Vec<AttributeValue>,
}

#[derive(Deserialize)]
pub struct AttributeStatement {
    #[serde(rename = "Attribute")]
    pub attributes: Vec<Attribute>,
}

#[derive(Deserialize)]
pub struct AuthnContextClassRef {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct AuthnContext {
    #[serde(rename = "AuthnContextClassRef")]
    pub authn_context_class_ref: AuthnContextClassRef,
}

#[derive(Deserialize)]
pub struct AuthnStatement {
    #[serde(rename = "AuthnInstant")]
    pub authn_instant: String,
    #[serde(rename = "SessionNotOnOrAfter")]
    pub session_not_on_or_after: String,
    #[serde(rename = "SessionIndex")]
    pub session_index: String,
    #[serde(rename = "AuthnContext")]
    pub authn_context: AuthnContext,
}

#[derive(Deserialize)]
pub struct Audience {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct AudienceRestriction {
    #[serde(rename = "Audience")]
    pub audience: Audience,
}

#[derive(Deserialize)]
pub struct Conditions {
    #[serde(rename = "NotBefore")]
    pub not_before: String,
    #[serde(rename = "NotOnOrAfter")]
    pub not_on_or_after: String,
    #[serde(rename = "AudienceRestriction")]
    pub audience_restriction: AudienceRestriction,
}

#[derive(Deserialize)]
pub struct SubjectConfirmationData {
    #[serde(rename = "NotOnOrAfter")]
    pub not_on_or_after: String,
    #[serde(rename = "Recipient")]
    pub recipient: String,
    #[serde(rename = "InResponseTo")]
    pub in_response_to: String,
}

#[derive(Deserialize)]
pub struct SubjectConfirmation {
    #[serde(rename = "Method")]
    pub method: String,
    #[serde(rename = "SubjectConfirmationData")]
    pub subject_confirmation_data: SubjectConfirmationData,
}

#[derive(Deserialize)]
pub struct NameID {
    #[serde(rename = "SPNameQualifier")]
    pub sp_name_qualifier: Option<String>,
    #[serde(rename = "Format")]
    pub format: String,
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct Subject {
    #[serde(rename = "NameID")]
    pub name_id: NameID,
    #[serde(rename = "SubjectConfirmation")]
    pub subject_confirmation: SubjectConfirmation,
}

#[derive(Deserialize)]
pub struct StatusCode {
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct Status {
    #[serde(rename = "StatusCode")]
    pub status_code: StatusCode,
}

#[derive(Deserialize)]
pub struct X509Certificate {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct X509Data {
    #[serde(rename = "X509Certificate")]
    pub x509_certificate: X509Certificate,
}

#[derive(Deserialize)]
pub struct KeyInfo {
    #[serde(rename = "xmlns:ds")]
    pub ds: Option<String>,
    #[serde(rename = "X509Data")]
    pub x509_data: X509Data,
}

#[derive(Deserialize)]
pub struct SignatureValue {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct DigestValue {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct DigestMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

#[derive(Deserialize)]
pub struct Transform {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

#[derive(Deserialize)]
pub struct Transforms {
    #[serde(rename = "Transform")]
    pub transforms: Vec<Transform>,
}

#[derive(Deserialize)]
pub struct Reference {
    #[serde(rename = "URI")]
    pub uri: String,
    #[serde(rename = "Transforms")]
    pub transforms: Transforms,
    #[serde(rename = "DigestMethod")]
    pub digest_method: DigestMethod,
    #[serde(rename = "DigestValue")]
    pub digest_value: DigestValue,
}

#[derive(Deserialize)]
pub struct SignatureMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

#[derive(Deserialize)]
pub struct CanonicalizationMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

#[derive(Deserialize)]
pub struct SignedInfo {
    #[serde(rename = "CanonicalizationMethod")]
    pub canonicalization_method: CanonicalizationMethod,
    #[serde(rename = "SignatureMethod")]
    pub signature_method: SignatureMethod,
    #[serde(rename = "Reference")]
    pub reference: Reference,
}

#[derive(Deserialize)]
pub struct Signature {
    #[serde(rename = "xmlns:ds")]
    pub ds: Option<String>,
    #[serde(rename = "SignedInfo")]
    pub signed_info: SignedInfo,
    #[serde(rename = "SignatureValue")]
    pub signature_value: SignatureValue,
    #[serde(rename = "KeyInfo")]
    pub key_info: KeyInfo,
}

#[derive(Deserialize)]
pub struct Issuer {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct Assertion {
    #[serde(rename = "xmlns:xsi")]
    pub xsi: Option<String>,
    #[serde(rename = "xmlns:xs")]
    pub xs: Option<String>,
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: String,
    #[serde(rename = "Issuer")]
    pub issuer: Issuer,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Subject")]
    pub subject: Subject,
    #[serde(rename = "Conditions")]
    pub conditions: Conditions,
    #[serde(rename = "AuthnStatement")]
    pub authn_statement: AuthnStatement,
    #[serde(rename = "AttributeStatement")]
    pub attribute_statement: AttributeStatement,
}

#[derive(Deserialize)]
#[serde(rename = "samlp:Response")]
pub struct Response {
    #[serde(rename = "xmlns:samlp")]
    pub samlp: String,
    #[serde(rename = "xmlns:saml")]
    pub saml: String,
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: String,
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "InResponseTo")]
    pub in_response_to: String,
    #[serde(rename = "Issuer")]
    pub issuer: Issuer,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Status")]
    pub status: Status,
    #[serde(rename = "Assertion")]
    pub assertion: Assertion,
}

pub fn decode_authn_response(encoded: &str) -> Result<String> {
    let deflated = BASE64_STANDARD.decode(encoded).map_err(|err| {
        Error::InvalidResponse(format!("SAMLResponse is not encoded to base64: {}", err))
    })?;
    String::from_utf8(deflated).map_err(|err| {
        Error::InvalidResponse(format!("SAMLResponse contains invalid chars: {}", err))
    })
}

pub fn decode_inflate_authn_response(deflated_encoded: &str) -> Result<String> {
    let deflated = BASE64_STANDARD.decode(deflated_encoded).map_err(|err| {
        Error::InvalidResponse(format!("SAMLResponse is not encoded to base64: {}", err))
    })?;
    let mut inflater = DeflateDecoder::new(deflated.as_slice());
    let mut inflated = String::new();
    inflater.read_to_string(&mut inflated)?;
    Ok(inflated)
}

impl IdentityProvider {
    pub fn authn_response(&self, xml: &str) -> Result<Response> {
        let response = from_xml_str::<Response>(xml)?;
        if let Some(signature) = response.signature.as_ref() {
            let cert = X509::from_pem(
                format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                    signature.key_info.x509_data.x509_certificate.value
                )
                .as_bytes(),
            )?;
            let mut is_valid = false;
            for public_key in self.certificates.iter() {
                if cert.verify(public_key.public_key()?.as_ref())? {
                    is_valid = true;
                    break;
                }
            }
            if !is_valid {
                return Err(Error::InvalidCert(
                    "SAML response contains invalid cert".into(),
                ));
            }
        }
        Ok(response)
    }
}
