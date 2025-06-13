use base64::prelude::*;
use flate2::read::DeflateDecoder;
use quick_xml::de::from_str as from_xml_str;
use serde::Deserialize;
use std::io::Read;

use crate::{
    error::{Error, Result},
    idp::IdentityProvider,
};

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
pub struct Issuer {
    #[serde(rename = "$value")]
    pub value: String,
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
    #[serde(rename = "Status")]
    pub status: Status,
}

pub fn decode_logout_response(encoded: &str) -> Result<String> {
    let deflated = BASE64_STANDARD.decode(encoded).map_err(|err| {
        Error::InvalidResponse(format!("SAMLResponse is not encoded to base64: {}", err))
    })?;
    String::from_utf8(deflated).map_err(|err| {
        Error::InvalidResponse(format!("SAMLResponse contains invalid chars: {}", err))
    })
}

pub fn decode_inflate_logout_response(deflated_encoded: &str) -> Result<String> {
    let deflated = BASE64_STANDARD.decode(deflated_encoded).map_err(|err| {
        Error::InvalidResponse(format!("SAMLResponse is not encoded to base64: {}", err))
    })?;
    let mut inflater = DeflateDecoder::new(deflated.as_slice());
    let mut inflated = String::new();
    inflater.read_to_string(&mut inflated)?;
    Ok(inflated)
}

impl IdentityProvider {
    pub fn logout_response(&self, xml: &str) -> Result<Response> {
        let response = from_xml_str::<Response>(xml)?;
        Ok(response)
    }
}
