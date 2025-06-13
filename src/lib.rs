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
