use std::convert::TryInto;

use http::{
    header::{HeaderName, HeaderValue},
    Method,
};

use super::*;

/// Consolidated
fn handle_pseudo_header(header: &Header, host: Option<String>, method: &Method, url: &url::Url) -> Option<HeaderValue> {
    match header {
        Header::Pseudo(PseudoHeader::Method) => {
            // Per [SEMANTICS], HTTP method names are case sensitive and uppoer
            // case by convention.  This function must respect the actual HTTP
            // method name as preented.
            let method = method.as_str();
            format!("{}", method).try_into().ok()
        },
        Header::Pseudo(PseudoHeader::RequestTarget) => {
            let path = url.path();
            if let Some(query) = url.query() {
                format!("{}?{}", path, query)
            } else {
                format!("{}", path)
            }
            .try_into()
            .ok()
        },
        Header::Pseudo(PseudoHeader::TargetURI) => format!("{}", url).try_into().ok(),
        // In a request, @authority is the HOST
        Header::Pseudo(PseudoHeader::Authority) => {
            if let Some(host) = host {
                format!("{}", host).try_into().ok()
            } else {
                None
            }
        },
        Header::Pseudo(PseudoHeader::Scheme) => {
            let scheme = url.scheme();
            format!("{}", scheme).try_into().ok()
        },
        Header::Pseudo(PseudoHeader::Path) => {
            let path = url.path();
            format!("{}", path).try_into().ok()
        },
        Header::Pseudo(PseudoHeader::Query) => {
            if let Some(query) = url.query() {
                format!("{}", query).try_into().ok()
            } else {
                None
            }
        },
        _ => None,
    }
}

impl RequestLike for reqwest::Request {
    fn header(&self, header: &Header) -> Option<HeaderValue> {
        match header {
            Header::Normal(header_name) => self.headers().get(header_name).cloned(),
            _ => handle_pseudo_header(&header, self.host(), self.method(), self.url()),
        }
    }
}

impl ClientRequestLike for reqwest::Request {
    fn host(&self) -> Option<String> {
        self.url().host_str().map(Into::into)
    }
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String> {
        self.body()?.as_bytes().map(|b| digest.http_digest(b))
    }
    fn set_header(&mut self, header: HeaderName, value: HeaderValue) {
        self.headers_mut().insert(header, value);
    }
}

impl RequestLike for reqwest::blocking::Request {
    fn header(&self, header: &Header) -> Option<HeaderValue> {
        match header {
            Header::Normal(header_name) => self.headers().get(header_name).cloned(),
            _ => handle_pseudo_header(&header, self.host(), self.method(), self.url()),
        }
    }
}

impl ClientRequestLike for reqwest::blocking::Request {
    fn host(&self) -> Option<String> {
        self.url().host_str().map(Into::into)
    }
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String> {
        let bytes_to_digest = self.body_mut().as_mut()?.buffer().ok()?;
        Some(digest.http_digest(bytes_to_digest))
    }
    fn set_header(&mut self, header: HeaderName, value: HeaderValue) {
        self.headers_mut().insert(header, value);
    }
}

#[cfg_attr(not(feature = "reqwest"), ignore)]
#[cfg(test)]
mod tests {
    use chrono::{offset::TimeZone, Utc};
    use http::header::{CONTENT_TYPE, HOST, DATE};
    use crate::header::PseudoHeader::RequestTarget;
    use super::*;

    #[test]
    fn it_works() {
        let headers = [
            Header::Pseudo(RequestTarget),
            Header::Normal(HOST),
            Header::Normal(DATE),
            Header::Normal(HeaderName::from_static("digest")),
        ]
        .to_vec();
        let config = SigningConfig::new_default("sig", "test_key", "abcdefgh".as_bytes())
        .with_headers(&headers);

        let client = reqwest::Client::new();

        let without_sig = client
            .post("http://test.com/foo/bar")
            .header(CONTENT_TYPE, "application/json")
            .header(
                DATE,
                Utc.ymd(2014, 7, 8)
                    .and_hms(9, 10, 11)
                    .format("%a, %d %b %Y %T GMT")
                    .to_string(),
            )
            .body(&br#"{ "x": 1, "y": 2}"#[..])
            .build()
            .unwrap();

        let with_sig = without_sig.signed(&config).unwrap();

        assert_eq!(with_sig.headers().get(signature_input_header()).unwrap(), r#"sig=("@request-target" "host" "date" "digest");alg="hmac-sha256";keyid="test_key""#);
        assert_eq!(with_sig.headers().get(signature_header()).unwrap(), r#"sig=:r5wgqaQMZ/iqU0eJs+fy9/aQnbVMTsxN9CTAiOTVLEA=:"#);
        assert_eq!(
            with_sig
                .headers()
                .get(digest_header())
                .unwrap(),
            "SHA-256=2vgEVkfe4d6VW+tSWAziO7BUx7uT/rA9hn1EoxUJi2o="
        );
    }

    #[test]
    #[ignore]
    fn it_can_talk_to_reference_integration() {
        let config = SigningConfig::new_default("sig", "dummykey", &base64::decode("dummykey").unwrap());

        let client = reqwest::blocking::Client::new();

        let req = client
            .get("http://localhost:8080/config")
            .build()
            .unwrap()
            .signed(&config)
            .unwrap();

        let result = client.execute(req).unwrap();
        println!("{:?}", result.text().unwrap());
    }
}
