use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error;
use std::fmt::{self, Display};
use std::io::{BufRead, Write};

use anyhow::Context;
use http::{header::HeaderName, HeaderValue, Method};
use url::Url;

use crate::{ClientRequestLike, Header, HttpDigest, PseudoHeader, RequestLike, ServerRequestLike};

/// Generic error returned when the input to `from_reader` does not look like
/// a HTTP request.
#[derive(Debug)]
pub struct ParseError;

impl Error for ParseError {}
impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Malformed HTTP request")
    }
}

/// A mock request type
#[derive(Debug, Clone, PartialEq)]
pub struct MockRequest {
    method: Method,
    path: String,
    headers: HashMap<HeaderName, HeaderValue>,
    body: Option<Vec<u8>>,
}

impl MockRequest {
    /// Returns the method used by this mock request
    pub fn method(&self) -> Method {
        self.method.clone()
    }
    /// Returns the path used by this mock request
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Returns the headers used by this mock request
    pub fn headers(&self) -> impl IntoIterator<Item = (&HeaderName, &HeaderValue)> {
        &self.headers
    }
    /// Returns the body used by this mock request
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    /// Constructs a new mock request
    pub fn new(method: Method, url: &str) -> Self {
        let url: Url = url.parse().unwrap();

        let path = if let Some(query) = url.query() {
            format!("{}?{}", url.path(), query)
        } else {
            url.path().into()
        };
        let mut res = Self {
            method,
            path,
            headers: Default::default(),
            body: None,
        };
        if let Some(host) = url.host_str().map(ToOwned::to_owned) {
            res = res.with_header("Host", &host)
        }
        res
    }
    /// Convenience method for setting a header
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.set_header(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
        self
    }
    /// Method for setting a request body
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        let l = body.len();
        self.body = Some(body);
        self.with_header("Content-Length", &l.to_string())
    }

    /// Parse a HTTP request into this mock request object
    pub fn from_reader<R: BufRead>(reader: &mut R) -> Result<Self, Box<dyn Error>> {
        let mut line = String::new();

        // Read request line
        reader.read_line(&mut line)?;
        let mut parts = line.split_ascii_whitespace();

        // Extract method
        let method: Method = parts.next().ok_or(ParseError)?.parse()?;

        // Extract method
        let path: String = parts.next().ok_or(ParseError)?.parse()?;

        // Extract headers
        #[allow(clippy::mutable_key_type)]
        let mut headers = HashMap::new();
        let has_body = loop {
            line.truncate(0);
            if reader.read_line(&mut line)? == 0 {
                break false;
            }
            if line.trim().is_empty() {
                break true;
            }

            let mut parts = line.splitn(2, ':');

            let name_str = parts.next().ok_or(ParseError)?.trim();
            let header_name: HeaderName = name_str
                .parse()
                .with_context(|| format!("{:?}", name_str))?;
            let value_str = parts.next().ok_or(ParseError)?.trim();
            let header_value: HeaderValue = value_str
                .parse()
                .with_context(|| format!("{:?}", value_str))?;
            headers.insert(header_name, header_value);
        };

        let body = if has_body {
            let mut body = Vec::new();
            reader.read_to_end(&mut body)?;
            Some(body)
        } else {
            None
        };

        Ok(Self {
            method,
            path,
            headers,
            body,
        })
    }

    /// Write out this HTTP request in standard format
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), Box<dyn Error>> {
        writeln!(writer, "{} {} HTTP/1.1", self.method.as_str(), self.path)?;
        for (header_name, header_value) in &self.headers {
            writeln!(
                writer,
                "{}: {}",
                header_name.as_str(),
                header_value.to_str()?
            )?;
        }

        if let Some(body) = &self.body {
            writeln!(writer)?;
            writer.write_all(body)?;
        }

        Ok(())
    }
}

impl RequestLike for MockRequest {
    fn header(&self, header: &Header) -> Option<HeaderValue> {
        match header {
            Header::Normal(header_name) => self.headers.get(header_name).cloned(),
            Header::Pseudo(PseudoHeader::RequestTarget) => {
                let method = self.method.as_str().to_ascii_lowercase();
                format!("{} {}", method, self.path).try_into().ok()
            }
            _ => None,
        }
    }
}

impl ClientRequestLike for MockRequest {
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String> {
        self.body.as_ref().map(|b| digest.http_digest(b))
    }
    fn set_header(&mut self, header: HeaderName, value: HeaderValue) {
        self.headers.insert(header, value);
    }
}

impl<'a> ServerRequestLike for &'a MockRequest {
    type Remnant = ();

    fn complete_with_digest(self, digest: &dyn HttpDigest) -> (Option<String>, Self::Remnant) {
        if let Some(body) = self.body.as_ref() {
            let computed_digest = digest.http_digest(body);
            (Some(computed_digest), ())
        } else {
            (None, ())
        }
    }
    fn complete(self) -> Self::Remnant {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::SigningExt;
    use crate::SigningConfig;
    use http::header::{HOST, DATE};

    use std::sync::Arc;

    use crate::{
        HttpSignatureVerify, RsaSha256Sign, RsaSha256Verify, SimpleKeyProvider, VerifyingConfig,
        VerifyingExt,
    };

    /// Test request as defined in the draft specification:
    /// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#rfc.appendix.C
    ///
    /// ```
    /// POST /foo?param=value&pet=dog HTTP/1.1
    /// Host: example.com
    /// Date: Sun, 05 Jan 2014 21:31:40 GMT
    /// Content-Type: application/json
    /// Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
    /// Content-Length: 18
    ///
    /// {"hello": "world"}
    /// ```
    fn test_request() -> MockRequest {
        MockRequest::new(Method::POST, "http://example.com/foo?param=value&pet=dog")
            .with_header("Host", "example.com")
            .with_header("Date", "Sun, 14 Jan 2014 21:31:40 GMT")
            .with_header("Content-Type", "application/json")
            .with_header(
                "Digest",
                "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
            )
            .with_body(r#"{"hello": "world"}"#.as_bytes().into())
    }

    /// Test key as defined in the draft specification:
    /// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#rfc.appendix.C
    fn test_key_provider() -> SimpleKeyProvider {
        SimpleKeyProvider::new(vec![(
            "test-key-rsa",
            Arc::new(
                RsaSha256Verify::new_pem(
                    //&base64::decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB").unwrap()
                    include_bytes!("../test_data/test_key_rsa_public.pem"),
                )
                .unwrap(),
            ) as Arc<dyn HttpSignatureVerify>,
        )])
    }

    /// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#default-test
    /// This test is currently broken in the spec, so it's been adjusted to pass...
    #[test]
    fn rsa_test() {
        // Expect successful validation
        let key = include_bytes!("../test_data/test_key_rsa_private.pem");
        let signature_alg = RsaSha256Sign::new_pem(key).expect("Failed to create key");
        // Declare the headers to be included in the signature.
        // NOTE: NO HEADERS ARE INCLUDED BY DEFAULT
        let headers = [
            Header::Normal(HOST),
            Header::Normal(DATE),
            Header::Normal(HeaderName::from_static("digest")),
        ]
        .to_vec();

        let sign_config = SigningConfig::new("sig", "test-key-rsa", signature_alg)
        .with_headers(&headers)
        .with_add_date(true);

        //dbg!(&sign_config);
        let mut req = test_request().signed(&sign_config).expect("Failed to sign");
        dbg!(&req);
        let mut verify_config = VerifyingConfig::new(test_key_provider());
        // Because the test_request has a fixed date in the past...
        verify_config.set_validate_date(false);

        let result = req.verify(&verify_config);
        assert!(result.is_ok());
        // Expect failing validation
        req = req.with_header("Date", "Sun, 05 Jan 2014 21:31:41 GMT");

        let result = req.verify(&verify_config);
        assert!(result.is_err());
    }

    /// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#basic-test
    #[test]
    fn basic_verify_test() {
        // Expect successful validation
        let req = test_request()
        .with_header("Signature-Input",
        r#"sig=("host" "date" "digest");alg="rsa-v1_5-sha256";keyid="test-key-rsa""#)
        .with_header(
            "Signature",
            "sig=:Hs0rc8YpCcl1HGISy6Ne5Xjjbm667uqFqYMRcDnTrzghMd+B5Em5tTXP\
            r/vFLWrGadd0zyhwuMoaODlAibV/jbtwpk/93ecJb4R1Jy53KXDAxv4vmvr4NvpkiK3n\
            SCa8wQLb8sQj7/J4iMGOz/EjbtBNOuNebMvnWs3NK4YLTF7QyoOezscQrKbzjHatDXwm\
            gzUY7wvbvrv0awny2TJSyt3suZZubg4Wlh28AnTPk/GSNjAYNDqGUCPVhFi+23KJD/9/\
            5ORM0DWKZUawE0KILE7/Mmj3CeXe6OzRWNxKx3P1BrdmBzF5dEDv28lgaAA8fSJzdEzm\
            iCHHU8bWy3nSSA==:"
        );

        let mut config = VerifyingConfig::new(test_key_provider());
        config.set_validate_date(false);
        config.set_require_digest(false);

        //dbg!(&req);

        req.verify(&config)
            .expect("Signature to be verified correctly");
    }

    #[test]
    fn no_headers() {
        // In leiu of a true const value for the header:
        let signature_input_header = HeaderName::from_static("signature-input");
        // The "Signature-Input" value should have no headers:
        let test_val = r#"sig=();alg="rsa-v1_5-sha256";keyid="test-key-rsa""#;

        let key = include_bytes!("../test_data/test_key_rsa_private.pem");
        let signature_alg = RsaSha256Sign::new_pem(key).expect("Failed to create key");

        // Turn off all automatic headers, like host, date, and digest
        let sign_config = SigningConfig::new("sig", "test-key-rsa", signature_alg)
        .with_compute_digest(false);

        // Create the signed request
        let req = test_request().signed(&sign_config).expect("Failed to sign");
       // dbg!(&req);
        // Get the Signature-Input header value as an &str
        let header_val = req.header(&signature_input_header.into()).unwrap();
        let header_val = header_val.to_str().unwrap();

        assert_eq!(&test_val, &header_val);

    }
}
