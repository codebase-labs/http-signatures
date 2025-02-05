use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Display};
use std::io::{BufRead, Write};

use anyhow::Context;
use http::{header::HeaderName, HeaderValue, Method};
use url::Url;

use crate::{
    ClientRequestLike, Derivable, DerivedComponent, DerivedQueryParameter, HttpDigest, RequestLike, ServerRequestLike,
    SignatureComponent,
};

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
    url: Url,
    headers: HashMap<HeaderName, HeaderValue>,
    body: Option<Vec<u8>>,
}

impl MockRequest {
    /// Returns the method used by this mock request
    pub fn method(&self) -> Method {
        self.method.clone()
    }
    /// Returns the path used by this mock request
    pub fn url(&self) -> &Url {
        &self.url
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
    pub fn new(method: Method, path: &str) -> Self {
        let url:Url = path.parse().unwrap();
        let mut res = Self {
            method,
            url: path.parse().unwrap(),
            headers: Default::default(),
            body: None,
        };

        let host_str = url.host_str();
        if let Some(host) = host_str {
            res = res.with_header("Host", host)
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
        let url: Url = path.parse().unwrap();

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
            url,
            headers,
            body,
        })
    }

    /// Write out this HTTP request in standard format
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), Box<dyn Error>> {
        writeln!(writer, "{} {} HTTP/1.1", self.method.as_str(), self.url())?;
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


impl Derivable<DerivedComponent> for MockRequest {
    /// Deriveable for MockRequest
    fn derive(&self, component: &DerivedComponent) -> Option<String> {
        match component {
            // Given POST https://www.method.com/path?param=value
            // target uri = POSST
            DerivedComponent::Method => Some(self.method().as_str().to_owned()),

            // Given POST https://www.method.com/path?param=value
            // target uri = https://www.method.com/path?param=value
            DerivedComponent::TargetURI => Some(self.url().to_string()),

            // Given POST https://www.method.com/path?param=value
            // target uri = www.method.com
            DerivedComponent::Authority => self.url().host_str().map(|s| s.to_owned()),

            // Given POST https://www.method.com/path?param=value
            // target uri = https
            DerivedComponent::Scheme => Some(self.url().scheme().to_owned()),

            // given POST https://www.example.com/path?param=value
            // request target = /path
            DerivedComponent::RequestTarget => {
                Some(self.url()[url::Position::BeforePath..].to_string())
            }

            // given POST https://www.example.com/path?param=value
            // request target = /path?param=value
            DerivedComponent::Path => Some(self.url().path().to_owned()),

            // given POST https://www.example.com/path?param=value&foo=bar&baz=batman
            // request target = /path?param=value
            DerivedComponent::Query => self.url().query().map(|s| format!("?{}", s.to_owned())),

            _ => None,
        }
    }
}

impl Derivable<DerivedQueryParameter> for MockRequest {
    /// Deriveable Query Param for MockRequest
    fn derive(&self, component: &DerivedQueryParameter) -> Option<String> {
        // find a query param that matches the name
         let pairs = self.url.query_pairs();
        for (name, value) in pairs {
            if component.param.eq(&name) {
               return Some(value.to_string()); 
            }
        }
        None
    }
}

impl RequestLike for MockRequest {
    /// Return a header value for standard headers, or a canonicalized Derived Component.
    fn header(&self, header: &SignatureComponent) -> Option<HeaderValue> {
        match header {
            // Either return a standard Header,
            SignatureComponent::Header(header_name) => self.headers.get(header_name).cloned(),
            // Or a Derived Component,
            SignatureComponent::Derived(component) => self.derive(component).map(|s| HeaderValue::from_str(&s).unwrap()),
            // Or a @query-params header
            SignatureComponent::DerivedParam(component) => self.derive(component).map(|s| HeaderValue::from_str(&s).unwrap()),
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
            if body.is_empty() {
                return (None, ());
            }
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
    use http::header::{DATE, HOST};

    use std::sync::Arc;

    use crate::{
        derived::Derivable,
        EcdsaP256Sha256Sign, EcdsaP256Sha256Verify, HttpSignatureVerify, RsaSha256Sign,
        RsaSha256Verify, SimpleKeyProvider, VerifyingConfig, VerifyingExt,
    };


    fn request(url: &str) -> MockRequest {
        MockRequest::new(Method::POST, url)
    }

    #[test]
    fn test_derive_method() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "POST";
        let result = request(url).derive(&DerivedComponent::Method).unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_target_uri() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "https://www.example.com/path?param=value";
        let result = request(url).derive(&DerivedComponent::TargetURI).unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_authority() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "www.example.com";
        let result = request(url).derive(&DerivedComponent::Authority).unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_scheme() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "https";
        let result = request(url).derive(&DerivedComponent::Scheme).unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_request_target() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "/path?param=value";
        let result = request(url).derive(&DerivedComponent::RequestTarget).unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_path() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "/path";
        let result = request(url).derive(&DerivedComponent::Path).unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_query() {
        let url = "https://www.example.com//path?param=value&foo=bar&baz=batman";
        let request_target = "?param=value&foo=bar&baz=batman";
        let result = request(url).derive(&DerivedComponent::Query).unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_query_params() {
        let url = "https://www.example.com//path?param=value&foo=bar&baz=batman";
        let request_target = "value";
        let dqp = DerivedQueryParameter{param: "param".to_string()};
        let result = request(url).derive(&dqp).unwrap();
        assert_eq!(request_target, result);
    }

   
    /// Test request
    ///
    /// ```
    /// POST /foo?param=value&pet=dog HTTP/1.1
    /// Host: example.com
    /// Date: Sun, 05 Jan 2014 21:31:40 GMT
    /// Content-Type: application/json
    /// Content-Length: 18
    /// Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
    ///
    /// {"hello": "world"}
    /// ```
    fn test_request() -> MockRequest {
        MockRequest::new(Method::POST, "http://example.com/foo?param=value&pet=dog")
            .with_header("Host", "example.com")
            .with_header("Date", "Sun, 05 Jan 2014 21:31:40 GMT")
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
        SimpleKeyProvider::new(vec![
            (
                "test-key-rsa",
                Arc::new(
                    RsaSha256Verify::new_pem(include_bytes!("../test_data/rsa-public.pem"))
                        .unwrap(),
                ) as Arc<dyn HttpSignatureVerify>,
            ),
            (
                "test-key-ecdsa",
                Arc::new(
                    EcdsaP256Sha256Verify::new_pem(include_bytes!("../test_data/ec-public.pem"))
                        .unwrap(),
                ) as Arc<dyn HttpSignatureVerify>,
            ),
        ])
    }

    /// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#default-test
    /// This test is currently broken in the spec, so it's been adjusted to pass...
    #[test]
    fn rsa_test() {
        // Expect successful validation
        let key = include_bytes!("../test_data/rsa-private.pem");
        let signature_alg = RsaSha256Sign::new_pkcs8_pem(key).expect("Failed to create key");
        let dqp = DerivedQueryParameter{param:"param".to_owned()};
        // Declare the headers to be included in the signature.
        // NOTE: NO HEADERS ARE INCLUDED BY DEFAULT
        let headers = [
            SignatureComponent::Header(HOST),
            SignatureComponent::Header(DATE),
            SignatureComponent::Header(HeaderName::from_static("digest")),
            SignatureComponent::Derived(DerivedComponent::RequestTarget),
            SignatureComponent::DerivedParam(dqp)
        ]
        .to_vec();

        let sign_config = SigningConfig::new("sig", "test-key-rsa", signature_alg)
            .with_components(&headers)
            .with_add_date(true);
        
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

    /// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#default-test
    #[test]
    fn ecdsa_test() {
        // Expect successful validation
        let key = include_bytes!("../test_data/ec-private.pem");
        let signature_alg = EcdsaP256Sha256Sign::new_pkcs8_pem(key).expect("Failed to create key");
        // Declare the headers to be included in the signature.
        // NOTE: NO HEADERS ARE INCLUDED BY DEFAULT
        let headers = [
            SignatureComponent::Header(HOST),
            SignatureComponent::Header(DATE),
            SignatureComponent::Header(HeaderName::from_static("digest")),
        ]
        .to_vec();

        let sign_config = SigningConfig::new("sig", "test-key-ecdsa", signature_alg)
            .with_components(&headers)
            .with_add_date(true);

        //dbg!(&sign_config);
        let mut req = test_request().signed(&sign_config).expect("Failed to sign");
        //dbg!(&req);
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

    #[test]
    fn no_headers() {
        // In leiu of a true const value for the header:
        let signature_input_header = HeaderName::from_static("signature-input");
        // The "Signature-Input" value should have no headers:
        let test_val = r#"sig=();alg="rsa-v1_5-sha256";keyid="test-key-rsa""#;

        let key = include_bytes!("../test_data/rsa-private.pem");
        let signature_alg = RsaSha256Sign::new_pkcs8_pem(key).expect("Failed to create key");

        // Turn off all automatic headers, like host, date, and digest
        let sign_config =
            SigningConfig::new("sig", "test-key-rsa", signature_alg).with_compute_digest(false);

        // Create the signed request
        let req = test_request().signed(&sign_config).expect("Failed to sign");
        // dbg!(&req);
        // Get the Signature-Input header value as an &str
        let header_val = req.header(&signature_input_header.into()).unwrap();
        let header_val = header_val.to_str().unwrap();

        assert_eq!(&test_val, &header_val);
    }
}
