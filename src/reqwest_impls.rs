use http::{
    header::{HeaderName, HeaderValue},
    Method,
};

use super::*;

/// Consolidated
fn handle_derived_component(
    header: &SignatureComponent,
    host: Option<String>,
    method: &Method,
    url: &url::Url,
) -> Option<HeaderValue> {
    match header {
        SignatureComponent::Derived(DerivedComponent::Method) => {
            // Per [SEMANTICS], HTTP method names are case sensitive and uppoer
            // case by convention.  This function must respect the actual HTTP
            // method name as preented.
            let method = method.as_str();
            method.to_string().try_into().ok()
        }
        SignatureComponent::Derived(DerivedComponent::RequestTarget) => {
            let path = url.path();
            if let Some(query) = url.query() {
                format!("{}?{}", path, query)
            } else {
                path.to_string()
            }
            .try_into()
            .ok()
        }
        SignatureComponent::Derived(DerivedComponent::TargetURI) => {
            url.to_string().try_into().ok()
        }
        // In a request, @authority is the HOST
        SignatureComponent::Derived(DerivedComponent::Authority) => {
            if let Some(host) = host {
                host.try_into().ok()
            } else {
                None
            }
        }
        SignatureComponent::Derived(DerivedComponent::Scheme) => {
            let scheme = url.scheme();
            scheme.to_string().try_into().ok()
        }
        SignatureComponent::Derived(DerivedComponent::Path) => {
            let path = url.path();
            path.to_string().try_into().ok()
        }
        SignatureComponent::Derived(DerivedComponent::Query) => {
            if let Some(query) = url.query() {
                query.to_string().try_into().ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

impl RequestLike for reqwest::Request {
    fn header(&self, header: &SignatureComponent) -> Option<HeaderValue> {
        match header {
            SignatureComponent::Header(header_name) => self.headers().get(header_name).cloned(),
            _ => handle_derived_component(header, self.host(), self.method(), self.url()),
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
    fn header(&self, header: &SignatureComponent) -> Option<HeaderValue> {
        match header {
            SignatureComponent::Header(header_name) => self.headers().get(header_name).cloned(),
            SignatureComponent::Derived(component) => self.derive(component).map(|s| HeaderValue::from_str(&s).unwrap()),
            // Or a @query-params header
            SignatureComponent::DerivedParam(component) => self.derive(component).map(|s| HeaderValue::from_str(&s).unwrap()),
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


impl Derivable<DerivedComponent> for reqwest::Request {
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
            DerivedComponent::Query => self.url().query().map(|s| format!("?{}",s.to_owned())),
            
            _ => None,
        }
    }
}


impl Derivable<DerivedComponent> for reqwest::blocking::Request {
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
            DerivedComponent::Query => self.url().query().map(|s| format!("?{}",s.to_owned())),
            
            _ => None,
        }
    }
}

impl Derivable<DerivedQueryParameter> for reqwest::blocking::Request {
    /// Deriveable Query Param for MockRequest
    fn derive(&self, component: &DerivedQueryParameter) -> Option<String> {
        // find a query param that matches the name
         let pairs = self.url().query_pairs();
        for (name, value) in pairs {
            if component.param.eq(&name) {
               return Some(value.to_string()); 
            }
        }
        None
    }
}

impl Derivable<DerivedQueryParameter> for reqwest::Request {
    /// Deriveable Query Param for MockRequest
    fn derive(&self, component: &DerivedQueryParameter) -> Option<String> {
        // find a query param that matches the name
         let pairs = self.url().query_pairs();
        for (name, value) in pairs {
            if component.param.eq(&name) {
               return Some(value.to_string()); 
            }
        }
        None
    }
}

#[cfg_attr(not(feature = "reqwest"), ignore)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::DerivedComponent::RequestTarget;
    use chrono::{offset::TimeZone, Utc};
    use http::header::{CONTENT_TYPE, DATE, HOST};

    fn request(url: &str) -> reqwest::Request {
        reqwest::Client::new().post(url).build().unwrap()
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

    #[test]
    fn it_works() {
        let components = [
            SignatureComponent::Derived(RequestTarget),
            SignatureComponent::Header(HOST),
            SignatureComponent::Header(DATE),
            SignatureComponent::Header(HeaderName::from_static("digest")),
        ]
        .to_vec();
        let config = SigningConfig::new_default("sig", "test_key", "abcdefgh".as_bytes())
            .with_components(&components);

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

        assert_eq!(
            with_sig.headers().get(signature_input_header()).unwrap(),
            r#"sig=("@request-target" "host" "date" "digest");alg="hmac-sha256";keyid="test_key""#
        );
        assert_eq!(
            with_sig.headers().get(signature_header()).unwrap(),
            r#"sig=:r5wgqaQMZ/iqU0eJs+fy9/aQnbVMTsxN9CTAiOTVLEA=:"#
        );
        assert_eq!(
            with_sig.headers().get(digest_header()).unwrap(),
            "SHA-256=2vgEVkfe4d6VW+tSWAziO7BUx7uT/rA9hn1EoxUJi2o="
        );
    }
}
