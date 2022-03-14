use std::convert::TryInto;

use http::{
    header::{HeaderName, HeaderValue},
    Method,
};

use super::*;

impl Derivable for reqwest::Request {
        fn derive(&self, component: DerivedComponent) -> Option<String> {
        match component {
            DerivedComponent::RequestTarget => {
                format!("{} {}", self.method().as_str(), self.path())
            },
            DerivedComponent::Method => {
                self.method().as_str()
            },
            DerivedComponent::TargetURI => {
                self.uri().to_string()
            },
            DerivedComponent::Authority => {
                self.uri().authority().and_then(|auth| auth.as_str())
            },
            DerivedComponent::Scheme => {
                self.uri().scheme().and_then(|scheme| scheme.as_str().try_into().ok())
            },
            DerivedComponent::Path => {
                self.uri().path().try_into().ok()
            },
            DerivedComponent::Query => {
                if let Some(query) = self.uri().query() {
                    format!("?{}", query).try_into().ok()
                } else {
                    None
                }
            },
            _ => None,

        }
    }

}

/// Consolidated
fn handle_derived_component(header: &SignatureComponent, host: Option<String>, method: &Method, url: &url::Url) -> Option<HeaderValue> {
    match header {
        SignatureComponent::Derived(DerivedComponent::Method) => {
            // Per [SEMANTICS], HTTP method names are case sensitive and uppoer
            // case by convention.  This function must respect the actual HTTP
            // method name as preented.
            let method = method.as_str();
            format!("{}", method).try_into().ok()
        },
        SignatureComponent::Derived(DerivedComponent::RequestTarget) => {
            let path = url.path();
            if let Some(query) = url.query() {
                format!("{}?{}", path, query)
            } else {
                format!("{}", path)
            }
            .try_into()
            .ok()
        },
        SignatureComponent::Derived(DerivedComponent::TargetURI) => format!("{}", url).try_into().ok(),
        // In a request, @authority is the HOST
        SignatureComponent::Derived(DerivedComponent::Authority) => {
            if let Some(host) = host {
                format!("{}", host).try_into().ok()
            } else {
                None
            }
        },
        SignatureComponent::Derived(DerivedComponent::Scheme) => {
            let scheme = url.scheme();
            format!("{}", scheme).try_into().ok()
        },
        SignatureComponent::Derived(DerivedComponent::Path) => {
            let path = url.path();
            format!("{}", path).try_into().ok()
        },
        SignatureComponent::Derived(DerivedComponent::Query) => {
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
    fn header(&self, header: &SignatureComponent) -> Option<HeaderValue> {
        match header {
            SignatureComponent::Header(header_name) => self.headers().get(header_name).cloned(),
            _ => handle_derived_component(&header, self.host(), self.method(), self.url()),
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
            _ => handle_derived_component(&header, self.host(), self.method(), self.url()),
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
    use crate::derived::DerivedComponent::RequestTarget;
    use super::*;

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
}
