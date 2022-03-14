//! ServerRequestLike implementation for actix-web
//! 
//! Establish actix_web::dev::ServiceRequest as an http_sig::ServeRequestLike for
//! digesting request payload.  ServerRequestLike::verify will most likely be called
//! in an actix-web middleware that is able to re-establish the payload from the
//! Remnant returned by the `complete_with_digest` method below.  So, this method
//! makes no attempt to do so.
//! 
//! 
use std::{
    convert::Into,
    future::{ready, Ready},
    rc::Rc,
    iter::Iterator
};
use std::convert::TryInto;

use actix_web::{
    dev::ServiceRequest,
    web::BytesMut,
    HttpMessage,
};
use futures_util::{future::LocalBoxFuture, stream::StreamExt};


use http::header::HeaderValue;


use crate::{SignatureComponent, HttpDigest, DerivedComponent, RequestLike, ServerRequestLike};

impl ServiceRequest {
    fn derive(component: DerivedComponent) -> Option<String> {
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
/// returns either a normal http headerValue, or a DerivedComponent
/// 
/// For Derived Components, the value is calculated from the request, and returned
/// as a DerivedComponent
/// The following Derived Compnents are not supported:
/// * Signature Parrams: This is an intermediate working component
/// * Query Params: Acti does not upport multiple instances of a heaader
/// * Status Code: This is a Response component
/// * Request-Response: Signed responses are not yet supported
impl RequestLike for ServiceRequest {

    fn header(&self, header: &SignatureComponent) -> Option<HeaderValue> {
        match header {
            SignatureComponent::Header(header) => {
                self
                .headers()
                .get(header).and_then(|x| Some(x.clone()))
            },

            SignatureComponent::Derived(DerivedComponent::RequestTarget) => {
                format!("{} {}", self.method().as_str(), self.path()).try_into().ok()
            },
            SignatureComponent::Derived(DerivedComponent::Method) => {
                self.method().as_str().try_into().ok()
            },
            SignatureComponent::Derived(DerivedComponent::TargetURI) => {
                self.uri().to_string().try_into().ok() 
            },
            SignatureComponent::Derived(DerivedComponent::Authority) => {
                self.uri().authority().and_then(|auth| auth.as_str().try_into().ok())
            },
            SignatureComponent::Derived(DerivedComponent::Scheme) => {
                self.uri().scheme().and_then(|scheme| scheme.as_str().try_into().ok())
            },
            SignatureComponent::Derived(DerivedComponent::Path) => {
                self.uri().path().try_into().ok()
            },
            SignatureComponent::Derived(DerivedComponent::Query) => {
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

impl<'a> ServerRequestLike for &'a ServiceRequest {
    type Remnant = Option<BytesMut>;

    fn complete_with_digest(self, digest: &dyn HttpDigest) -> (Option<String>, Self::Remnant) {

        // The request payload will be gathered hee
        let mut body = BytesMut::new();

        // Read the body out of the request payload stream...
        let mut stream = self.take_payload();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk?);
        }
        if body.len() == 0 {
            return (None, None);
        }

        let computed_digest = digest.http_digest(body);
        (Some(computed_digest), body)
        // we now have the payload bytes locally for digesting

    }
    fn complete(self) -> Self::Remnant {}
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{offset::TimeZone, Utc};

    use super::*;

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
    fn test_request() -> rouille::Request {
        rouille::Request::fake_http(
            "POST",
            "http://example.com/foo?param=value&pet=dog",
            vec![
                ("Date".into(), "Sun, 05 Jan 2014 21:31:40 GMT".into()),
                ("ContentType".into(), "application/json".into()),
                (
                    "Digest".into(),
                    "SHA-256=2vgEVkfe4d6VW+tSWAziO7BUx7uT/rA9hn1EoxUJi2o=".into(),
                ),
            ],
            br#"{"hello": "world"}"#[..].into(),
        )
    }

    #[test]
    fn can_verify_post_request() {
        let key_provider = SimpleKeyProvider::new(vec![(
            "test_key",
            Arc::new(DefaultSignatureAlgorithm::new("abcdefgh".as_bytes()))
                as Arc<dyn HttpSignatureVerify>,
        )]);
        let config = VerifyingConfig::new(key_provider).with_validate_date(false);

        let request = test_request();

        request.verify(&config).unwrap();
    }

    #[test]
    fn can_verify_get_request() {
        let key_provider = SimpleKeyProvider::new(vec![(
            "test_key",
            Arc::new(DefaultSignatureAlgorithm::new("abcdefgh".as_bytes()))
                as Arc<dyn HttpSignatureVerify>,
        )]);
        let config = VerifyingConfig::new(key_provider).with_validate_date(false);

        let request = rouille::Request::fake_http(
            "GET",
            "/foo/bar",
            vec![
                ("Date".into(), Utc.ymd(2014, 7, 8)
                    .and_hms(9, 10, 11)
                    .format("%a, %d %b %Y %T GMT")
                    .to_string()),
                ("Authorization".into(), "Signature keyId=\"test_key\",algorithm=\"hmac-sha256\",signature=\"sGQ3hA9KB40CU1pHbRLXLvLdUWYn+c3fcfL+Sw8kIZE=\",headers=\"(request-target) date".into()),
            ],
            Vec::new()
        );

        request.verify(&config).unwrap();
    }

    use actix_web::{
        http::{self, header},
        test, web, App, HttpRequest, HttpResponse,
    };

    async fn index(req: HttpRequest) -> HttpResponse {
        if let Some(_hdr) = req.headers().get(header::CONTENT_TYPE) {
            HttpResponse::Ok().into()
        } else {
            HttpResponse::BadRequest().into()
        }
    }

    #[actix_web::test]
    async fn test_index_ok() {
        let req = test::TestRequest::default()
            .insert_header(header::ContentType::plaintext())
            .to_http_request();
        let resp = index(req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_index_post() {
        let app = test::init_service(App::new().route("/", web::post().to(index))).await;
        let req = test::TestRequest::post()
            .uri("/")
            .insert_header(header::ContentType::plaintext())
            .set_payload(web::Bytes::from("Hello world"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }
}
