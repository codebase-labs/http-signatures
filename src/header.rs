use std::cmp::Ordering;
use std::str::FromStr;

use http::header::{HeaderName, InvalidHeaderName};

/// Standard Digest header .
pub const DIGEST: &'static str = "digest";
/// Standard Signature header.
pub const SIGNATURE:  &'static str = "signature";
/// Standard Signature-input header.
pub const SIGNATURE_INPUT:  &'static str = "signature-input";

///
/// Pseudo-headers are used to incorporate additional information into a HTTP
/// signature for which there is no corresponding HTTP header.
///
/// They are described as "special headers" in the draft specification:
/// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#canonicalization
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
#[non_exhaustive]
pub enum PseudoHeader {
    /// Section 2.3.1.
    SignatureParams,

    /// Section 2.3.2.
    Method,

    /// Section 2.3.3.
    TargetURI,

    /// Section 2.3.4
    Authority,

    /// Section 2.3.5
    Scheme,

    /// Section 2.3.6
    RequestTarget,

    /// Section 2.3.7.
    Path,

    /// Section 2.3.8
    Query,

    /// Section 2.3.9
    QueryParams,

    /// Section 2.3.10
    Status,

    /// Section 2.3.11.
    RequestResponse,
}

impl PseudoHeader {
    /// Returns the string representation of the pseudo-header.
    pub fn as_str(&self) -> &str {
        match self {
            PseudoHeader::SignatureParams => "@signature-params",
            PseudoHeader::Method => "@method",
            PseudoHeader::TargetURI => "@target-uri",
            PseudoHeader::Authority => "@authority",
            PseudoHeader::Scheme => "@scheme",
            PseudoHeader::RequestTarget => "@request-target",
            PseudoHeader::Path => "@path",
            PseudoHeader::Query => "@query",
            PseudoHeader::QueryParams => "@query-params",
            PseudoHeader::Status => "@status",
            PseudoHeader::RequestResponse => "@request-response",
        }
    }
}

impl FromStr for PseudoHeader {
    type Err = ();
    fn from_str(s: &str) -> Result<PseudoHeader, Self::Err> {
        match s {
            "@signature-params" => Ok(PseudoHeader::SignatureParams),
            "@method" => Ok(PseudoHeader::Method),
            "@target-uri" => Ok(PseudoHeader::TargetURI),
            "@authority" => Ok(PseudoHeader::Authority),
            "@scheme" => Ok(PseudoHeader::Scheme),
            "@request-target" => Ok(PseudoHeader::RequestTarget),
            "@path" => Ok(PseudoHeader::Path),
            "@query" => Ok(PseudoHeader::Query),
            "@query-params" => Ok(PseudoHeader::QueryParams),
            "@status" => Ok(PseudoHeader::Status),
            "@request-response" => Ok(PseudoHeader::RequestResponse),
            _ => Err(()),
        }
    }
}

/// A header which can be incorporated into a HTTP signature.
///
/// Headers can either be normal HTTP headers or special "pseudo-headers"
/// used for including additional information into a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    /// This header is one of the special "pseudo-headers"
    Pseudo(PseudoHeader),
    /// This header is a normal HTTP heaeder.
    Normal(HeaderName),
}

impl Header {
    /// Returns the string representation of the header, as it will appear
    /// in the HTTP signature.
    pub fn as_str(&self) -> &str {
        match self {
            Header::Pseudo(h) => h.as_str(),
            Header::Normal(h) => h.as_str(),
        }
    }
}

impl FromStr for Header {
    type Err = InvalidHeaderName;
    fn from_str(s: &str) -> Result<Header, Self::Err> {
        PseudoHeader::from_str(s)
            .map(Into::into)
            .or_else(|_| HeaderName::from_str(s).map(Into::into))
    }
}

impl Ord for Header {
    fn cmp(&self, other: &Header) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for Header {
    fn partial_cmp(&self, other: &Header) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<HeaderName> for Header {
    fn from(other: HeaderName) -> Self {
        Header::Normal(other)
    }
}

impl From<PseudoHeader> for Header {
    fn from(other: PseudoHeader) -> Self {
        Header::Pseudo(other)
    }
}

/// The Digest, Signature, and Signature-Input headers should be normal headers
/// supported directly by the [http] crate.  But there is no mechanism for
/// extending the set of StandardHeaders.  The following will suffice until
/// that is remedied

/// Standard Digest header
pub fn digest_header() -> HeaderName {
    HeaderName::from_static(DIGEST)
}

/// Standard Signature header
pub fn signature_header() -> HeaderName {
    HeaderName::from_static(SIGNATURE)
}

/// Standard Signature-Input header
pub fn signature_input_header() -> HeaderName {
    HeaderName::from_static(SIGNATURE_INPUT)
}

