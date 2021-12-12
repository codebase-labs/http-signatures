use std::cmp::Ordering;
use std::str::FromStr;

use http::header::{HeaderName, InvalidHeaderName};

///
/// Pseudo-headers are used to incorporate additional information into a HTTP
/// signature for which there is no corresponding HTTP header.
///
/// They are described as "special headers" in the draft specification:
/// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#canonicalization
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
#[non_exhaustive]
pub enum PseudoHeader {
    /// The signature metadata parameters for this signature. (Section 2.3.1)
    SignatureParams,
    /// The method used for a request. (Section 2.3.2)
    Method,
    /// The full target URI for a request. (Section 2.3.3)
    TargetURI,
    /// The authority of the target URI for a request. (Section 2.3.4)
    Authority,
    /// The scheme of the target URI for a request. (Section 2.3.5)
    Scheme,
    /// The `(request-target)` pseudo-header is constructed by joining the lower-cased
    /// request method (`get`, `post`, etc.) and the request path (`/some/page?foo=1`)
    /// with a single space character.
    ///
    /// For example:
    /// `get /index.html`
    RequestTarget,
    /// The absolute path portion of the target URI for a request. (Section 2.3.7)
    Path,
    /// The query portion of the target URI for a request. (Section 2.3.8)
    Query,
    /// The parsed query parameters of the target URI for a request. (Section 2.3.9)
    QueryParams,
    /// The status code for a response. (Section 2.3.10)
    Status,
    /// A signature from a request message that resulted in this response message. (Section 2.3.11)
    RequestResponse,
    /// Passed as part of the auth header
    Created,
    /// Passed as part of the auth header
    Expires,
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
            PseudoHeader::Created => "@created",
            PseudoHeader::Expires => "@expires",
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
            "@created" => Ok(PseudoHeader::Created),
            "@expires" => Ok(PseudoHeader::Expires),
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
