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
    /// The @method component identifier refers to the HTTP method of a request
    /// message. The component value is canonicalized by taking the value of
    /// the method as a string. Note that the method name is case-sensitive as
    /// per [SEMANTICS] Section 9.1, and conventionally standardized method
    /// names are uppercase US-ASCII. If used, the @method component
    /// identifier MUST occur only once in the covered components.
    ///
    /// For example, the following request message:
    /// ```
    /// POST /path?param=value HTTP/1.1
    /// Host: www.example.com
    /// ```
    /// Would result in the following @method value:
    /// ```
    /// "@method": POST
    /// ```
    /// If used in a response message, the @method component identifier refers
    /// to the associated component value of the request that triggered the
    /// response message being signed.
    Method,

    /// The full target URI for a request. (Section 2.3.3)
    /// The @target-uri component identifier refers to the target URI of a
    /// request message. The component value is the full absolute target URI of
    /// the request, potentially assembled from all available parts including
    /// the authority and request target as described in [SEMANTICS] Section 7.1.
    /// If used, the @target-uri component identifier MUST occur only once in
    /// the covered components.
    ///
    /// For example, the following message sent over HTTPS:
    /// ```
    /// POST /path?param=value HTTP/1.1
    /// Host: www.example.com
    /// ```
    /// Would result in the following @target-uri value:
    /// ```
    /// "@target-uri": https://www.example.com/path?param=value
    /// ```
    /// If used in a response message, the @target-uri component identifier
    /// refers to the associated component value of the request that triggered
    /// the response message being signed.
    TargetURI,

    /// The authority of the target URI for a request. (Section 2.3.4)
    Authority,

    /// The scheme of the target URI for a request. (Section 2.3.5)
    Scheme,

    /// The @request-target component identifier refers to the full request
    /// target of the HTTP request message, as defined in [SEMANTICS] Section 7.1.
    /// The component value of the request target can take different forms,
    /// depending on the type of request, as described below. If used, the
    /// @request-target component identifier MUST occur only once in the
    /// covered components.
    ///
    /// For HTTP 1.1, the component value is equivalent to the request target
    /// portion of the request line. However, this value is more difficult to
    /// reliably construct in other versions of HTTP. Therefore, it is
    /// NOT RECOMMENDED that this identifier be used when versions of HTTP
    /// other than 1.1 might be in use.
    ///
    /// The origin form value is combination of the absolute path and query
    /// components of the request URL. For example, the following request message:

    /// For example:
    /// ```
    /// POST /path?param=value HTTP/1.1
    /// Host: www.example.com
    /// ```
    /// Would result in the following @request-target component value:
    /// ```
    /// "@request-target": /path?param=value
    /// ```
    ///
    RequestTarget,

    /// The @path component identifier refers to the target path of the HTTP
    /// request message. The component value is the absolute path of the request
    /// target defined by [RFC3986], with no query component and no trailing ?
    /// character. The value is normalized according to the rules in [SEMANTICS]
    /// Section 4.2.3. Namely, an empty path string is normalized as a single
    /// slash / character, and path components are represented by their values
    /// after decoding any percent-encoded octets. If used, the @path component
    /// identifier MUST occur only once in the covered components.
    ///
    /// For example, the following request message:
    /// ```
    /// POST /path?param=value HTTP/1.1
    /// Host: www.example.com
    /// ```
    /// Would result in the following @path value:
    /// ```
    /// "@path": /path
    /// ```
    /// If used in a response message, the @path identifier refers to the
    /// associated component value of the request that triggered the response
    /// message being signed.
    Path,

    /// The @query component identifier refers to the query component of the
    /// HTTP request message. The component value is the entire normalized query
    /// string defined by [RFC3986], including the leading ? character. The value
    /// is normalized according to the rules in [SEMANTICS] Section 4.2.3. Namely,
    ///  percent-encoded octets are decoded. If used, the @query component
    /// identifier MUST occur only once in the covered components.
    ///
    /// For example, the following request message:
    /// ```
    /// POST /path?param=value&foo=bar&baz=batman HTTP/1.1
    /// Host: www.example.com
    /// ```
    /// Would result in the following @query value:
    /// ```
    /// "@query": ?param=value&foo=bar&baz=batman
    /// ```
    /// The following request message:
    /// ```
    /// POST /path?queryString HTTP/1.1
    /// Host: www.example.com
    /// ```
    /// Would result in the following @query value:
    /// ```
    /// "@query": ?queryString
    /// ```
    /// If used in a response message, the @query component identifier refers to
    /// the associated component value of the request that triggered the
    /// response message being signed.
    Query,

    /// If a request target URI uses HTML form parameters in the query string as
    /// defined in [HTMLURL] Section 5, the @query-params component identifier
    /// allows addressing of individual query parameters. The query parameters
    /// MUST be parsed according to [HTMLURL] Section 5.1, resulting in a list
    /// of (nameString, valueString) tuples. The REQUIRED name parameter of each
    /// input identifier contains the nameString of a single query parameter.
    /// Several different named query parameters MAY be included in the covered
    /// components. Single named parameters MAY occur in any order in the
    /// covered components.
    ///
    /// The component value of a single named parameter is the the valueString
    /// of the named query parameter defined by [HTMLURL] Section 5.1, which is
    /// the value after percent-encoded octets are decoded. Note that this value
    /// does not include any leading ? characters, equals sign =, or separating
    /// & characters. Named query parameters with an empty valueString are
    /// included with an empty string as the component value.
    ///
    /// If a parameter name occurs multiple times in a request, all parameter
    /// values of that name MUST be included in separate signature input lines
    /// in the order in which the parameters occur in the target URI.
    ///
    /// For example for the following request:
    /// ```
    /// POST /path?param=value&foo=bar&baz=batman&qux= HTTP/1.1
    /// Host: www.example.com
    /// ```
    /// Indicating the baz, qux and param named query parameters in would
    /// result in the following @query-param value:
    /// ```
    /// "@query-params";name="baz": batman
    /// "@query-params";name="qux":
    /// "@query-params";name="param": value
    /// ```
    /// If used in a response message, the @query-params component identifier
    /// refers to the associated component value of the request that triggered
    /// the response message being signed.
    QueryParams,

    /// The @status component identifier refers to the three-digit numeric
    /// HTTP status code of a response message as defined in [SEMANTICS]
    /// Section 15. The component value is the serialized three-digit integer of
    /// the HTTP response code, with no descriptive text. If used, the @status
    /// component identifier MUST occur only once in the covered components.
    ///
    /// For example, the following response message:
    /// ```
    /// HTTP/1.1 200 OK
    /// Date: Fri, 26 Mar 2010 00:05:00 GMT
    /// ```
    /// Would result in the following @status value:
    /// ```
    /// "@status": 200
    /// ```
    /// The @status component identifier MUST NOT be used in a request message
    Status,

    /// When a signed request message results in a signed response message, the
    /// @request-response component identifier can be used to cryptographically
    /// link the request and the response to each other by including the
    /// identified request signature value in the response's signature input
    /// without copying the value of the request's signature to the response
    /// directly. This component identifier has a single REQUIRED parameter:
    ///
    /// key
    ///
    /// Identifies which signature from the response to sign.
    ///
    /// The component value is the sf-binary representation of the signature
    /// value of the referenced request identified by the key parameter.
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
