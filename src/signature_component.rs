use std::cmp::Ordering;
use std::str::FromStr;
use std::fmt;

use http::header::{HeaderName, InvalidHeaderName};

use crate::{DerivedComponent,DerivedQueryParameter};

/// Standard Digest header .
pub const DIGEST: &str = "digest";
/// Standard Signature header.
pub const SIGNATURE:  &str = "signature";
/// Standard Signature-input header.
pub const SIGNATURE_INPUT:  &str = "signature-input";


/// A header which can be incorporated into a HTTP signature.
///
/// Headers can either be normal HTTP headers or [DerivedComponent]
/// used for including additional information into a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureComponent {
    /// This header is one of the special "pseudo-headers"
    Derived(DerivedComponent),
    /// The special case @query-params component
    DerivedParam(DerivedQueryParameter),
    /// This header is a normal HTTP heaeder.
    Header(HeaderName),
}

impl fmt::Display for SignatureComponent {
    /// Returns the string representation of the header, as it will appear
    /// in the HTTP signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Derived(h) => f.write_str(h.to_string().as_ref()),
            Self::DerivedParam(dqp) => f.write_str(dqp.to_string().as_ref()),
            Self::Header(h) => f.write_str(h.as_str()),
        }
    }
}

impl FromStr for SignatureComponent {
    type Err = InvalidHeaderName;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DerivedComponent::from_str(s)
            .map(Into::into)
            .or_else(|_| DerivedQueryParameter::from_str(s).map(Into::into))
            .or_else(|_| HeaderName::from_str(s).map(Into::into))
    }
}

impl Ord for SignatureComponent {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd for SignatureComponent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<HeaderName> for SignatureComponent {
    fn from(other: HeaderName) -> Self {
        Self::Header(other)
    }
}

impl From<DerivedComponent> for SignatureComponent {
    fn from(other: DerivedComponent) -> Self {
        Self::Derived(other)
    }
}
impl From<DerivedQueryParameter> for SignatureComponent {
    fn from(other: DerivedQueryParameter) -> Self {
        Self::DerivedParam(other)
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

