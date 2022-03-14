//! Derived Components
//! 
use std::str::FromStr;

/// Http-Signature Derived Components
/// 
/// In addition to HTTP fields, there are a number of different components 
/// that can be derived from the control data, processing context, or other 
/// aspects of the HTTP message being signed. Such derived components can be 
/// included in the signature base by defining a component identifier and the 
/// derivation method for its component value.
/// They are defubed in the draft specification at 
/// [Derived Components](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-09.html#name-derived-components)
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
#[non_exhaustive]
pub enum DerivedComponent {
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

impl DerivedComponent {
    /// Returns the string representation of the pseudo-header.
    pub fn as_str(&self) -> &str {
        match self {
            DerivedComponent::SignatureParams => "@signature-params",
            DerivedComponent::Method => "@method",
            DerivedComponent::TargetURI => "@target-uri",
            DerivedComponent::Authority => "@authority",
            DerivedComponent::Scheme => "@scheme",
            DerivedComponent::RequestTarget => "@request-target",
            DerivedComponent::Path => "@path",
            DerivedComponent::Query => "@query",
            DerivedComponent::QueryParams => "@query-params",
            DerivedComponent::Status => "@status",
            DerivedComponent::RequestResponse => "@request-response",
        }
    }
}

impl FromStr for DerivedComponent {
    type Err = ();

    fn from_str(s: &str) -> Result<DerivedComponent, Self::Err> {
        match s.to_lowercase().as_ref() {
            "@signature-params" => Ok(DerivedComponent::SignatureParams),
            "@method" => Ok(DerivedComponent::Method),
            "@target-uri" => Ok(DerivedComponent::TargetURI),
            "@authority" => Ok(DerivedComponent::Authority),
            "@scheme" => Ok(DerivedComponent::Scheme),
            "@request-target" => Ok(DerivedComponent::RequestTarget),
            "@path" => Ok(DerivedComponent::Path),
            "@query" => Ok(DerivedComponent::Query),
            "@query-params" => Ok(DerivedComponent::QueryParams),
            "@status" => Ok(DerivedComponent::Status),
            "@request-response" => Ok(DerivedComponent::RequestResponse),
            _ => Err(()),
        }
    }
}

pub trait Derivable {
    fn derive(&self, component: DerivedComponent) -> Option<String>;
}
