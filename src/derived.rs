//! Derived Components
//!
use std::str::FromStr;
use std::fmt;
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

    /// Section 2.3.10
    Status,

    /// Section 2.3.11.
    RequestResponse,
}

impl fmt::Display for  DerivedComponent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DerivedComponent::SignatureParams => f.write_str("@signature-params"),
            DerivedComponent::Method => f.write_str("@method"),
            DerivedComponent::TargetURI => f.write_str("@target-uri"),
            DerivedComponent::Authority => f.write_str("@authority"),
            DerivedComponent::Scheme => f.write_str("@scheme"),
            DerivedComponent::RequestTarget => f.write_str("@request-target"),
            DerivedComponent::Path => f.write_str("@path"),
            DerivedComponent::Query => f.write_str("@query"),
            DerivedComponent::Status => f.write_str("@status"),
            DerivedComponent::RequestResponse => f.write_str("@request-response"),
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
            "@status" => Ok(DerivedComponent::Status),
            "@request-response" => Ok(DerivedComponent::RequestResponse),
            _ => Err(()),
        }
    }
}

/// Query Parameter
/// Section 2.2.9
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct DerivedQueryParameter {
    /// Qeuery Parameter name
    pub param: String,
}

// TODO: This should never return an empty string
impl FromStr for DerivedQueryParameter {
    type Err = ();
    fn from_str(text: &str) -> Result<DerivedQueryParameter, Self::Err> {
        let v: Vec<&str> =text.split(':').collect();
        if v.len() != 2 {
            return Err(())
        }
        Ok(DerivedQueryParameter{param: v[1].trim().to_owned()})
    }
}

impl fmt::Display for DerivedQueryParameter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "@query-params: {}", self.param)
    }
}

/// Derivable
pub trait Derivable<T> {
    /// Derivable
    fn derive(&self, component: &T) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dqp_to_string() {
        let param = "param1".to_string();
        let dqp = DerivedQueryParameter{param};
        println!("{}",dqp);
        assert_eq!(dqp.to_string(), "@query-params: param1");
    }

    #[test]
    fn test_string_to_dqp() {
        let s = "@query-params: param1";
        let dqp = DerivedQueryParameter::from_str(s).unwrap();
        let dqp2 = DerivedQueryParameter{param: "param1".to_owned()};
        assert_eq!(dqp, dqp2);
    }

}