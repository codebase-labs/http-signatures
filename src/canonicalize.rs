//! Canonicalize request headers and derived components
//!
//! The http-signatures spec provides guidance for ensuring all signature
//! components, including standard headers, are placed in a canonical
//! format for proper digesting.  For instance, request crates tht allow
//! multiple instances of a single header need to be canonicalized into a
//! single header with multiple values.
//!
//! Any object that derives the RequestLike trait must also provide values
//! for Derived Components.  Derived Component are not headers, but are often
//! derived from request header and URI values.
use http::HeaderValue;
use itertools::{Either, Itertools};
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::iter::Iterator;
use std::str::FromStr;
use thiserror::Error;

use crate::derived::DerivedComponent::SignatureParams;
use crate::signature_component::SignatureComponent;

/// The types of error which may occur whilst computing the canonical "signature string"
/// for a request.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CanonicalizeError {
    /// One or more components required to be part of the signature was not present
    /// on the request, and the `skip_missing` configuration option
    /// was disabled.
    #[error("Missing components required for signature: {0:?}")]
    MissingComponents(Vec<SignatureComponent>),
    /// Malformed `signature-input component
    #[error("Malformed Signature-Input component")]
    SignatureInputError,
}

/// Base trait for all request types
pub trait RequestLike {
    /// Returns an existing header on the request. This method *must* reflect changes made
    /// by the `ClientRequestLike::set_header` method.
    fn header(&self, header: &SignatureComponent) -> Option<HeaderValue>;

    /// Returns true if this request contains a value for the specified header. If this
    /// returns true, following requests to `header()` for the same name must return a
    /// value.
    fn has_header(&self, header: &SignatureComponent) -> bool {
        self.header(header).is_some()
    }
}

impl<T: RequestLike> RequestLike for &T {
    fn header(&self, header: &SignatureComponent) -> Option<HeaderValue> {
        (**self).header(header)
    }
}

/// Helper enum for canonicalizing the signature components
#[derive(Clone, Debug)]
pub enum ComponentValue {
    /// String type
    StringValue(String),
    /// Number type
    NumberValue(i64),
}

/// Generate string from ComponentValue
impl ToString for ComponentValue {
    fn to_string(&self) -> String {
        match self {
            Self::StringValue(value) => format!(r#""{}""#, value),
            Self::NumberValue(value) => format!("{:?}", value),
        }
    }
}
impl ComponentValue {
    /// Turn a key/value pair into a ComponentValue
    pub fn from_str(key: &str, value: &str) -> Result<Self, CanonicalizeError> {
        match key {
            "created" => Ok(ComponentValue::NumberValue(
                value.parse::<i64>().unwrap_or(0),
            )),
            "expires" => Ok(ComponentValue::NumberValue(
                value.parse::<i64>().unwrap_or(0),
            )),
            "alg" => Ok(ComponentValue::StringValue(String::from(value))),
            "keyid" => Ok(ComponentValue::StringValue(String::from(value))),
            "nonce" => Ok(ComponentValue::StringValue(String::from(value))),
            _ => Err(CanonicalizeError::SignatureInputError),
        }
    }
}

/// Parse the set of components from Signature-Input
///
/// The input value should be formatted as `("header1" "header2" ...)`
fn parse_components(input: &str) -> Result<Vec<&str>, CanonicalizeError> {
    // Remove the parentheses
    let pat: &[_] = &['(', ')'];
    let input = input.trim().trim_matches(pat).trim();
    if input.is_empty(){
        return Ok(Vec::new());
    }

    // Splt on the spaces
    let components = input
        .split(' ')
        .map(|part| {
            let v = part.trim().trim_matches('"');
            Some(v)
        })
        .collect::<Option<Vec<&str>>>()
        .or_else(|| {
            info!("Canonicalization Failed: Malformed components in Signature-Info");
            None
        });
    if components.is_none() {
        return Err(CanonicalizeError::SignatureInputError);
    }

    Ok(components.unwrap())
}

/// Parse the set of signature components into a hash map
fn component_map(components: &str) -> Result<BTreeMap<String, ComponentValue>, CanonicalizeError> {
    let components = components
        .trim()
        .split(';')
        .map(|part: &str| {
            let mut kv = part.splitn(2, '=');
            let k = String::from(kv.next()?.trim());
            let v = ComponentValue::from_str(&k, kv.next()?.trim().trim_matches('"')).unwrap();
            Some((k, v))
        })
        .collect::<Option<BTreeMap<String, ComponentValue>>>()
        .or_else(|| {
            info!("Canonicalization Failed: Malformed components list in 'Signature-Info' header");
            None
        });
    if components.is_none() {
        return Err(CanonicalizeError::SignatureInputError);
    }
    Ok(components.unwrap())
}

fn split_once_or_err<'a, 'b>(
    input: &'a str,
    pattern: &'b str,
) -> Result<(&'a str, &'a str), CanonicalizeError> {
    match input.split_once(pattern) {
        Some((label, components)) => Ok((label, components)),
        None => {
            info!("Canonicalization Failed: Malformed Signature-Input header value");
            Err(CanonicalizeError::SignatureInputError)
        }
    }
}
/// Parsed Signature Input parameters
struct SignatureInput {
    label: String, 
    components: Vec<SignatureComponent>, 
    contexts: BTreeMap<String, ComponentValue>
}

/// Parse the Signature-Input header into (label, components, components)
///
/// The Signature-input header is formatted as:
/// ```text
/// <label> =("header1" "header2" ...);alg="<signing alg>";[created=<ts>;][exxpires=<ts>;]keyid="<key>";[nonce=<nonce>]
/// ```
/// Example:
/// ```text
/// sig=("@method" "@scheme" "@authority" "@target-uri" "@request-target");alg="hmac-sha256";created=1640871972;keyid="My Key";nonce="some_random_nonce"
/// ```
impl TryFrom<&str> for SignatureInput {
    type Error = CanonicalizeError;
    fn try_from(signature_input_header: &str) -> Result<Self, Self::Error> {
        let (label, components) = split_once_or_err(signature_input_header, "=")?;

        let (component_list, components) = split_once_or_err(components, ";")?;
    
        let component_list = parse_components(component_list).map_err(|e| {
            info!("Verification Failed: No header list for 'Signature-Info' header");
            e
        })?;
    
        let component_list: Vec<SignatureComponent> = component_list
            .iter()
            .map(|s| SignatureComponent::from_str(*s).unwrap())
            .collect();
    
        let contexts = component_map(components).map_err(|e| {
            info!("Verification Failed: No components for 'Signature-Info' header");
            e
        })?;
    
        Ok( Self{label: label.to_string(), components: component_list, contexts})
    }
}

/// Configuration for computing the canonical "signature string" of a request.
///
/// The signature string is composed of the set of the components configured on the
/// [SignatureConfig] along with the set of signing context components. This set
/// of components + components is repeated in the `@signature-params`  derived componnent,
/// as well as the final `Signature-input` header that is placed on the request.
#[derive(Debug, Default)]
pub struct CanonicalizeConfig {
    label: Option<String>,
    components: Option<Vec<SignatureComponent>>,
    context: BTreeMap<String, ComponentValue>,
}

impl CanonicalizeConfig {
    /// Creates a new canonicalization configuration using the default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create th config from the Signature-Input header of a request
    pub fn from_signature_input(input: &str) -> Result<Self, CanonicalizeError> {
        let mut config = Self::new();

        let signature_input = SignatureInput::try_from(input)?;
        config.set_label(&signature_input.label);
        config.set_components(signature_input.components);
        config.set_contexts(signature_input.contexts);

        Ok(config)
    }

    /// Get the label
    pub fn label(&self) -> Option<String> {
        self.label.as_ref().cloned()
    }

    /// Set the label
    pub fn with_label(mut self, label: &str) -> Self {
        self.label = Some(String::from(label));
        self
    }
    /// Set the label in place
    pub fn set_label(&mut self, label: &str) -> &mut Self {
        self.label = Some(String::from(label));
        self
    }

    /// Set the components to include in the signature
    pub fn with_components(mut self, components: Vec<SignatureComponent>) -> Self {
        self.components = Some(components);
        self
    }

    /// Set the components to include in the signature
    pub fn set_components(&mut self, components: Vec<SignatureComponent>) -> &mut Self {
        self.components = Some(components);
        self
    }

    /// Get the components to include in the signature
    pub fn components(&self) -> Option<impl IntoIterator<Item = &SignatureComponent>> {
        self.components.as_ref()
    }

    /// Establish the set of context values.
    pub fn set_contexts(&mut self, contexts: BTreeMap<String, ComponentValue>) -> &mut Self {
        self.context = contexts;
        self
    }

    /// Get a signature context component by key
    pub fn get_context(&self, key: &str) -> Option<ComponentValue> {
        //self.context.get(key).map(|value| value.clone())
        self.context.get(key).cloned()
    }

    /// Add a signature context component
    fn add_context(&mut self, key: &str, value: ComponentValue) {
        self.context.insert(String::from(key), value);
    }

    /// Get the `created` context
    pub fn created(&self) -> Option<i64> {
        match self.get_context("created") {
            Some(ComponentValue::NumberValue(i)) => Some(i),
            _ => None,
        }
    }

    /// Add `created` to the context
    pub fn set_context_created(&mut self, ts: i64) {
        self.add_context("created", ComponentValue::NumberValue(ts));
    }

    /// Get the `expires` context
    pub fn expires(&self) -> Option<i64> {
        match self.get_context("expires") {
            Some(ComponentValue::NumberValue(i)) => Some(i),
            _ => None,
        }
    }

    /// Add `expires` to the context
    pub fn set_context_expires(&mut self, ts: i64) {
        self.add_context("expires", ComponentValue::NumberValue(ts));
    }

    /// Get the `alg` context
    pub fn alg(&self) -> Option<String> {
        match self.get_context("alg") {
            Some(ComponentValue::StringValue(s)) => Some(s),
            _ => None,
        }
    }

    /// Add `alg` to the context
    pub fn set_context_algorithm(&mut self, alg: &str) {
        self.add_context("alg", ComponentValue::StringValue(String::from(alg)));
    }

    /// Get the `nonce` context
    pub fn nonce(&self) -> Option<String> {
        match self.get_context("nonce") {
            Some(ComponentValue::StringValue(s)) => Some(s),
            _ => None,
        }
    }

    /// Add `nonce` to the context
    pub fn set_context_nonce(&mut self, nonce: &str) {
        self.add_context("nonce", ComponentValue::StringValue(String::from(nonce)));
    }

    /// Get the `keyid` context
    pub fn key_id(&self) -> Option<String> {
        match self.get_context("keyid") {
            Some(ComponentValue::StringValue(s)) => Some(s),
            _ => None,
        }
    }

    /// Add `keyid` to the context
    pub fn set_context_key_id(&mut self, key_id: &str) {
        self.add_context("keyid", ComponentValue::StringValue(String::from(key_id)));
    }

    /// Generates the canonicalized string of components
    pub fn get_context_as_string(&self) -> String {
        let result = self
            .context
            .iter()
            .map(|(k, v)| format!("{}={}", k, v.to_string()))
            .collect::<Vec<String>>();
        result.join(";")
    }
}

/// Extension method for computing the canonical "signature string" of a request.
pub trait CanonicalizeExt {
    /// Compute the canonical representation of this request
    fn canonicalize(
        &self,
        config: &CanonicalizeConfig,
    ) -> Result<SignatureString, CanonicalizeError>;
}

/// Opaque struct storing a computed signature string.
pub struct SignatureString {
    content: Vec<u8>,
    pub(crate) components: Vec<(SignatureComponent, HeaderValue)>,
}

impl SignatureString {
    /// Obtain a view of this signature string as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.content
    }
}

impl From<SignatureString> for Vec<u8> {
    fn from(other: SignatureString) -> Self {
        other.content
    }
}

impl<T: RequestLike> CanonicalizeExt for T {
    /// Build signature string block
    ///
    /// The purpose of `canonicalize` is to ensure the set of components that are
    /// digested are first placed in a canonicalized format, so that both the
    /// client (creating a signed request) and the server (verifying the signature)
    /// digest in the same exact way.
    fn canonicalize(
        &self,
        config: &CanonicalizeConfig,
    ) -> Result<SignatureString, CanonicalizeError> {
        // Find value of each header
        let (components, missing_components): (Vec<_>, Vec<_>) = config
            .components
            .as_deref()
            .unwrap()
            .iter()
            .cloned()
            .partition_map(|header| {
                if let Some(header_value) = self.header(&header) {
                    Either::Left((header, header_value))
                } else {
                    Either::Right(header)
                }
            });

        if !missing_components.is_empty() {
            return Err(CanonicalizeError::MissingComponents(missing_components));
        }

        // Add the @Signature-Param DerivedComponent, built on the header collection
        // and the signature context
        let signature_context = config.get_context_as_string();

        // Format the list of components as ["header1" "header2"]
        let joined_components = components
            .iter()
            .map(|(header, _)| format!(r#""{}""#, header))
            .join(" ");

        // Generate the Signature-params DerivedComponent, and apply it to the
        // CanonicalizeConfig
        let signature_params_value = format!("({});{}", &joined_components, &signature_context);
        let mut components = components.to_vec();

        components.push((
            SignatureComponent::Derived(SignatureParams),
            signature_params_value.try_into().ok().unwrap(),
        ));

        // Canonicalize the components
        let mut content = Vec::new();
        for (name, value) in &components {
            if !content.is_empty() {
                content.push(b'\n');
            }
            content.extend(format!(r#""{}""#, name).as_bytes());
            content.extend(b": ");
            content.extend(value.as_bytes());
        }

        Ok(SignatureString {
            content,
            components,
        })
    }
}
