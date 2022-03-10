//! # HTTP Signature Validator
//! A test app to enable validating canonicalization assumptions.
//!
//! ## Testing Canonicalization
//! To verify the fully canonicalized signing input.
//!
//! Basic syntax:
//!
//! ```bash
//! > cat ../test_data/basic_request.txt | cargo run -- canonicalize -l sig \
//!  -a 'rsa-v1_5-sha256' -d date
//! ```
//!
//! This will produce the following output:
//!
//! ```bash, no_run
//! "date": Sun, 05 Jan 2014 21:31:40 GMT
//! "@signature-params": ("date");alg="rsa-v1_5-sha256"
//! ```
//!
//! ## Testing Signing
//! To generate a signed request that can be tested with a verifying server
//! run something akin to the following:
//!
//! ```bash
//! > cat ../test_data/basic_request.txt| cargo run -q -- sign -l sig -d "host date digest" -t RSA -a 'rsa-v1_5-sha256' -k "test-key-rsa" -p ../test_data/rsa-v1_5-2048-private-pk8.der
//! ```
//!
//! The above will produce the following output:
//!
//! ```bash, no_run
//! POST /foo?param=value&pet=dog HTTP/1.1
//! signature: sig=:Gv5M2DlTCg1cc7l1D4Vuu5Dx3DJ2+OCgv76dnmSDKzY=:
//! host: example.com
//! content-type: application/json
//! signature-input: sig=("host" "date" "digest");alg="hmac-sha256";keyid="test-key-rsa"
//! date: Sun, 05 Jan 2014 21:31:40 GMT
//! digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
//! content-length: 18
//!
//! {"hello": "world"}
//! ```
//!
//! ## Testing Verification
//!
//! ```bash
//! > cat ../test_data/signed_request.txt| cargo run -q -- verify -t RSA -k "test-key-rsa" -u ../test_data/rsa-2048-public-key.pk8
//! ```
//!
//! If successful, there will be no output.  If verification fails, you can turn
//! on logging to see what might be failing:
//!
//! ```bash
//! cat ../test_data/signed_request.txt| RUST_LOG=http_sig=trace cargo run -q -- verify -t RSA -k "test-key-rsa" -u .../test_data/rsa-2048-public-key.pk8
//! ```

// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 | openssl pkcs8 -topk8 -nocrypt -outform der -out rsa-2048-private-key.pk8
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use http_sig::mock_request::MockRequest;
use http_sig::{
    CanonicalizeConfig, CanonicalizeExt, Header,
    RsaPssSha256Sign, RsaPssSha256Verify,
    RsaPssSha512Sign, RsaPssSha512Verify,
    RsaSha256Sign, RsaSha256Verify,
    RsaSha512Sign, RsaSha512Verify,
    SigningConfig, SigningExt, SimpleKeyProvider,
    VerifyingConfig, VerifyingExt,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
enum Mode {
    Canonicalize,
    Sign,
    Verify,
}

#[derive(Debug, StructOpt)]
#[structopt(about = "A validator for use with the HTTP-signatures test suite.")]
struct Opt {
    /// A list of header names, optionally quoted
    #[structopt(subcommand)]
    mode: Mode,

    /// A list of header names, optionally quoted
    #[allow(clippy::option_option)]
    #[structopt(short = "d", long, global = true, min_values = 0)]
    headers: Option<Option<String>>,

    /// A Key Id string.
    #[structopt(short, long = "keyId", global = true)]
    key_id: Option<String>,

    /// A private key file name filename.
    #[structopt(short, long, parse(from_os_str), global = true)]
    private_key: Option<PathBuf>,


    /// A public key file name filename.
    #[structopt(short = "u", long, parse(from_os_str), global = true)]
    public_key: Option<PathBuf>,

    /// Signature label to use
    #[structopt(short, long, global = true)]
    label: Option<String>,

    /// One of: rsa-v_1-sha256, rsa-v_1-sha512, rsa-pss-sha256, rsa-pss-sha512, hmac-sha256, hmac-sha512
    #[structopt(short, long, global = true)]
    algorithm: Option<String>,

    /// The created param for the signature.
    #[structopt(short, long, global = true)]
    created: Option<i64>,

    /// The expires param for the signature.
    #[structopt(short, long, global = true)]
    expires: Option<i64>,

    /// The nonce to use for signing
    #[structopt(short, long, global = true)]
    nonce: Option<String>,
}

impl Opt {
    fn parse_headers(&self) -> Result<Option<Vec<Header>>, Box<dyn Error>> {
        Ok(if let Some(headers) = &self.headers {
            Some(if let Some(headers) = headers {
                let headers: Vec<Header> = headers
                    .split_ascii_whitespace()
                    .map(|s| s.parse::<Header>().with_context(|| format!("{:?}", s)))
                    .collect::<Result<_, _>>()?;
                headers
            } else {
                Vec::new()
            })
        } else {
            None
        })
    }

    fn canonicalize_config(&self) -> Result<CanonicalizeConfig, Box<dyn Error>> {
        let mut config = CanonicalizeConfig::default();
        if let Some(created) = self.created {
            config.set_context_created(created.into());
        }
        if let Some(expires) = self.expires {
            config.set_context_expires(expires.into());
        }
        if let Some(headers) = self.parse_headers()? {
            config.set_headers(headers);
        }
        if let Some(nonce) = self.nonce.as_deref() {
            config.set_context_nonce(&nonce);
        }
        if let Some(label) = self.label.as_deref() {
            config.set_label(label);
        }
        if let Some(key_id) = self.key_id.as_deref() {
            config.set_context_key_id(key_id);
        }

        match self.algorithm.as_deref() {
            Some("rsa-v1_5-sha256") |
            Some("rsa-v1_5-sha512") |
            Some("rsa-pss-sha256") |
            Some("rsa-pss-sha512") |
            Some("ecdsa-p256-sha256") |
            Some("hmac-sha256") => {
                config.set_context_algorithm(self.algorithm.as_deref().unwrap())
            }
            Some(other) => return Err(anyhow!("Unknown algorithm: {}", other).into()),
            None => return Err(anyhow!("No algorithm provided").into())
        }

        match self.parse_headers()? {
            Some(headers) => {
                config.set_headers(headers);
            }
            None => {
                config.set_headers(Vec::new());
            }
        }

        Ok(config)
    }
    fn signing_config(&self) -> Result<SigningConfig, Box<dyn Error>> {
        let key_id = self.key_id.clone().unwrap_or_default();
        let label = self.label.clone().unwrap_or("sig".to_owned());

        let key_data = if let Some(key) = self.private_key.as_ref() {
            Some(fs::read(key)?)
        } else {
            None
        };

        match self.algorithm.as_deref() {
            Some("rsa-pss-sha256")
            | Some("rsa-pss-sha512")
            | Some("rsa-v1_5-sha256")
            | Some("rsa-v1_5-sha512")
            | Some("hmac-sha256")
            | Some("ecdsa-p256-sha256")
            | None => {}
            Some(other) => return Err(anyhow!("Unknown algorithm: {}", other).into()),
        }

        let mut config = match (self.algorithm.as_deref(), key_data) {
            (Some("rsa-v1_5-sha256"), Some(pkey)) => {
                SigningConfig::new(&label, &key_id, RsaSha256Sign::new_pkcs8(&pkey)?)
            },
            (Some("rsa-v1_5-sha512"), Some(pkey)) => {
                SigningConfig::new(&label, &key_id, RsaSha512Sign::new_pkcs8(&pkey)?)
            },
            (Some("rsa-pss-sha256"), Some(pkey)) => {
                SigningConfig::new(&label, &key_id, RsaPssSha256Sign::new_pkcs8(&pkey)?)
            },
            (Some("rsa-pss-sha512"), Some(pkey)) => {
                SigningConfig::new(&label, &key_id, RsaPssSha512Sign::new_pkcs8(&pkey)?)
            },
            (Some(_), None) => return Err(anyhow!("No key provided").into()),
            (Some(other), Some(_)) => {
                return Err(anyhow!("Unsupported algorithm: {}", other).into())
            }
            (None, _) => return Err(anyhow!("No algorithm provided").into()),
        };

        if let Some(headers) = self.parse_headers()? {
            config.set_headers(&headers);
        }

        if let Some(created) = self.created {
            config.set_signature_created_at(created);
        }

        if let Some(expires) = self.expires {
            config.set_signature_expires_at(expires);
        }

        // Disable various convenience options that would mess up the test suite
        config.set_add_date(false);
        config.set_compute_digest(false);
        config.set_add_host(false);
        config.set_skip_missing(false);

        Ok(config)
    }
    fn verification_config(&self) -> Result<VerifyingConfig, Box<dyn Error>> {
        let key_id = self.key_id.clone().unwrap_or_default();
        let key_data = if let Some(key) = self.public_key.as_ref() {
            Some(fs::read(key)?)
        } else {
            None
        };

        let mut key_provider = SimpleKeyProvider::default();

        match self.algorithm.as_deref() {
            Some("rsa-pss-sha256")
            | Some("rsa-pss-sha512")
            | Some("rsa-v1_5-sha256")
            | Some("rsa-v1_5-sha512")
            | Some("hmac-sha256")
            | Some("ecdsa-p256-sha256")
            | None => {}
            Some(other) => return Err(anyhow!("Unknown algorithm: {}", other).into()),
        }
        
        match (self.algorithm.as_deref(), key_data) {
            (Some("rsa-v1_5-sha256"), Some(pkey)) => {
                key_provider.add(&key_id, Arc::new(RsaSha256Verify::new_der(&pkey)?))
            },
            (Some("rsa-v1_5-sha512"), Some(pkey)) => {
                key_provider.add(&key_id, Arc::new(RsaSha512Verify::new_der(&pkey)?))
            },
            (Some("rsa-pss-sha256"), Some(pkey)) => {
                key_provider.add(&key_id, Arc::new(RsaPssSha256Verify::new_der(&pkey)?))
            },
            (Some("rsa-pss-sha512"), Some(pkey)) => {
                key_provider.add(&key_id, Arc::new(RsaPssSha512Verify::new_der(&pkey)?))
            },
            (Some(_), None) => return Err(anyhow!("No key provided").into()),
            (Some(other), Some(_)) => return Err(anyhow!("Unknown key type: {}", other).into()),
            (None, _) => {}
        }

        let mut config = VerifyingConfig::new(key_provider);

        // Disable various convenience options that would mess up the test suite
        config.set_require_digest(false);
        config.set_validate_date(false);
        //config.set_required_headers(&[]);

        Ok(config)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let opt = Opt::from_args();

    let mut req = MockRequest::from_reader(&mut io::stdin().lock())?;

    //log::info!("{:#?}", req);
    match opt.mode {
        Mode::Canonicalize => {
            let res = req.canonicalize(&opt.canonicalize_config()?)?;
            io::stdout().lock().write_all(res.as_bytes())?;
        }
        Mode::Sign => {
            req.sign(&opt.signing_config()?)?;
            req.write(&mut io::stdout().lock())?;
        }
        Mode::Verify => {
            let config = opt.verification_config()?;
            req.verify(&config)?;
        }
    }

    Ok(())
}
