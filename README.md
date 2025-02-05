# http-sig

Implementation of the IETF draft [HTTP Message Signatures](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-09.html).

This crate is maintained by the developers at PassFort Limited.

## To Do
This version is a partial impementation of HTTP Message Signatures.  The following
is not supported:
- Response signing
- Processing `Accept-Signature`
- `@request-response` specialty component

## Documentation

https://docs.rs/http-sig

## Features

This crate is intended to be used with multiple different HTTP clients and/or servers.
As such, client/server-specific implementations are gated by correspondingly named
features.

### Supported crates:

| Crate / Feature name                              | Client/Server | Notes                                                         |
| ------------------------------------------------- | ------------- | ------------------------------------------------------------- |
| [reqwest](https://crates.io/crates/reqwest)       | Client        | Supports blocking and non-blocking requests.<sup>1</sup>      |
| [rouille](https://crates.io/crates/rouille)       | Server        |                                                               |

1. Due to limitations of the reqwest API, digests cannot be calculated automatically for non-blocking, streaming requests. For
   these requests, the user must add the digest manually before signing the request, or else the `Digest` header will
   not be included in the signature. Automatic digests for streaming requests *are* supported via the blocking API.

### Supported signature algorithms:

Algorithm registry: https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-09.html#name-initial-contents

- `hmac-sha256`
- `rsa-pss-sha512`
- `rsa-v1_5-sha256`
- `ecdsa-p256-sha256`

### Supported digest algorithms:

Digest registry: https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml

- `SHA-256`
- `SHA-512`

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Contributing

Thanks for your interest in http-sig.

The best way to contribute is to open issues for bugs or missing features. Bug reports
should contain as much information as possible and contain steps to reproduce. We are
particularly interested in any bugs which may impact security.

Pull requests are also accepted. However, this crate is maintained primarily for
internal use at PassFort Limited, and pull requests which do not align with our current
priorities may not be reviewed promptly. To avoid wasted effort on large features, we
strongly recommend opening an issue first to discuss the potential changes.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
