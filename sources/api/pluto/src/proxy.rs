use crate::hyper_proxy::{Proxy, ProxyConnector};
use headers::Authorization;
use hyper::Uri;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::dns::GaiResolver;
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::crypto::CryptoProvider;
use snafu::{ResultExt, Snafu};
use std::sync::Arc;
use url::Url;

#[derive(Debug, Snafu)]
pub(super) enum Error {
    #[snafu(display("Unable to parse '{}' as URI: {}", input, source))]
    UriParse {
        input: String,
        source: hyper::http::uri::InvalidUri,
    },

    #[snafu(display("Unable to parse '{}' as URL: {}", input, source))]
    UrlParse {
        input: String,
        source: url::ParseError,
    },

    #[snafu(display("Failed to create proxy creator: {}", source))]
    ProxyConnector { source: std::io::Error },
}

type Result<T> = std::result::Result<T, Error>;

/// Setups a hyper-based HTTP client configured with a proxy connector.
// TODO: in here, change setup_http_client to setup_http_connector, and use that function
// in the http_connector method of the HttpClient trait
pub(crate) fn setup_http_client<H, N>(
    https_proxy: H,
    no_proxy: Option<&[N]>,
) -> Result<ProxyConnector<HttpsConnector<HttpConnector>>>
where
    H: AsRef<str>,
    N: AsRef<str>,
{
    // Determines whether a request of a given scheme, host and port should be proxied
    // according to `https_proxy` and `no_proxy`.

    // The no-proxy intercept requires ownership of its input data.
    let no_proxy: Option<Vec<String>> =
        no_proxy.map(|n| n.iter().map(|s| s.as_ref().to_owned()).collect());
    let intercept = move |scheme: Option<&str>, host: Option<&str>, _port| {
        if let Some(host) = host {
            if let Some(no_proxy) = &no_proxy {
                if scheme != Some("https") {
                    return false;
                }
                if no_proxy.iter().any(|s| s == "*") {
                    // Don't proxy anything
                    return false;
                }
                // If the host matches one of the no proxy list entries, return false (don't proxy)
                // Note that we're not doing anything fancy here for checking `no_proxy` since
                // we only expect requests here to be going out to some AWS API endpoint.
                return !no_proxy.iter().any(|no_proxy_host| {
                    !no_proxy_host.is_empty() && host.ends_with(no_proxy_host)
                });
            }
            true
        } else {
            false
        }
    };

    let https_proxy = https_proxy.as_ref();
    let mut proxy_uri = https_proxy.parse::<Uri>().context(UriParseSnafu {
        input: https_proxy.to_owned(),
    })?;
    // If the proxy's URI doesn't have a scheme, assume HTTP for the scheme and let the proxy
    // server forward HTTPS connections and start a tunnel.
    if proxy_uri.scheme().is_none() {
        proxy_uri = format!("http://{}", https_proxy)
            .parse::<Uri>()
            .context(UriParseSnafu {
                input: https_proxy.to_owned(),
            })?;
    }
    let mut proxy = Proxy::new(intercept, proxy_uri);
    // Parse https_proxy as URL to extract out auth information if any
    let proxy_url = Url::parse(https_proxy).context(UrlParseSnafu {
        input: https_proxy.to_owned(),
    })?;

    if !proxy_url.username().is_empty() || proxy_url.password().is_some() {
        proxy.set_authorization(Authorization::basic(
            proxy_url.username(),
            proxy_url.password().unwrap_or_default(),
        ));
    }

    let https_connector = make_tls(
        GaiResolver::new(),
        rustls::crypto::aws_lc_rs::default_provider(),
    );
    let proxy_connector =
        ProxyConnector::from_proxy(https_connector, proxy).context(ProxyConnectorSnafu)?;

    Ok(proxy_connector)
}

pub(crate) fn make_tls<R>(
    resolver: R,
    crypto_provider: CryptoProvider,
) -> hyper_rustls::HttpsConnector<HttpConnector<R>> {
    use hyper_rustls::ConfigBuilderExt;
    let mut base_connector = HttpConnector::new_with_resolver(resolver);
    base_connector.enforce_http(false);
    hyper_rustls::HttpsConnectorBuilder::new()
               .with_tls_config(
                rustls::ClientConfig::builder_with_provider(Arc::new(restrict_ciphers(crypto_provider)))
                    .with_safe_default_protocol_versions()
                    .expect("Error with the TLS configuration. Please file a bug report under https://github.com/smithy-lang/smithy-rs/issues.")
                    .with_native_roots().expect("error with TLS configuration.")
                    .with_no_client_auth()
            )
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(base_connector)
}

fn restrict_ciphers(base: CryptoProvider) -> CryptoProvider {
    let suites = &[
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        // TLS1.2 suites
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    let supported_suites = suites
        .iter()
        .flat_map(|suite| {
            base.cipher_suites
                .iter()
                .find(|s| &s.suite() == suite)
                .cloned()
        })
        .collect::<Vec<_>>();
    CryptoProvider {
        cipher_suites: supported_suites,
        ..base
    }
}
