use std::collections::BTreeMap;
use std::iter::once;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use http::header;
use http::uri::Authority;
use http::uri::PathAndQuery;
use rustls::crypto::aws_lc_rs::sign::any_supported_type;

use pingora::Error;
use pingora::ErrorType;
use pingora::Result;
use pingora::http::ResponseHeader;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::HttpPeer;
use pingora::proxy::ProxyHttp;
use pingora::proxy::Session;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use pingora::tls::cert_resolvers::CertifiedKey;
use pingora::tls::cert_resolvers::ResolvesServerCertUsingSni;
use pingora::tls::load_certs_and_key_files;

type Peer = Box<HttpPeer>;

pub struct Reversi {
    hosts: &'static [Host],
}

pub struct Host {
    pub domain: &'static str,
    pub redirects: &'static [&'static str],
    pub upstream: &'static str,
}

struct Mapper {
    redirects: BTreeMap<&'static str, &'static str>,
    upstreams: BTreeMap<&'static str, Peer>,
}

enum Target {
    Invalid,
    Redirect(String),
    Upstream(Peer),
}

impl Host {
    fn certificate_path(domain: &str, file: &str) -> String {
        let dir = PathBuf::from(format!("/certs/live/{domain}"));
        let path = dir.join(file).canonicalize().unwrap();
        path.to_str().unwrap().into()
    }

    fn domains(&self) -> impl Iterator<Item = &'static str> {
        once(self.domain).chain(self.redirects.iter().copied())
    }
}

impl<'a> FromIterator<&'a Host> for TlsSettings {
    fn from_iter<T: IntoIterator<Item = &'a Host>>(iter: T) -> Self {
        let mut certs = ResolvesServerCertUsingSni::new();

        for domain in iter.into_iter().flat_map(Host::domains) {
            let cert = Host::certificate_path(domain, "fullchain.pem");
            let key = Host::certificate_path(domain, "privkey.pem");
            let (cert, key) = load_certs_and_key_files(&cert, &key).unwrap().unwrap();
            let key = any_supported_type(&key).unwrap();
            let ck = CertifiedKey::new(cert, key);

            certs.add(domain, ck).unwrap();
        }

        TlsSettings::resolver(Arc::new(certs)).unwrap()
    }
}

impl<'a> FromIterator<&'a Host> for Mapper {
    fn from_iter<T: IntoIterator<Item = &'a Host>>(iter: T) -> Self {
        let mut redirects = BTreeMap::new();
        let mut upstreams = BTreeMap::new();

        for spec in iter {
            let domain = spec.domain;
            let peer = HttpPeer::new(spec.upstream, false, domain.into());
            upstreams.insert(domain, Box::new(peer));

            for redirect in spec.redirects {
                redirects.insert(*redirect, domain);
            }
        }

        Self {
            redirects,
            upstreams,
        }
    }
}

impl Mapper {
    fn resolve(&self, session: &mut Session) -> Target {
        let lookup = session
            .get_header(header::HOST)
            .and_then(|header| header.to_str().ok())
            .or(session.req_header().uri.host())
            .and_then(|host| Authority::from_str(host).ok());

        let Some(authority) = lookup else {
            return Target::Invalid;
        };

        if let Some(peer) = self.upstreams.get(authority.host()) {
            return Target::Upstream(peer.clone());
        }

        if let Some(target) = self.redirects.get(authority.host()) {
            let path = session.req_header().uri.path_and_query();
            let path = path.map_or("/", PathAndQuery::as_str);
            return Target::Redirect(format!("https://{target}{path}"));
        }

        Target::Invalid
    }
}

#[async_trait]
impl ProxyHttp for Mapper {
    type CTX = Option<Target>;

    fn new_ctx(&self) -> Self::CTX {
        None
    }

    async fn request_filter(&self, session: &mut Session, context: &mut Self::CTX) -> Result<bool> {
        use http::StatusCode as Code;

        let mut headers = Box::new(match context.get_or_insert(self.resolve(session)) {
            Target::Invalid => ResponseHeader::build(Code::SERVICE_UNAVAILABLE, Some(0))?,
            Target::Upstream(_) => return Ok(false),
            Target::Redirect(target) => {
                let mut response = ResponseHeader::build(Code::SEE_OTHER, Some(0))?;
                response.insert_header(header::LOCATION, target.as_str())?;
                response
            }
        });

        headers.insert_header(header::CONTENT_LENGTH, "0")?;
        session.write_response_header(headers, true).await?;
        session.write_response_body(None, true).await?;

        Ok(true)
    }

    async fn upstream_peer(&self, session: &mut Session, context: &mut Self::CTX) -> Result<Peer> {
        match context.take().unwrap_or(self.resolve(session)) {
            Target::Upstream(peer) => Ok(peer),
            _ => Err(Error::new(ErrorType::InternalError)),
        }
    }
}

impl From<&'static [Host]> for Reversi {
    fn from(value: &'static [Host]) -> Self {
        Self { hosts: value }
    }
}

impl Reversi {
    #[allow(clippy::missing_panics_doc)]
    pub fn run(self) -> ! {
        let mapper = Mapper::from_iter(self.hosts);
        let tls = TlsSettings::from_iter(self.hosts);
        let mut server = Server::new(None).unwrap();
        let mut service = http_proxy_service(&server.configuration, mapper);

        service.add_tcp("[::]:8080"); // TODO: Redirect only.
        service.add_tls_with_settings("[::]:8443", None, tls);

        server.bootstrap();
        server.add_service(service);
        server.run_forever();
    }
}
