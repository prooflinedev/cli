//! The Proofline console origin the CLI talks to.

use std::fmt;
use std::net::IpAddr;

use url::{Host, Url};

/// The production console.
pub const DEFAULT_ORIGIN: &str = "https://proofline.sh";

/// An HTTPS origin, or a loopback HTTP origin for local testing. A bearer token
/// is never sent to a plain-HTTP host on the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin(Url);

#[derive(Debug, thiserror::Error)]
pub enum OriginError {
    #[error("the Proofline URL {0:?} is not an absolute URL")]
    Unparseable(String),
    #[error("the Proofline URL must use HTTPS; plain HTTP is accepted only for localhost")]
    Insecure,
    #[error("the Proofline URL must be an origin, without credentials, path, query or fragment")]
    NotOrigin,
}

impl Origin {
    pub fn parse(raw: &str) -> Result<Self, OriginError> {
        let url = Url::parse(raw).map_err(|_| OriginError::Unparseable(raw.to_owned()))?;
        let loopback = match url.host() {
            Some(Host::Domain(domain)) => domain == "localhost",
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
            None => return Err(OriginError::Unparseable(raw.to_owned())),
        };
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            _ => return Err(OriginError::Insecure),
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(OriginError::NotOrigin);
        }
        Ok(Self(url))
    }

    /// The URL for `segments` below the origin, each percent-encoded as one
    /// path segment, so a repository name such as `owner/name` stays one segment.
    pub fn join<'a>(&self, segments: impl IntoIterator<Item = &'a str>) -> Url {
        let mut url = self.0.clone();
        if let Ok(mut path) = url.path_segments_mut() {
            path.clear().extend(segments);
        }
        url
    }

    /// The key a stored credential is filed under.
    pub fn as_key(&self) -> String {
        self.0.origin().ascii_serialization()
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_and_loopback_http() {
        assert_eq!(
            Origin::parse("https://proofline.sh").unwrap().to_string(),
            "https://proofline.sh"
        );
        assert!(Origin::parse("http://127.0.0.1:8080").is_ok());
        assert!(Origin::parse("http://localhost:3000/").is_ok());
        assert!(Origin::parse("http://[::1]:3000").is_ok());
    }

    #[test]
    fn refuses_plain_http_paths_and_credentials() {
        assert!(matches!(
            Origin::parse("http://proofline.sh"),
            Err(OriginError::Insecure)
        ));
        assert!(matches!(
            Origin::parse("http://10.0.0.1"),
            Err(OriginError::Insecure)
        ));
        assert!(matches!(
            Origin::parse("https://proofline.sh/api"),
            Err(OriginError::NotOrigin)
        ));
        assert!(matches!(
            Origin::parse("https://u:p@proofline.sh"),
            Err(OriginError::NotOrigin)
        ));
        assert!(matches!(
            Origin::parse("proofline.sh"),
            Err(OriginError::Unparseable(_))
        ));
    }

    #[test]
    fn join_encodes_each_segment() {
        let origin = Origin::parse("https://proofline.sh").unwrap();
        assert_eq!(
            origin
                .join(["api", "reviews", "pr", "acme/web", "7"])
                .as_str(),
            "https://proofline.sh/api/reviews/pr/acme%2Fweb/7"
        );
    }
}
