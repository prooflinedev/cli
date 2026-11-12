//! A deployment review's public address. The review API reads a deployment
//! review by its `public_key`: `rev_` followed by the review's identifier
//! without hyphens. The key is parsed before any request, and the review the
//! server returns is held to it, so a command never reports another review
//! as the deployment the caller named.

use std::fmt;
use std::str::FromStr;

use uuid::Uuid;

use crate::model::ReviewDetail;

const PREFIX: &str = "rev_";
/// A review identifier without its hyphens.
const DIGITS: usize = 32;
/// The `kind` of a deployment review.
pub const KIND: &str = "DEPLOYMENT";

/// The stable public address of one review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(Uuid);

impl PublicKey {
    /// The review this key addresses.
    pub const fn review_id(self) -> Uuid {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("a deployment review key is `rev_` followed by 32 lowercase hexadecimal digits")]
pub struct InvalidPublicKey;

impl FromStr for PublicKey {
    type Err = InvalidPublicKey;

    /// Only the canonical form: the key becomes a path segment, and a second
    /// spelling of one review would not be the address the server published.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let digits = raw.strip_prefix(PREFIX).ok_or(InvalidPublicKey)?;
        if digits.len() != DIGITS
            || !digits
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(InvalidPublicKey);
        }
        Uuid::try_parse(digits)
            .map(Self)
            .map_err(|_| InvalidPublicKey)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}", self.0.simple())
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeploymentError {
    #[error("requested deployment review {requested}, but the server returned review {returned}")]
    WrongReview {
        requested: PublicKey,
        returned: Uuid,
    },
    #[error("review {review} has kind {kind}, not DEPLOYMENT; read it with `findings --review`")]
    NotADeployment { review: Uuid, kind: String },
}

/// Holds the returned review to the key that asked for it.
pub fn validate(detail: &ReviewDetail, requested: PublicKey) -> Result<(), DeploymentError> {
    if detail.id != requested.review_id() {
        return Err(DeploymentError::WrongReview {
            requested,
            returned: detail.id,
        });
    }
    if detail.kind != KIND {
        return Err(DeploymentError::NotADeployment {
            review: detail.id,
            kind: crate::text::one_line(&detail.kind),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REVIEW: &str = "0190f3a0-0000-7000-8000-0000000000d1";
    const KEY: &str = "rev_0190f3a00000700080000000000000d1";

    fn key() -> String {
        KEY.to_owned()
    }

    fn detail(id: &str, kind: &str) -> ReviewDetail {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "kind": kind,
            "status": "COMPLETED",
            "assessment_count": 0,
            "assessments": [],
        }))
        .unwrap()
    }

    #[test]
    fn a_key_names_its_review_and_prints_as_it_was_written() {
        let parsed: PublicKey = key().parse().unwrap();
        assert_eq!(parsed.review_id(), Uuid::parse_str(REVIEW).unwrap());
        assert_eq!(parsed.to_string(), key());
    }

    #[test]
    fn only_the_canonical_spelling_is_a_key() {
        for refused in [
            "",
            REVIEW,
            // No prefix, another prefix, or the hyphenated identifier.
            "0190f3a00000700080000000000000d1",
            "REV_0190f3a00000700080000000000000d1",
            "rev_0190f3a0-0000-7000-8000-0000000000d1",
            // Uppercase digits, one digit short and one digit long.
            "rev_0190F3A00000700080000000000000D1",
            "rev_0190f3a00000700080000000000000d",
            "rev_0190f3a00000700080000000000000d10",
            // Thirty-two characters that are not all digits.
            "rev_0190f3a0000070008000000/../../x1",
            " rev_0190f3a00000700080000000000000d1",
        ] {
            assert_eq!(
                refused.parse::<PublicKey>(),
                Err(InvalidPublicKey),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn a_returned_review_must_be_the_deployment_that_was_named() {
        let requested: PublicKey = key().parse().unwrap();
        assert_eq!(validate(&detail(REVIEW, KIND), requested), Ok(()));
        let other = "0190f3a0-0000-7000-8000-0000000000d2";
        assert_eq!(
            validate(&detail(other, KIND), requested),
            Err(DeploymentError::WrongReview {
                requested,
                returned: Uuid::parse_str(other).unwrap(),
            })
        );
        // Untrusted server text is contained before it reaches the terminal.
        let refused = validate(&detail(REVIEW, "PULL_\u{1b}[31mREQUEST"), requested).unwrap_err();
        assert!(matches!(refused, DeploymentError::NotADeployment { .. }));
        assert!(!refused.to_string().contains('\u{1b}'));
    }
}
