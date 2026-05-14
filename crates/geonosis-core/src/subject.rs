//! Authenticated subject — the LSP-pivot type.
//!
//! The four variants are interchangeable to the token-mint code path; the
//! flow executor decides which one to emit on `Done(...)`.

use serde::{Deserialize, Serialize};

use crate::id::{AgentId, ClientId, UserId};
use crate::scope::ScopeName;

/// Result of a successful authentication flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Subject {
    /// A local user (resolved via storage).
    Local { user_id: UserId },
    /// A brokered external identity. `candidate_user` is `Some` once the
    /// first-broker-login step links to a local row.
    External {
        idp_alias: String,
        external_id: String,
        candidate_user: Option<UserId>,
    },
    /// A confidential client acting as itself (client_credentials grant).
    ServiceAccount { client_id: ClientId },
    /// An Agent (M2M / AI) delegated by a parent subject.
    Agent {
        agent_id: AgentId,
        parent: Box<Subject>,
        scopes: Vec<ScopeName>,
    },
}

/// Immutable owning identity for an Agent.
///
/// Stored on `Agent` at creation; cannot be changed (reparenting = revoke +
/// recreate per `docs/18-agent-identity.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ParentSubject {
    User {
        user_id: UserId,
    },
    ServiceAccount {
        client_id: ClientId,
    },
    Organization {
        organization_id: crate::id::OrganizationId,
    },
}

impl Subject {
    /// Returns the subject identifier suitable for emission in `sub` (token
    /// claim). Per OIDC, the subject is a stable per-issuer string.
    pub fn token_sub(&self) -> String {
        match self {
            Self::Local { user_id } => user_id.to_string(),
            Self::External { external_id, .. } => external_id.clone(),
            Self::ServiceAccount { client_id } => format!("service-account:{client_id}"),
            Self::Agent { agent_id, .. } => format!("agent:{agent_id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_sub_prefixed() {
        let s = Subject::Agent {
            agent_id: AgentId::new(),
            parent: Box::new(Subject::Local {
                user_id: UserId::new(),
            }),
            scopes: vec![],
        };
        assert!(s.token_sub().starts_with("agent:"));
    }

    #[test]
    fn service_account_sub_prefixed() {
        let s = Subject::ServiceAccount {
            client_id: ClientId::new(),
        };
        assert!(s.token_sub().starts_with("service-account:"));
    }
}
