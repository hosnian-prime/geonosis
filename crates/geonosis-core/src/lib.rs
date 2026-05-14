//! geonosis-core: pure domain types for the Geonosis IAM platform.
//!
//! No I/O. No async. Every public type is `Send + Sync`. These types are
//! exchanged between every other crate in the workspace.

pub mod agent;
pub mod attribute;
pub mod client;
pub mod common;
pub mod credential;
pub mod error;
pub mod group;
pub mod id;
pub mod organization;
pub mod realm;
pub mod role;
pub mod scope;
pub mod secret;
pub mod session;
pub mod subject;
pub mod token;
pub mod user;
pub mod user_profile;

pub use agent::{Agent, AgentAuthMethod, AgentCapability, AgentKind, AgentRateLimit};
pub use attribute::{AttributeValue, RequiredAction};
pub use client::{
    AccessTokenType, Client, ClientAuthMethod, ClientKind, ConsentPolicy, FlowBinding, GrantPolicy,
    GrantType, PkceMode, RedirectUri, RedirectUriError,
};
pub use common::{Amr, AuthnLevel, JwsAlgorithm, SenderConstraint, SslRequirement};
pub use credential::{Credential, CredentialKind, CredentialRef};
pub use error::CoreError;
pub use group::Group;
pub use id::{
    AgentId, BrokerAuthnStateId, BrokerLinkId, ClientId, CodeId, ConsentGrantId, CredentialId,
    EventId, FederationId, FlowId, FlowStateId, GroupId, IdpId, KeyId, NodeId, OrgDomainId,
    OrgInvitationId, OrgRoleId, OrganizationId, RealmId, RefreshTokenId, RoleId, ScimTargetId,
    SessionId, SpiBindingId, TokenFamilyId, UserId, WasmModuleId,
};
pub use organization::{
    MembershipState, OrgConsentMode, OrgConsentPolicy, OrgDomain, OrgInvitation, OrgMembership,
    OrgPermission, OrgRole, Organization, OrganizationBranding, OrganizationPolicy,
};
pub use realm::{
    AcrLevel, AcrPolicy, AcrRequirement, BruteForcePolicy, EventConfig, LocalizationPolicy,
    LoginSettings, OtpPolicy, PasswordPolicy, PasswordPolicyReport, PasswordRule, Realm,
    RegistrationPolicy, SessionPolicy, ThemeBinding, TokenPolicy, WebauthnPolicy,
};
pub use role::{CompositeRoles, Role};
pub use scope::{Scope, ScopeName};
pub use secret::Secret;
pub use session::{ClientSessionRef, Session};
pub use subject::{ParentSubject, Subject};
pub use token::{
    AccessTokenClaims, CodeChallenge, CodeChallengeMethod, CodeGrant, IdTokenClaims, OrgClaim,
    RealmAccess, RefreshToken, ResourceAccess,
};
pub use user::{FederationLink, PersonName, User};
pub use user_profile::{
    AttributeActorSet, AttributePermissions, AttributeValidator, UnmanagedAttributePolicy,
    UserAttributeDecl, UserAttributeGroup, UserProfile,
};
