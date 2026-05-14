//! Stable URNs for each built-in + the helper that seeds them into the
//! shared `ProviderRegistry` exposed by `geonosis-spi-host`. The actual
//! `ProviderBinding` rows are realm-scoped, so this helper takes a realm
//! id and emits one binding per built-in.

pub struct BuiltinUrn;

impl BuiltinUrn {
    pub const PASSWORD: &'static str = "builtin:authn:password";
    pub const OTP: &'static str = "builtin:authn:otp";
    pub const RECOVERY_CODE: &'static str = "builtin:authn:recovery-code";
    pub const WEBAUTHN: &'static str = "builtin:authn:webauthn";
    pub const MAGIC_LINK: &'static str = "builtin:authn:magic-link";
    pub const PHONE_OTP: &'static str = "builtin:authn:phone-otp";
    pub const CONSENT: &'static str = "builtin:authn:consent";
    pub const COOKIE: &'static str = "builtin:authn:cookie";
    pub const IDP_REDIRECT: &'static str = "builtin:authn:idp-redirect";
    pub const REQUIRE_ACTION: &'static str = "builtin:authn:require-action";
    pub const RISK_SCORE: &'static str = "builtin:authn:risk-score";

    pub const ALL: &'static [&'static str] = &[
        Self::PASSWORD,
        Self::OTP,
        Self::RECOVERY_CODE,
        Self::WEBAUTHN,
        Self::MAGIC_LINK,
        Self::PHONE_OTP,
        Self::CONSENT,
        Self::COOKIE,
        Self::IDP_REDIRECT,
        Self::REQUIRE_ACTION,
        Self::RISK_SCORE,
    ];
}

/// Register every v0.1 built-in authenticator URN into the shared SPI
/// registry. The actual runtime instance (e.g. `PasswordAuthenticator`)
/// stays out of the registry — dispatch lookups happen by URN and the
/// runtime is held by the flow executor.
pub fn register_builtins(
    registry: &geonosis_spi_host::ProviderRegistry,
    realm: geonosis_core::RealmId,
) {
    use geonosis_spi_host::{
        dispatch::WitInterfaceName,
        registry::{ProviderBinding, ProviderCapabilities, ProviderOrigin},
    };
    use serde_json::json;

    let interface = WitInterfaceName(WitInterfaceName::AUTHN.into());
    for urn in BuiltinUrn::ALL {
        registry.register(ProviderBinding {
            id: geonosis_core::SpiBindingId::new(),
            realm_id: realm,
            interface: interface.clone(),
            provider_urn: (*urn).to_string(),
            // All built-ins ship at priority 0; higher-priority plugins
            // can override them by re-registering and setting `replaces`.
            priority: 0,
            enabled: true,
            config: json!({}),
            replaces: None,
            capabilities: ProviderCapabilities::default(),
            origin: ProviderOrigin::Builtin,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use geonosis_spi_host::{dispatch::WitInterfaceName, ProviderRegistry};

    #[test]
    fn all_eleven_builtins_listed() {
        assert_eq!(BuiltinUrn::ALL.len(), 11);
    }

    #[test]
    fn urns_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for urn in BuiltinUrn::ALL {
            assert!(seen.insert(*urn), "duplicate URN: {urn}");
        }
    }

    #[test]
    fn register_seeds_every_builtin() {
        let r = ProviderRegistry::new();
        let realm = geonosis_core::RealmId::new();
        register_builtins(&r, realm);
        let listed = r.list(realm, &WitInterfaceName(WitInterfaceName::AUTHN.into()));
        assert_eq!(listed.len(), BuiltinUrn::ALL.len());
        for urn in BuiltinUrn::ALL {
            assert!(
                listed.iter().any(|b| b.provider_urn == *urn),
                "missing {urn}"
            );
        }
    }
}
