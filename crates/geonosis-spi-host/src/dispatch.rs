//! Dispatch mode per WIT interface.

use serde::{Deserialize, Serialize};

/// Stable WIT interface name (versioned). v0.1 interfaces are at `0.1.0`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WitInterfaceName(pub String);

impl WitInterfaceName {
    pub const AUTHN: &'static str = "geonosis:authn@0.1.0";
    pub const MAPPER: &'static str = "geonosis:mapper@0.1.0";
    pub const EVENT: &'static str = "geonosis:event@0.1.0";
    pub const POLICY: &'static str = "geonosis:policy@0.1.0";
    pub const USER_STORAGE: &'static str = "geonosis:user-storage@0.1.0";
    pub const BROKER_ADAPTER: &'static str = "geonosis:broker-adapter@0.1.0";
    pub const USER_PROFILE_VALIDATOR: &'static str = "geonosis:user-profile-validator@0.1.0";
    pub const UI_COMPONENT: &'static str = "geonosis:ui-component@0.1.0";
    pub const HOST: &'static str = "geonosis:host@0.1.0";

    pub fn dispatch_mode(&self) -> DispatchMode {
        match self.0.as_str() {
            Self::USER_STORAGE => DispatchMode::FirstMatch,
            Self::AUTHN => DispatchMode::NamedSelect,
            Self::MAPPER => DispatchMode::Chain,
            Self::EVENT => DispatchMode::FireForget,
            Self::POLICY => DispatchMode::FirstDecision,
            Self::BROKER_ADAPTER => DispatchMode::NamedSelect,
            Self::USER_PROFILE_VALIDATOR => DispatchMode::NamedAttach,
            Self::UI_COMPONENT => DispatchMode::NamedSelect,
            Self::HOST => DispatchMode::NamedSelect,
            _ => DispatchMode::NamedSelect,
        }
    }
}

/// How the host calls a list of providers for an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DispatchMode {
    /// First provider whose lookup returns `Found` wins.
    FirstMatch,
    /// Caller names the provider by URN; one provider runs.
    NamedSelect,
    /// All providers run; results compose left-to-right.
    Chain,
    /// All providers run; results discarded; failures logged.
    FireForget,
    /// First provider with a non-Indeterminate decision wins.
    FirstDecision,
    /// Each provider attaches to a specific attribute / slot.
    NamedAttach,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mappers_chain_user_storage_first_matches() {
        assert_eq!(
            WitInterfaceName(WitInterfaceName::MAPPER.into()).dispatch_mode(),
            DispatchMode::Chain
        );
        assert_eq!(
            WitInterfaceName(WitInterfaceName::USER_STORAGE.into()).dispatch_mode(),
            DispatchMode::FirstMatch
        );
        assert_eq!(
            WitInterfaceName(WitInterfaceName::EVENT.into()).dispatch_mode(),
            DispatchMode::FireForget
        );
    }
}
