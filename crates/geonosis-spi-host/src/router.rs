//! Dispatch-mode router.
//!
//! Per `docs/07-spi-wasm.md` §"Dispatch modes": each WIT interface has
//! a canonical dispatch shape. The router functions in this module
//! consume the priority-sorted, replacement-aware `ProviderBinding`
//! slice from `ProviderRegistry::list` and apply the right shape.
//!
//! Per-mode functions instead of one big generic — the return type
//! differs (Option<T> for FirstMatch vs Vec<T> for NamedAttach), and
//! a single signature would force an unwieldy enum-of-results that
//! callers immediately match on. v0.1 picks clarity.
//!
//! Caller contract:
//! - Pass `bindings` already filtered to enabled + non-replaced (use
//!   `ProviderRegistry::list_active`).
//! - `call` is an async closure that runs ONE provider and returns its
//!   typed result. Failures are the closure's `Err`; the router
//!   short-circuits on the first one for `FirstMatch` / `FirstDecision`
//!   and logs + continues for `FireForget` / `Chain` / `NamedAttach`.

use std::future::Future;

use thiserror::Error;

use crate::registry::{LookupOutcome, ProviderBinding};

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("no provider registered for interface")]
    NoProvider,
    #[error("named provider not found: {0}")]
    NamedNotFound(String),
    #[error("provider failed: {0}")]
    ProviderFailed(String),
}

/// **FirstMatch** — iterate providers in priority order, call each
/// until one returns `Found`. Returns `Ok(None)` when every provider
/// returns `NotFound`; errors stop the iteration immediately.
///
/// Used by `geonosis:user-storage@0.1.0`: the first storage that
/// recognizes the username wins, federation falls through to local.
pub async fn first_match<T, F, Fut>(
    bindings: &[ProviderBinding],
    mut call: F,
) -> Result<Option<T>, DispatchError>
where
    F: FnMut(&ProviderBinding) -> Fut,
    Fut: Future<Output = Result<LookupOutcome<T>, DispatchError>>,
{
    for b in bindings {
        match call(b).await? {
            LookupOutcome::Found(v) => return Ok(Some(v)),
            LookupOutcome::NotFound => continue,
        }
    }
    Ok(None)
}

/// **NamedSelect** — caller passes the URN; the named provider runs
/// exactly once. Returns `NamedNotFound` when the URN isn't bound.
///
/// Used by `geonosis:authn@0.1.0`, `geonosis:broker-adapter@0.1.0`,
/// `geonosis:ui-component@0.1.0`: flow / IdP / theme config names the
/// provider directly.
pub async fn named_select<T, F, Fut>(
    bindings: &[ProviderBinding],
    urn: &str,
    call: F,
) -> Result<T, DispatchError>
where
    F: FnOnce(&ProviderBinding) -> Fut,
    Fut: Future<Output = Result<T, DispatchError>>,
{
    let binding = bindings
        .iter()
        .find(|b| b.provider_urn == urn)
        .ok_or_else(|| DispatchError::NamedNotFound(urn.to_string()))?;
    call(binding).await
}

/// **Chain** — all providers run in priority order; each receives the
/// previous provider's output. Used by `geonosis:mapper@0.1.0` to fold
/// claim transformations left-to-right.
pub async fn chain<T, F, Fut>(
    bindings: &[ProviderBinding],
    initial: T,
    mut call: F,
) -> Result<T, DispatchError>
where
    F: FnMut(&ProviderBinding, T) -> Fut,
    Fut: Future<Output = Result<T, DispatchError>>,
{
    let mut acc = initial;
    for b in bindings {
        acc = call(b, acc).await?;
    }
    Ok(acc)
}

/// **NamedAttach** — every provider runs against its own slot (e.g.
/// per-attribute validator). All results returned; callers usually
/// associate each with `binding.provider_urn` or `binding.config`.
///
/// Used by `geonosis:user-profile-validator@0.1.0`.
pub async fn named_attach<T, F, Fut>(
    bindings: &[ProviderBinding],
    mut call: F,
) -> Result<Vec<(String, T)>, DispatchError>
where
    F: FnMut(&ProviderBinding) -> Fut,
    Fut: Future<Output = Result<T, DispatchError>>,
{
    let mut out = Vec::with_capacity(bindings.len());
    for b in bindings {
        let v = call(b).await?;
        out.push((b.provider_urn.clone(), v));
    }
    Ok(out)
}

/// **FireForget** — every provider runs; failures logged, not
/// propagated. Used by `geonosis:event@0.1.0` so a misbehaving event
/// listener can't break the producing request.
pub async fn fire_forget<F, Fut>(bindings: &[ProviderBinding], mut call: F)
where
    F: FnMut(&ProviderBinding) -> Fut,
    Fut: Future<Output = Result<(), DispatchError>>,
{
    for b in bindings {
        if let Err(e) = call(b).await {
            tracing::warn!(
                provider_urn = %b.provider_urn,
                error = %e,
                "fire-forget provider failed; continuing",
            );
        }
    }
}

/// Decision variant returned by `FirstDecision` providers — matches
/// the `geonosis:policy@0.1.0` WIT contract (Permit / Deny / Skip).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Permit,
    Deny,
    Skip,
}

/// **FirstDecision** — providers run in priority order; the first
/// non-`Skip` decision wins. Used by `geonosis:policy@0.1.0`.
///
/// When every provider returns `Skip`, the router returns `None` so
/// the caller can fall back to a default rule (per doc 07 §Policy:
/// "no decision = permit", but the default lives in the caller, not
/// the dispatch layer).
pub async fn first_decision<F, Fut>(
    bindings: &[ProviderBinding],
    mut call: F,
) -> Result<Option<Decision>, DispatchError>
where
    F: FnMut(&ProviderBinding) -> Fut,
    Fut: Future<Output = Result<Decision, DispatchError>>,
{
    for b in bindings {
        match call(b).await? {
            Decision::Skip => continue,
            d => return Ok(Some(d)),
        }
    }
    Ok(None)
}

/// Filter a binding slice down to those that are enabled AND not
/// replaced by a higher-priority sibling. Mirrors the logic in
/// `ProviderRegistry::first_enabled` so the router doesn't need a
/// live registry — callers can preload the slice once per request.
pub fn active_bindings(bindings: &[ProviderBinding]) -> Vec<ProviderBinding> {
    let replaced: std::collections::HashSet<String> =
        bindings.iter().filter_map(|b| b.replaces.clone()).collect();
    bindings
        .iter()
        .filter(|b| b.enabled && !replaced.contains(&b.provider_urn))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::WitInterfaceName;
    use crate::registry::{ProviderCapabilities, ProviderOrigin};
    use geonosis_core::id::{RealmId, SpiBindingId};

    fn binding(urn: &str, priority: i32, replaces: Option<&str>, enabled: bool) -> ProviderBinding {
        ProviderBinding {
            id: SpiBindingId::new(),
            realm_id: RealmId::new(),
            interface: WitInterfaceName(WitInterfaceName::AUTHN.into()),
            provider_urn: urn.into(),
            priority,
            enabled,
            config: serde_json::json!({}),
            replaces: replaces.map(str::to_string),
            capabilities: ProviderCapabilities::default(),
            origin: ProviderOrigin::Builtin,
        }
    }

    #[tokio::test]
    async fn first_match_short_circuits() {
        let bs = vec![binding("a", 200, None, true), binding("b", 100, None, true)];
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result: Option<&str> = first_match(&bs, |b| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let urn = b.provider_urn.clone();
            async move {
                if urn == "a" {
                    Ok::<_, DispatchError>(LookupOutcome::Found("hit-a"))
                } else {
                    Ok(LookupOutcome::NotFound)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result, Some("hit-a"));
        // Only one call — the first match short-circuited.
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn first_match_all_not_found_returns_none() {
        let bs = vec![binding("a", 100, None, true)];
        let result: Option<&str> = first_match(&bs, |_b| async move {
            Ok::<_, DispatchError>(LookupOutcome::NotFound)
        })
        .await
        .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn named_select_hits_exact() {
        let bs = vec![binding("a", 100, None, true), binding("b", 100, None, true)];
        let result = named_select(&bs, "b", |b| {
            let urn = b.provider_urn.clone();
            async move { Ok::<_, DispatchError>(urn) }
        })
        .await
        .unwrap();
        assert_eq!(result, "b");
    }

    #[tokio::test]
    async fn named_select_missing_returns_error() {
        let bs = vec![binding("a", 100, None, true)];
        let err = named_select(&bs, "z", |_b| async move { Ok::<_, DispatchError>(()) })
            .await
            .unwrap_err();
        assert!(matches!(err, DispatchError::NamedNotFound(_)));
    }

    #[tokio::test]
    async fn chain_folds_in_priority_order() {
        // Higher-priority bindings come first in the slice (matches
        // ProviderRegistry::list output).
        let bs = vec![
            binding("plus1", 200, None, true),
            binding("times2", 100, None, true),
        ];
        let result = chain(&bs, 0_i32, |b, acc| {
            let urn = b.provider_urn.clone();
            async move {
                match urn.as_str() {
                    "plus1" => Ok::<_, DispatchError>(acc + 1),
                    "times2" => Ok(acc * 2),
                    _ => Ok(acc),
                }
            }
        })
        .await
        .unwrap();
        // (0 + 1) * 2 = 2
        assert_eq!(result, 2);
    }

    #[tokio::test]
    async fn named_attach_collects_every_provider() {
        let bs = vec![
            binding("v1", 200, None, true),
            binding("v2", 100, None, true),
        ];
        let result = named_attach(&bs, |b| {
            let len = b.provider_urn.len();
            async move { Ok::<_, DispatchError>(len) }
        })
        .await
        .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "v1");
        assert_eq!(result[1].0, "v2");
    }

    #[tokio::test]
    async fn fire_forget_swallows_failures() {
        let bs = vec![binding("a", 100, None, true), binding("b", 100, None, true)];
        let calls = std::sync::atomic::AtomicUsize::new(0);
        fire_forget(&bs, |_b| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { Err::<(), _>(DispatchError::ProviderFailed("oops".into())) }
        })
        .await;
        // Both providers ran despite failures.
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn first_decision_returns_first_non_skip() {
        let bs = vec![
            binding("a", 300, None, true),
            binding("b", 200, None, true),
            binding("c", 100, None, true),
        ];
        let result = first_decision(&bs, |b| {
            let urn = b.provider_urn.clone();
            async move {
                match urn.as_str() {
                    "a" => Ok::<_, DispatchError>(Decision::Skip),
                    "b" => Ok(Decision::Permit),
                    _ => Ok(Decision::Deny),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result, Some(Decision::Permit));
    }

    #[tokio::test]
    async fn first_decision_all_skip_yields_none() {
        let bs = vec![binding("a", 100, None, true)];
        let result = first_decision(
            &bs,
            |_b| async move { Ok::<_, DispatchError>(Decision::Skip) },
        )
        .await
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn active_bindings_filters_replaced_and_disabled() {
        let bs = vec![
            binding("builtin:authn:password", 100, None, true),
            binding(
                "wasm:authn:custom",
                200,
                Some("builtin:authn:password"),
                true,
            ),
            binding("dead", 50, None, false),
        ];
        let active = active_bindings(&bs);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].provider_urn, "wasm:authn:custom");
    }
}
