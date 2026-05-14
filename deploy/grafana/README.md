# Grafana dashboards

Per `docs/13-observability.md` §"Dashboards (shipped)", v0.1 targets
six dashboards:

| Dashboard | Status | Metric prerequisites (instrumentation gap) |
|---|---|---|
| **Geonosis Overview** | shipped (`geonosis-overview.json`) | `geonosis_build_info`, `geonosis_http_requests_total`, `geonosis_http_responses_total`, `geonosis_audit_events_total`, `geonosis_process_start_time_seconds` — all already emitted |
| Authentication | gap | `geonosis_oidc_authorize_total{realm,outcome}`, `geonosis_oidc_login_failures_total{realm,reason}` — needs v0.1.x instrumentation |
| Token Lifecycle | gap | `geonosis_oidc_token_total{realm,grant_type,outcome}`, `geonosis_token_reuse_detected_total` — needs v0.1.x |
| Federation Health | gap | `geonosis_federation_ldap_*`, `geonosis_listener_lag_seconds` — needs v0.1.x |
| Cluster Health | gap | `geonosis_db_pool_in_use`, `geonosis_db_pool_size`, `geonosis_cache_*`, `geonosis_spi_*` — needs v0.1.x |
| Audit Volume | partial | `geonosis_audit_events_total` is emitted (single counter); per-action / per-realm labels are the v0.1.x split |

The shipped `geonosis-overview.json` works against today's metric
set with no instrumentation gap. The remaining five dashboards will
land as the corresponding metric counters get wired in v0.1.x — see
the `geonosis_*` namespace contract in `docs/13-observability.md`.

## Importing

```bash
# Provision via Grafana Operator
kubectl apply -f deploy/grafana/grafana-overview-dashboard.yaml

# Or via the Grafana UI
# Dashboards → Import → Upload geonosis-overview.json
```

## Prometheus scrape

The dashboards assume scrape labels do **not** add a `__name__`
rewrite and that the `instance` label is the pod IP — i.e. the
default `ServiceMonitor` shipped in `deploy/helm/geonosis/`.
