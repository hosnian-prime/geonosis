# 11 — Deployment on Kubernetes

Geonosis is designed to run as a stateless Deployment behind a
horizontal autoscaler, talking to a managed Postgres. This document
covers the recommended topology, the supplied Helm chart, networking,
and rollout discipline.

## Reference topology

```
              ┌──────────────────────────────────────────┐
              │  External LB / Ingress                   │
              │   geonosis.example.com  (TLS)            │
              └──────────────────────────────────────────┘
                                │
                       ┌────────┴────────┐
                       │ K8s Ingress     │
                       │ (gateway / nginx│
                       │  ingress-nginx) │
                       └────────┬────────┘
                                │
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
            ┌──────┐        ┌──────┐        ┌──────┐
            │ pod 1│        │ pod 2│        │ pod N│
            └──┬───┘        └──┬───┘        └──┬───┘
               │               │               │
               └──────────┬────┴───────────────┘
                          ▼
                  ┌────────────────────┐
                  │  Postgres primary  │
                  │  + read replicas   │  (managed RDS/Cloud SQL/etc.)
                  └────────────────────┘
                          │
                          ▼
                  ┌────────────────────┐
                  │ Object store       │
                  │ (S3/GCS) for WASM  │
                  │ module bytecode    │
                  └────────────────────┘
```

Optional:

- **External KMS** for signing keys (HashiCorp Vault transit, AWS KMS,
  GCP KMS) — see [`12-security-crypto.md`](./12-security-crypto.md).
- **OTel collector** sidecar or DaemonSet.

## Helm chart

`deploy/helm/geonosis/` provides:

- `Deployment` for the server
- `Service` (ClusterIP), `Ingress` (configurable)
- `ServiceAccount`, `Role`, `RoleBinding` (for leader-election
  via a Postgres advisory lock; minimal K8s RBAC otherwise)
- `ConfigMap` for non-secret config
- `Secret` references for DB URL, KMS credentials, master key
- `HorizontalPodAutoscaler` (CPU-based default; OTel custom metrics
  optional)
- `PodDisruptionBudget` (default `minAvailable: 1` for 2+ replicas)
- `NetworkPolicy` (deny-all + explicit allows)
- `PrometheusRule` and `ServiceMonitor` (if monitored by `kube-prometheus-stack`)

Values surface (excerpt):

```yaml
image:
  repository: ghcr.io/geonosis/geonosis-server
  tag: "0.1.0"

replicaCount: 3

database:
  url: ""                  # required, via existing secret
  poolMax: 32

cache:
  budgetMiB: 256

cluster:
  notifyChannel: geonosis_invalidate

spi:
  moduleStore: postgres    # or "s3"; if "s3", configure bucket below
  s3:
    bucket: ""
    region: ""

crypto:
  kms:
    kind: software         # or "vault" / "aws-kms" / "gcp-kms"
    endpoint: ""

ingress:
  enabled: true
  className: nginx
  hosts:
    - geonosis.example.com
  tls:
    - secretName: geonosis-tls
      hosts: [geonosis.example.com]

resources:
  requests: { cpu: 500m, memory: 512Mi }
  limits:   { cpu: 2,    memory: 2Gi }

probes:
  startup:    { path: /-/started,  initialDelaySeconds: 5,  failureThreshold: 30 }
  readiness:  { path: /-/ready,    periodSeconds: 5 }
  liveness:   { path: /-/healthy,  periodSeconds: 30 }
```

## Health probes

| Probe | Endpoint | Success criteria |
|---|---|---|
| Startup | `/-/started` | Process up, DB reachable once, migrations at or above required schema |
| Readiness | `/-/ready` | DB pool healthy, listener connected, SPI registry initialized, theme overlay loaded |
| Liveness | `/-/healthy` | Process responsive (no deadlock). Cheap, no DB round-trip |

`/-/ready` returning false during transient DB outages causes K8s
to steer traffic away from the affected pod. Liveness deliberately
does not depend on the DB — we don't want a flapping primary to
restart every pod.

## Rolling updates

Default Deployment strategy:

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 0
    maxSurge: 1
```

Combined with `PodDisruptionBudget(minAvailable: 1)` for ≥2-replica
clusters, this gives true zero-pod-down rolling deploys.

`preStop` hook of 15 s gives the ingress controller time to drain
the pod after readiness flips to false:

```yaml
lifecycle:
  preStop:
    exec:
      command: ["/bin/sh", "-c", "curl -fsS http://localhost:8080/-/drain && sleep 12"]
```

`/-/drain` is an internal endpoint that flips readiness to false
without affecting liveness; it does NOT reject incoming requests
already in flight.

## Resource sizing (defaults)

| Replica count target | RPS / pod | CPU / pod | Memory / pod |
|---|---|---|---|
| 2 | up to 200 | 250m | 256 MiB |
| 3 | up to 2 000 | 500m | 512 MiB |
| 5 | up to 8 000 | 1 vCPU | 1 GiB |
| 10 | up to 25 000 | 2 vCPU | 2 GiB |

Numbers indicative; real sizing depends on flow complexity, hot
SPI calls, JWT signing alg, etc. The bench harness in
`crates/geonosis-bench` produces the load profile we tune against.

## Postgres requirements

- Postgres **15 or newer** (uses `MERGE`, `gen_random_uuid`,
  `pg_walinspect` optional).
- `LISTEN`/`NOTIFY` enabled (default).
- `max_connections` sized for `replicas × poolMax + headroom +
  background workers`.
- Recommended extensions: none required; `pg_trgm` recommended for
  user search.
- Recommended `shared_buffers >= 1 GiB`, `work_mem >= 16 MiB`,
  `effective_cache_size = 75% of RAM`.

Read replicas are optional. The server uses the primary for all
writes and for reads on the critical authentication path; a future
release may add replica-aware read for admin lists.

## Networking

- Pod-to-Postgres: TLS required in production. SSL `verify-full`
  by default.
- Pod-to-S3 (if configured): TLS, signature v4. IRSA/Workload Identity
  if available.
- Pod-to-pod: not required. The cluster has no peer-to-peer protocol.
- Pod-to-Ingress: HTTP/1.1 or HTTP/2.
- `NetworkPolicy` template:

  - Ingress: from ingress controller only, port 8080 (HTTP) and 8443
    (HTTPS optional).
  - Egress: to Postgres CIDR, S3 endpoints, KMS endpoints, OTel
    collector. Nothing else.

## Secrets

- DB password, master encryption key, KMS credentials live in K8s
  Secrets (or external secret manager integrations: External Secrets
  Operator, Vault Agent).
- The chart ships **secret references** — it does NOT generate
  secrets at install time, to avoid surprises.
- Rotation: signing key rotation is a runtime operation (see
  [`12-security-crypto.md`](./12-security-crypto.md)). Master
  encryption key rotation is documented but requires a controlled
  rollout (operator runs `geoctl secrets rewrap`).

## Migrations on rollout

The chart includes a `Helm hook: pre-upgrade` Job that runs
`geoctl migrate` once before the Deployment rolls. This sequencing:

1. `helm upgrade` triggers `pre-upgrade` Job.
2. Job container pulls the new image, executes migrations under the
   Postgres advisory lock, exits zero.
3. Rolling update of the Deployment begins.

Failure path: a non-zero exit from the migration Job aborts the
upgrade. Existing pods continue serving the old version.

If an operator prefers manual control (separate migration step), the
Job can be disabled via values:

```yaml
migrations:
  preUpgradeJob: false
```

In that case the Deployment refuses to start until schema is at the
required version (see [`10-zero-downtime-migrations.md`](./10-zero-downtime-migrations.md)).

## Multi-zone

A standard production deploy is 3+ replicas spread across availability
zones via `topologySpreadConstraints`. Postgres should be HA across
zones (managed services handle this automatically).

## Operator (future)

A Geonosis K8s Operator (`crd: Realm`, `crd: Client`, `crd: WasmPlugin`)
is not v0.1 scope. The reference Helm chart is sufficient for first
adopters. A CRD-driven control plane is on the v0.3 roadmap.

## Single-binary deploy (non-K8s)

The same binary runs as a Linux systemd unit, in a container with
`docker run`, or with bare `./geonosis-server`. The only required
inputs are `DATABASE_URL` and a `GEONOSIS_MASTER_KEY` env var. The
operational story is the same; the chart is a convenience.

## Non-goals

- **Embedded Postgres** — Geonosis never bundles a database. Even
  the dev fixture uses a real Postgres container.
- **Cross-cluster federation** — out of scope.
- **In-cluster cert issuance.** Bring your cert-manager.

## Open

- **Default ingress class** — leave unset; let operators choose.
- **Service mesh hints** — verify behavior with Linkerd/Istio,
  document gotchas.
- **K8s Operator CRDs** — schema sketch needed for v0.3.
