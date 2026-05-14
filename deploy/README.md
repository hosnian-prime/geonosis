# Deployment artefacts

This directory ships everything an operator needs to run `geonosis-server`
in production. The layout mirrors `docs/11-deployment-k8s.md` §"Helm chart"
and `docs/13-observability.md` §"Dashboards (shipped)".

| Subdirectory | Purpose | Doc reference |
|---|---|---|
| `helm/geonosis/` | Reference Helm chart (Deployment, Service, PDB, HPA, NetworkPolicy, ServiceMonitor, PrometheusRule) | `docs/11-deployment-k8s.md` |
| `grafana/` | Grafana dashboards as JSON. Overview dashboard ships; remaining five are tracked in `grafana/README.md` against their metric instrumentation work in v0.1.x | `docs/13-observability.md` §"Dashboards (shipped)" |
| `prometheus-rules/` | Standalone Prometheus alert rules for installs without the Operator | `docs/13-observability.md` §"Alerting rules" |
| `compose/` | Local-dev `docker-compose.yml` for the quickstart (postgres + server). See `docs/recipes/01-quickstart-docker.md` | `docs/21-dx-package.md` §"5-minute quickstart" |

## Helm chart at a glance

```bash
# Render templates against custom values without installing
helm template my-release ./deploy/helm/geonosis \
  --values ./my-values.yaml

# Install
kubectl create namespace geonosis
kubectl -n geonosis create secret generic geonosis-database \
  --from-literal=url=postgres://geonosis:pw@db/geonosis
kubectl -n geonosis create secret generic geonosis-master-key \
  --from-literal=master-key=$(openssl rand -base64 32)
helm install -n geonosis geonosis ./deploy/helm/geonosis \
  --values ./my-values.yaml
```

The chart wires three probes (`/-/started`, `/-/ready`, `/-/healthy`)
plus the `preStop` drain hook (`POST /-/drain && sleep 12s`) so
zero-downtime rollouts are wired by default.

## Image

`Dockerfile` at the repository root builds a multi-stage image:

```bash
docker build -t ghcr.io/hosnian-prime/geonosis-server:0.1.0 .
```

The runtime layer is Debian slim with `ca-certificates`, `tzdata`,
and `curl` (only so the `preStop` hook can call `/-/drain` over
loopback). No shell access; the binary runs as a dedicated
non-root user (UID 65532).
