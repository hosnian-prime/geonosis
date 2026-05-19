# Connection Pool & Load Tuning

## Postgres Pool (sqlx)

Default settings (`geonosis-storage/src/postgres.rs`):

| Parameter | Default | Recommended (4 vCPU) |
|---|---|---|
| `max_connections` | 32 | 50-80 (rule: `2 * vCPUs + disk_spindles`) |
| `min_connections` | 4 | 8 |
| `idle_timeout` | 300s | 120s |
| `max_lifetime` | 1800s | 1800s |
| `acquire_timeout` | 10s | 5s |

Override via environment:
```
GEONOSIS_DB_MAX_CONNECTIONS=64
GEONOSIS_DB_MIN_CONNECTIONS=8
GEONOSIS_DB_IDLE_TIMEOUT=120
```

## Postgres Server Tuning

For the load test target (5000 req/s, 4 vCPU):
```
max_connections = 200
shared_buffers = 1GB
effective_cache_size = 3GB
work_mem = 4MB
maintenance_work_mem = 256MB
```

## Running the Load Test

```bash
# 1. Start Geonosis with Postgres
docker compose -f deploy/compose/quickstart.yml up -d

# 2. Seed the load test realm
tests/load/seed-load-realm.sh http://localhost:8080

# 3. Run k6
k6 run tests/load/authorize-token.js --env BASE_URL=http://localhost:8080

# 4. Check results
cat tests/load/report.json | jq .
```

## Flame Graph Profiling

```bash
# Install cargo-flamegraph
cargo install flamegraph

# Profile under load (run k6 in a separate terminal)
cargo flamegraph --bin geonosis-server -- \
  --public-url http://localhost:8080 \
  --bind 0.0.0.0:8080 \
  --database-url postgres://geonosis:geonosis@localhost/geonosis

# Open flamegraph.svg in browser
```

## Target Metrics

| Metric | Target | Measure |
|---|---|---|
| Authorize throughput | >= 5000 req/s | k6 `http_reqs` rate |
| Authorize p95 latency | < 200ms | k6 `authorize_latency` p95 |
| Authorize p99 latency | < 500ms | k6 `authorize_latency` p99 |
| Error rate | < 1% | k6 `error_rate` |
