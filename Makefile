# Geonosis — operator + developer convenience targets.
#
# Run `make help` for the menu. Targets are split into four groups:
#
#   Build / test           — cargo build, cargo test, cargo clippy, …
#   Local dev quickstart   — docker compose + bootstrap realm
#   Examples               — axum resource server + Next.js client
#   Operations             — Helm render, Docker image build, migrations
#
# Override defaults via env / make-args:
#   make compose-up COMPOSE_FILE=deploy/compose/quickstart.yml
#   make docker-build IMAGE=ghcr.io/me/geonosis-server:dev
#   make migrate DATABASE_URL=postgres://geonosis:geonosis@localhost/geonosis

CARGO            ?= cargo
COMPOSE          ?= docker compose
COMPOSE_FILE     ?= deploy/compose/quickstart.yml
IMAGE            ?= ghcr.io/hosnian-prime/geonosis-server:dev
HELM             ?= helm
HELM_CHART       ?= deploy/helm/geonosis
HELM_RELEASE     ?= geonosis
HELM_NAMESPACE   ?= geonosis
DATABASE_URL     ?= postgres://geonosis:geonosis@localhost:5432/geonosis
SERVER_URL       ?= http://localhost:8080
GEOCTL           ?= $(CARGO) run --quiet --bin geoctl --

.DEFAULT_GOAL := help

# ---------------------------------------------------------------- help
.PHONY: help
help: ## List available targets
	@awk 'BEGIN{FS=":.*## "; max=0} \
	      /^[a-zA-Z0-9_.-]+:.*## / {if (length($$1) > max) max = length($$1)} \
	      END{}' $(MAKEFILE_LIST) > /dev/null
	@awk 'BEGIN{FS=":.*## "; printf "\nGeonosis Makefile\n\n"} \
	      /^[a-zA-Z0-9_.-]+:.*## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2} \
	      /^### / {printf "\n\033[1m%s\033[0m\n", substr($$0,5)}' $(MAKEFILE_LIST)

### Build / test
.PHONY: build
build: ## Compile the workspace
	$(CARGO) build --workspace

.PHONY: release
release: ## Build release binaries
	$(CARGO) build --workspace --release

.PHONY: test
test: ## Run the workspace test suite (unit tests)
	$(CARGO) test --workspace --lib

.PHONY: test-all
test-all: ## Run all tests (unit + integration)
	$(CARGO) test --workspace

.PHONY: test-admin-api
test-admin-api: ## Run admin API integration tests
	$(CARGO) test --package geonosis-admin-ui --test '*'

.PHONY: test-admin-smoke
test-admin-smoke: ## Run admin API smoke test only
	$(CARGO) test --package geonosis-admin-ui --test smoke

.PHONY: check
check: ## cargo check on the entire workspace
	$(CARGO) check --workspace

.PHONY: clippy
clippy: ## cargo clippy with warnings as errors (allows pre-existing lints in geonosis-core)
	$(CARGO) clippy --workspace --all-targets -- -D warnings

.PHONY: fmt
fmt: ## Apply rustfmt
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Verify rustfmt cleanliness
	$(CARGO) fmt --all -- --check

.PHONY: clean
clean: ## Remove cargo build artefacts
	$(CARGO) clean

### Local dev quickstart
.PHONY: compose-up
compose-up: ## Start the quickstart stack (postgres + server + bootstrap realm)
	$(COMPOSE) -f $(COMPOSE_FILE) up -d
	@echo "Waiting for /-/ready…"
	@for i in $$(seq 1 30); do \
	  if curl -fsS http://localhost:8080/-/ready >/dev/null 2>&1; then \
	    echo "ready"; exit 0; \
	  fi; \
	  sleep 1; \
	done; \
	echo "server did not become ready; check 'make compose-logs'"; exit 1

.PHONY: compose-down
compose-down: ## Stop the quickstart stack
	$(COMPOSE) -f $(COMPOSE_FILE) down

.PHONY: compose-wipe
compose-wipe: ## Stop the quickstart stack AND drop the postgres volume
	$(COMPOSE) -f $(COMPOSE_FILE) down -v

.PHONY: compose-logs
compose-logs: ## Tail server logs from the quickstart stack
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f geonosis

.PHONY: quickstart
quickstart: compose-up ## Bring up the stack and print the verification commands
	@echo
	@echo "Geonosis is running at $(SERVER_URL)"
	@echo
	@echo "Verify discovery:"
	@echo "  curl -fsS $(SERVER_URL)/realms/acme/.well-known/openid-configuration | jq ."
	@echo
	@echo "Demo user:    ada@acme.test / ada-pw"
	@echo "Admin user:   admin@acme.test / admin-pw"
	@echo "OIDC client:  acme-web  (redirect http://127.0.0.1:8888/callback)"

.PHONY: run
run: ## Run the server locally with in-memory storage (no Postgres)
	$(CARGO) run --bin geonosis-server -- \
	  --listen 127.0.0.1:8080 \
	  --public-url $(SERVER_URL)

.PHONY: cli
cli: ## Drop into geoctl (forward args after `--`)
	$(GEOCTL)

### Examples
.PHONY: example-axum
example-axum: ## Run the axum resource-server example (port 7000)
	$(CARGO) run --manifest-path examples/axum-resource-server/Cargo.toml

.PHONY: example-axum-check
example-axum-check: ## cargo check the axum example
	$(CARGO) check --manifest-path examples/axum-resource-server/Cargo.toml

.PHONY: example-nextjs-install
example-nextjs-install: ## Install the Next.js example's Node deps
	cd examples/nextjs-app && npm install

.PHONY: example-nextjs
example-nextjs: ## Run the Next.js example (port 8888)
	cd examples/nextjs-app && npm run dev

### Operations
.PHONY: docker-build
docker-build: ## Build the geonosis-server container image
	docker build -t $(IMAGE) .

.PHONY: helm-lint
helm-lint: ## helm lint the chart
	$(HELM) lint $(HELM_CHART)

.PHONY: helm-render
helm-render: ## helm template the chart with default values
	$(HELM) template $(HELM_RELEASE) $(HELM_CHART) --namespace $(HELM_NAMESPACE)

.PHONY: helm-install
helm-install: ## helm install the chart (assumes secrets are pre-created)
	$(HELM) install $(HELM_RELEASE) $(HELM_CHART) \
	  --namespace $(HELM_NAMESPACE) --create-namespace

.PHONY: helm-upgrade
helm-upgrade: ## helm upgrade the running release
	$(HELM) upgrade $(HELM_RELEASE) $(HELM_CHART) --namespace $(HELM_NAMESPACE)

.PHONY: migrate
migrate: ## Apply pending migrations (uses $(DATABASE_URL))
	$(GEOCTL) migrate --database-url $(DATABASE_URL) up

.PHONY: migrate-status
migrate-status: ## Show migration status against $(DATABASE_URL)
	$(GEOCTL) migrate --database-url $(DATABASE_URL) status
