default: ci

bootstrap:
  cargo fetch --locked
  cargo install --locked cargo-deny --version 0.20.2
  cargo install --locked cargo-audit --version 0.22.2

lint:
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  scripts/check-no-secrets.sh

test:
  cargo test --workspace --locked --no-fail-fast

build:
  cargo build --workspace --locked

ci: lint test build audit

postgres-test:
  cargo test --locked -p core-api --test postgres -- --ignored --test-threads=1

up:
  docker compose -f infra/docker/compose.yml up --build

down:
  docker compose -f infra/docker/compose.yml down

audit:
  cargo deny check
  cargo audit

protocol-size:
  cargo run --locked -p messenger-protocol --example size_report

crypto-size:
  cargo run --locked -p messenger-crypto --example crypto_report

identity-harness:
  cargo run --locked -p messenger-identity --example identity_harness

network-lab:
  cargo run --locked -p network-lab --bin network-lab

swift-bindings:
  scripts/test-swift-bindings.sh

kotlin-bindings:
  scripts/test-kotlin-bindings.sh
