default: ci
bootstrap:
  cargo fetch --locked
lint:
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
test:
  cargo test --workspace
build:
  cargo build --workspace --locked
ci: lint test build audit
up:
  docker compose -f infra/docker/compose.yml up --build
down:
  docker compose -f infra/docker/compose.yml down
audit:
  cargo deny check
protocol-size:
  cargo run -p messenger-protocol --example size_report
