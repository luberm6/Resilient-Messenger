#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
command -v gradle >/dev/null
cargo build --locked -p messenger-uniffi
cargo install --locked uniffi --features cli --version 0.32.0
generated="$root/apps/android/bindings-test/src/main/kotlin"
uniffi-bindgen generate \
  --library target/debug/libmessenger_uniffi.so \
  --language kotlin \
  --out-dir "$generated"
JAVA_TOOL_OPTIONS="-Djna.library.path=$root/target/debug" \
  gradle -p apps/android/bindings-test --no-daemon run
