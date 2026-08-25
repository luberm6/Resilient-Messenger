#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
command -v swiftc >/dev/null
cargo build --locked -p messenger-uniffi
cargo install --locked uniffi --features cli --version 0.32.0
generated="$root/target/swift-integration"
mkdir -p "$generated"
uniffi-bindgen generate \
  --library target/debug/libmessenger_uniffi.dylib \
  --language swift \
  --out-dir "$generated"
swiftc \
  -I "$generated" \
  -Xcc "-fmodule-map-file=$generated/messenger_uniffiFFI.modulemap" \
  -L "$root/target/debug" \
  -Xlinker -rpath -Xlinker "$root/target/debug" \
  -lmessenger_uniffi \
  "$generated/messenger_uniffi.swift" \
  apps/ios/Tests/BindingsIntegration/main.swift \
  -o "$generated/swift-bindings-test"
"$generated/swift-bindings-test"
