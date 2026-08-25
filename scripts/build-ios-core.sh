#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  rustup target add "$target"
  cargo build --release --locked -p messenger-uniffi --target "$target"
done
command -v xcodebuild >/dev/null
mkdir -p target/ios-bindings target/xcframework
cargo install --locked uniffi --features cli --version 0.32.0
uniffi-bindgen generate --library target/aarch64-apple-ios/release/libmessenger_uniffi.a --language swift --out-dir target/ios-bindings
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libmessenger_uniffi.a -headers target/ios-bindings \
  -library target/aarch64-apple-ios-sim/release/libmessenger_uniffi.a -headers target/ios-bindings \
  -output target/xcframework/ResilientMessengerCore.xcframework
