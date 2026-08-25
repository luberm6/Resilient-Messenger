#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to an installed Android NDK}"
for target in aarch64-linux-android x86_64-linux-android armv7-linux-androideabi; do
  rustup target add "$target"
done
cargo install --locked cargo-ndk --version 4.1.2
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o apps/android/core/src/main/jniLibs build --release --locked -p messenger-uniffi
cargo install --locked uniffi --features cli --version 0.32.0
mkdir -p apps/android/core/src/main/kotlin
uniffi-bindgen generate --library target/aarch64-linux-android/release/libmessenger_uniffi.so --language kotlin --out-dir apps/android/core/src/main/kotlin
command -v gradle >/dev/null
gradle -p apps/android --no-daemon :core:assembleRelease
