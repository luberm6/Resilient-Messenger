# v1 golden vectors

`v1-ping.hex` is the canonical encoding of `[schema=1, version=1, Ping, client_message_id=16×0x07, ttl=0, body=h'']`. Rust decoding is tested. Swift and Kotlin bindings must expose the same byte-level Rust codec through UniFFI; their binding conformance tests are added together with binding generation, not duplicated as platform codecs.
