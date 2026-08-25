FROM rust:1.98.0-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p relay
FROM debian:bookworm-slim
RUN useradd --system --uid 10001 relay
COPY --from=build /src/target/release/relay /usr/local/bin/relay
USER relay
EXPOSE 8081
ENTRYPOINT ["relay"]
