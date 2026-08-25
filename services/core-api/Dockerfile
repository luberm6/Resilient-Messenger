FROM rust:1.85.1-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --locked --release -p core-api
FROM debian:bookworm-slim
COPY --from=build /app/target/release/core-api /usr/local/bin/core-api
ENTRYPOINT ["core-api"]
