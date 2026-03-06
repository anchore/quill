FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

ARG ZIG_VERSION=0.13.0
RUN mkdir -p /opt/zig && \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-$(uname -m)-${ZIG_VERSION}.tar.xz" \
    | tar -xJ -C /opt/zig --strip-components=1

ENV PATH="/opt/zig:${PATH}"

WORKDIR /build
COPY hello.s .

# assemble and link minimal binary
RUN zig cc -target aarch64-macos \
    -nostdlib \
    -Wl,-e,_main \
    -Wl,-pagezero_size,0x1000 \
    -o hello hello.s

FROM scratch
COPY --from=builder /build/hello /hello
