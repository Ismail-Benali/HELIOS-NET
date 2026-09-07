# =====================================================================
# Stage 1: Builder (Polyglot Compilation)
# =====================================================================
FROM golang:1.22-bookworm AS builder

# Install system build dependencies: Python 3, GCC, Make, and curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    gcc \
    make \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Rust stable toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Copy project source code into builder stage
COPY . /build

# Execute unified polyglot build script (Go, C, and Rust)
RUN python3 build.py

# =====================================================================
# Stage 2: Runtime (Minimal & Secure Base)
# =====================================================================
FROM python:3.12-slim AS runtime

# Create secure non-root user
RUN useradd -ms /bin/bash helios

WORKDIR /app

# Copy compiled binaries and control plane scripts from builder stage
COPY --from=builder /build/*.py /app/
COPY --from=builder /build/core /app/core/
COPY --from=builder /build/engine /app/engine/
COPY --from=builder /build/modules /app/modules/
COPY --from=builder /build/transport /app/transport/
COPY --from=builder /build/rust-core /app/rust-core/

# Set ownership and execution permissions for non-root user
RUN chown -R helios:helios /app && \
    chmod -R +x /app/*.py

USER helios

ENTRYPOINT ["python3", "run.py"]
