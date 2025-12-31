FROM alpine:latest AS builder

# Install build dependencies
RUN apk update && apk add --no-cache \
    gcc make musl-dev \
    curl-dev jansson-dev \
    openssl-dev zlib-dev \
    git cmake

# Copy source
WORKDIR /build
COPY src/ ./src/
COPY modules/ ./modules/
COPY plugins/ ./plugins/
COPY Makefile .

# Build
RUN make release

# Runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk update && apk add --no-cache \
    curl jansson \
    openssl zlib \
    bash bash-completion \
    net-tools bind-tools \
    python3 py3-pip

# Copy built binary
COPY --from=builder /build/clobes /usr/local/bin/clobes

# Copy configuration
COPY config/ /etc/clobes/
COPY completion/ /usr/share/bash-completion/completions/

# Create directories
RUN mkdir -p /var/log/clobes /var/cache/clobes

# Create user
RUN adduser -D clobesuser
USER clobesuser
WORKDIR /home/clobesuser

# Test
RUN clobes version

# Default command
CMD ["clobes", "--help"]
