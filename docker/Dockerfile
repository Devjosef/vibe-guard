# syntax=docker/dockerfile:1.4

# Build stage for all platforms
FROM --platform=$BUILDPLATFORM node:18.19.1-alpine AS builder

# Set build arguments
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG VERSION=1.0.0

# Install build dependencies
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src/ ./src/

# Build the application
RUN npm run build

# Build platform-specific binaries
RUN npm run package:linux && \
    npm run package:darwin && \
    npm run package:win

# Final stage - minimal runtime image
FROM --platform=$TARGETPLATFORM alpine:3.19

# Set build arguments
ARG TARGETPLATFORM
ARG VERSION=1.0.0

# Install minimal runtime dependencies
RUN apk add --no-cache \
    libstdc++ \
    libgcc \
    ca-certificates \
    curl \
    tzdata

# Create non-root user with specific UID/GID
RUN addgroup -g 1001 -S vibe-guard && \
    adduser -S vibe-guard -u 1001 -G vibe-guard && \
    mkdir -p /home/vibe-guard/.config && \
    chown -R vibe-guard:vibe-guard /home/vibe-guard

# Copy the appropriate binary based on architecture
COPY --from=builder /app/binaries/vibe-guard-* /usr/local/bin/

# Set proper permissions
RUN chmod +x /usr/local/bin/vibe-guard-* && \
    ln -s /usr/local/bin/vibe-guard-$(uname -s | tr '[:upper:]' '[:lower:]') /usr/local/bin/vibe-guard

# Switch to non-root user
USER vibe-guard

# Set working directory for scanning
WORKDIR /code

# Create volume for persistent data
VOLUME ["/home/vibe-guard/.config"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD vibe-guard --version && \
    vibe-guard scan --help && \
    curl -f http://localhost:${PORT:-3000}/health || exit 1

# Set the entrypoint
ENTRYPOINT ["vibe-guard"]

# Default command
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="Vibe-Guard Security Scanner"
LABEL org.opencontainers.image.description="🛡️ Security scanner for developers who code fast"
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.source="https://github.com/Devjosef/vibe-guard"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="Vibe-Guard Team"
LABEL org.opencontainers.image.vendor="Vibe-Guard"
LABEL org.opencontainers.image.architecture=${TARGETPLATFORM} 
LABEL org.opencontainers.image.os=alpine
LABEL org.opencontainers.image.base.name=alpine:3.19
LABEL org.opencontainers.image.base.digest=sha256:1234567890abcdef 