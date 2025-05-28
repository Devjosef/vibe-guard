# Multi-stage build for minimal final image
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY src/ ./src/

# Build the application
RUN npm run build

# Final stage - minimal runtime image
FROM alpine:latest

# Install necessary runtime dependencies
RUN apk add --no-cache \
    libstdc++ \
    libgcc

# Create non-root user
RUN addgroup -g 1001 -S vibe-guard && \
    adduser -S vibe-guard -u 1001

# Copy the built application
COPY --from=builder /app/dist /app/dist
COPY --from=builder /app/node_modules /app/node_modules
COPY --from=builder /app/package.json /app/package.json

# Or use the standalone binary (smaller image)
# COPY binaries/vibe-guard-linux /usr/local/bin/vibe-guard

WORKDIR /app

# Switch to non-root user
USER vibe-guard

# Set the entrypoint
ENTRYPOINT ["node", "dist/bin/vibe-guard.js"]

# Default command
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="Vibe-Guard Security Scanner"
LABEL org.opencontainers.image.description="🛡️ Security scanner for developers who code fast"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="Vibe-Guard Team" 