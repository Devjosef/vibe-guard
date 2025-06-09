#!/bin/bash
set -e

# Configuration
DOCKER_REGISTRY="devjosef"
IMAGE_NAME="vibe-guard"
VERSION=$(node -p "require('../package.json').version")

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Function to print error
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running"
    exit 1
fi

# Login to Docker Hub
print_status "Logging in to Docker Hub..."
docker login

# Build for multiple platforms
print_status "Building multi-platform images..."
docker buildx create --use
docker buildx build \
    --platform linux/amd64,linux/arm64,linux/arm/v7 \
    --tag ${DOCKER_REGISTRY}/${IMAGE_NAME}:${VERSION} \
    --tag ${DOCKER_REGISTRY}/${IMAGE_NAME}:latest \
    --push \
    -f docker/Dockerfile \
    ..

# Verify the builds
print_status "Verifying builds..."
for platform in linux/amd64 linux/arm64 linux/arm/v7; do
    print_status "Testing ${platform} image..."
    docker pull --platform ${platform} ${DOCKER_REGISTRY}/${IMAGE_NAME}:${VERSION}
    docker run --rm --platform ${platform} ${DOCKER_REGISTRY}/${IMAGE_NAME}:${VERSION} --version
done

print_status "Build and push completed successfully!"
print_status "Images available at: https://hub.docker.com/r/${DOCKER_REGISTRY}/${IMAGE_NAME}" 