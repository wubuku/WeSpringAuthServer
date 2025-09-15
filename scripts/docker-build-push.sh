#!/bin/bash

# Docker Build and Push Script for WeSpringAuthServer
# This script builds Docker images and pushes them to DockerHub
# Usage: ./docker-build-push.sh [options]
#
# Environment Variables Required:
#   DOCKERHUB_USERNAME - Your DockerHub username
#   DOCKERHUB_TOKEN - Your DockerHub Personal Access Token
#
# Options:
#   -a, --arch ARCH          Target architecture (default: amd64, options: amd64, arm64)
#   -t, --tag TAG            Custom tag (default: latest)
#   -v, --version VERSION    Version tag (default: 1.0.0-SNAPSHOT)
#   -n, --no-cache           Build without cache
#   -h, --help               Show this help message
#
# Examples:
#   export DOCKERHUB_USERNAME="your_username"
#   export DOCKERHUB_TOKEN="your_token"
#   ./docker-build-push.sh
#   ./docker-build-push.sh --arch arm64 --tag v1.0.0
#   ./docker-build-push.sh --no-cache --version 1.0.0

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_IMAGE_NAME="wespring-auth-server"
DEFAULT_VERSION="1.0.0-SNAPSHOT"
DEFAULT_ARCH="amd64"
DEFAULT_TAG="latest"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

This script builds Docker images and pushes them to DockerHub for WeSpringAuthServer.

Required Environment Variables:
  DOCKERHUB_USERNAME - Your DockerHub username
  DOCKERHUB_TOKEN    - Your DockerHub Personal Access Token

Options:
  -a, --arch ARCH          Target architecture (default: amd64, options: amd64, arm64)
  -t, --tag TAG            Custom tag (default: latest)
  -v, --version VERSION    Version tag (default: 1.0.0-SNAPSHOT)
  -n, --no-cache           Build without cache
  -h, --help               Show this help message

Examples:
  # Set environment variables first
  export DOCKERHUB_USERNAME="your_username"
  export DOCKERHUB_TOKEN="your_token"

  # Build and push with default settings
  $0

  # Build and push for arm64 architecture
  $0 --arch arm64

  # Build and push with custom tag
  $0 --tag v1.0.0

  # Build and push with custom version
  $0 --version 1.0.0 --tag v1.0.0

  # Build without cache
  $0 --no-cache

  # Build for arm64 with custom tag and no cache
  $0 --arch arm64 --tag v1.0.0 --no-cache

Image Naming Convention:
  - Full image name: \${DOCKERHUB_USERNAME}/\${DEFAULT_IMAGE_NAME}
  - Tags: \${TAG}, \${VERSION}, sha-\${SHORT_SHA}
  - Platform: linux/\${ARCH}

EOF
}

# Function to check if environment variables are set
check_env_vars() {
    if [[ -z "${DOCKERHUB_USERNAME}" ]]; then
        print_error "DOCKERHUB_USERNAME environment variable is not set"
        print_error "Please set it with: export DOCKERHUB_USERNAME='your_username'"
        exit 1
    fi

    if [[ -z "${DOCKERHUB_TOKEN}" ]]; then
        print_error "DOCKERHUB_TOKEN environment variable is not set"
        print_error "Please set it with: export DOCKERHUB_TOKEN='your_token'"
        exit 1
    fi
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running or not accessible"
        print_error "Please start Docker and try again"
        exit 1
    fi
    print_success "Docker is running"
}

# Function to setup Docker Buildx
setup_buildx() {
    print_info "Setting up Docker Buildx..."

    # Check if buildx is available
    if ! docker buildx version >/dev/null 2>&1; then
        print_error "Docker Buildx is not available. Please install it first."
        print_info "You can install it with: docker buildx install"
        exit 1
    fi

    # Create a new builder if it doesn't exist
    local builder_name="wespring-auth-builder"
    if ! docker buildx ls | grep -q "$builder_name"; then
        print_info "Creating new Buildx builder '$builder_name'..."
        docker buildx create --name "$builder_name" --use
    else
        print_info "Using existing Buildx builder '$builder_name'..."
        docker buildx use "$builder_name"
    fi

    print_success "Docker Buildx setup complete"
}

# Function to login to DockerHub
login_dockerhub() {
    print_info "Logging in to DockerHub..."

    # Login to DockerHub
    echo "$DOCKERHUB_TOKEN" | docker login -u "$DOCKERHUB_USERNAME" --password-stdin

    if [[ $? -eq 0 ]]; then
        print_success "Successfully logged in to DockerHub as $DOCKERHUB_USERNAME"
    else
        print_error "Failed to login to DockerHub"
        exit 1
    fi
}

# Function to run tests
run_tests() {
    print_info "Running tests before building..."

    # Check if Maven is available
    if ! command -v mvn >/dev/null 2>&1; then
        print_warning "Maven not found, skipping tests"
        return 0
    fi

    # Run tests
    if mvn clean test -B; then
        print_success "Tests passed successfully"
    else
        print_error "Tests failed"
        print_error "Please fix the failing tests before building the Docker image"
        exit 1
    fi
}

# Function to build and push image
build_and_push() {
    local image_name="$1"
    local arch="$2"
    local tag="$3"
    local version="$4"
    local no_cache="$5"

    print_info "Building and pushing image: $image_name"
    print_info "Target architecture: linux/$arch"
    print_info "Dockerfile: ./Dockerfile"

    # Check if Dockerfile exists
    if [[ ! -f "./Dockerfile" ]]; then
        print_error "Dockerfile not found in current directory"
        exit 1
    fi

    # Generate tags
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local short_sha=$(git rev-parse --short HEAD 2>/dev/null || echo "local")
    local tags="${image_name}:${tag},${image_name}:${version},${image_name}:sha-${short_sha}"

    print_info "Tags to be created: $tags"
    print_info "Build timestamp: $timestamp"

    # Prepare buildx command
    local buildx_cmd="docker buildx build"
    buildx_cmd="$buildx_cmd --platform linux/$arch"
    buildx_cmd="$buildx_cmd --file ./Dockerfile"
    buildx_cmd="$buildx_cmd --tag $image_name:$tag"
    buildx_cmd="$buildx_cmd --tag $image_name:$version"
    buildx_cmd="$buildx_cmd --tag $image_name:sha-$short_sha"
    buildx_cmd="$buildx_cmd --push"
    
    if [[ "$no_cache" == "true" ]]; then
        buildx_cmd="$buildx_cmd --no-cache"
    fi
    
    buildx_cmd="$buildx_cmd --build-arg GIT_REFRESH=$timestamp"
    buildx_cmd="$buildx_cmd ."

    print_info "Starting build and push process..."
    print_info "Command: $buildx_cmd"

    # Execute buildx command
    eval $buildx_cmd

    if [[ $? -eq 0 ]]; then
        print_success "Successfully built and pushed image: $image_name"
        print_info "Available tags:"
        echo "  - $image_name:$tag"
        echo "  - $image_name:$version"
        echo "  - $image_name:sha-$short_sha"
        echo "  - Platform: linux/$arch"
        return 0
    else
        print_error "Failed to build and push image: $image_name"
        return 1
    fi
}

# Function to show build summary
show_summary() {
    local image_name="$1"
    local tag="$2"
    local version="$3"
    local arch="$4"

    print_info "=========================================="
    print_success "Build completed successfully!"
    print_info "Image: $image_name"
    print_info "Tags: $tag, $version, sha-$(git rev-parse --short HEAD 2>/dev/null || echo 'local')"
    print_info "Platform: linux/$arch"
    print_info "=========================================="
    print_info "You can now pull the image with:"
    echo "  docker pull $image_name:$tag"
    echo "  docker pull $image_name:$version"
    print_info "=========================================="
}

# Main function
main() {
    # Initialize variables
    local arch="$DEFAULT_ARCH"
    local tag="$DEFAULT_TAG"
    local version="$DEFAULT_VERSION"
    local no_cache="false"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help|help)
                show_usage
                exit 0
                ;;
            -a|--arch)
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    print_error "Option --arch requires an argument"
                    echo ""
                    show_usage
                    exit 1
                fi
                arch="$2"
                # Validate architecture
                if [[ "$arch" != "amd64" && "$arch" != "arm64" ]]; then
                    print_error "Invalid architecture: $arch"
                    print_error "Supported architectures: amd64, arm64"
                    exit 1
                fi
                shift 2
                ;;
            -t|--tag)
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    print_error "Option --tag requires an argument"
                    echo ""
                    show_usage
                    exit 1
                fi
                tag="$2"
                shift 2
                ;;
            -v|--version)
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    print_error "Option --version requires an argument"
                    echo ""
                    show_usage
                    exit 1
                fi
                version="$2"
                shift 2
                ;;
            -n|--no-cache)
                no_cache="true"
                shift
                ;;
            -*)
                print_error "Unknown option: $1"
                echo ""
                show_usage
                exit 1
                ;;
            *)
                print_error "Unknown argument: $1"
                echo ""
                show_usage
                exit 1
                ;;
        esac
    done

    # Show configuration
    print_info "Starting Docker build and push process for WeSpringAuthServer..."
    print_info "Configuration:"
    print_info "  Architecture: linux/$arch"
    print_info "  Tag: $tag"
    print_info "  Version: $version"
    print_info "  No cache: $no_cache"

    # Check environment variables
    check_env_vars

    # Check Docker
    check_docker

    # Run tests
    run_tests

    # Setup Docker Buildx
    setup_buildx

    # Login to DockerHub
    login_dockerhub

    # Build image name
    local image_name="${DOCKERHUB_USERNAME}/${DEFAULT_IMAGE_NAME}"

    # Build and push
    if build_and_push "$image_name" "$arch" "$tag" "$version" "$no_cache"; then
        show_summary "$image_name" "$tag" "$version" "$arch"
        print_success "All operations completed successfully!"
    else
        print_error "Build and push failed. Check the output above for details."
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
