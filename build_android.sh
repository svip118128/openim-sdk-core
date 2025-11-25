#!/bin/bash

set -e

OUTPUT_DIR="./build"
AAR_NAME="open_im_sdk.aar"
ANDROID_API_LEVEL=${ANDROID_API_LEVEL:-21}
ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk-bundle}

echo "=========================================="
echo "OpenIM SDK Core - Android AAR Builder"
echo "=========================================="

check_requirements() {
    echo "Checking requirements..."
    
    if ! command -v go &> /dev/null; then
        echo "Error: Go is not installed"
        exit 1
    fi
    
    if ! command -v gomobile &> /dev/null; then
        echo "Installing gomobile..."
        go install golang.org/x/mobile/cmd/gomobile@latest
        go install golang.org/x/mobile/cmd/gobind@latest
        gomobile init
    fi
    
    if [ -z "$ANDROID_HOME" ]; then
        echo "Error: ANDROID_HOME is not set"
        exit 1
    fi
    
    echo "✓ All requirements met"
}

clean_build() {
    echo "Cleaning previous builds..."
    rm -rf "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
    echo "✓ Clean completed"
}

build_aar() {
    echo "Building AAR for Android..."
    echo "Target packages: ./open_im_sdk/ ./open_im_sdk_callback/"
    
    gomobile bind \
        -v \
        -trimpath \
        -ldflags="-s -w" \
        -o "$OUTPUT_DIR/$AAR_NAME" \
        -target=android \
        -androidapi=$ANDROID_API_LEVEL \
        ./open_im_sdk/ \
        ./open_im_sdk_callback/
    
    if [ -f "$OUTPUT_DIR/$AAR_NAME" ]; then
        echo "✓ AAR built successfully: $OUTPUT_DIR/$AAR_NAME"
        ls -lh "$OUTPUT_DIR/$AAR_NAME"
    else
        echo "Error: AAR build failed"
        exit 1
    fi
}

build_specific_arch() {
    local arch=$1
    echo "Building AAR for architecture: $arch..."
    
    GOARCH=$arch gomobile bind \
        -v \
        -trimpath \
        -ldflags="-s -w" \
        -o "$OUTPUT_DIR/open_im_sdk_${arch}.aar" \
        -target=android/$arch \
        -androidapi=$ANDROID_API_LEVEL \
        ./open_im_sdk/ \
        ./open_im_sdk_callback/
    
    echo "✓ AAR built for $arch"
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  all              Build AAR for all architectures (default)"
    echo "  arm              Build AAR for ARM only"
    echo "  arm64            Build AAR for ARM64 only"
    echo "  386              Build AAR for x86 only"
    echo "  amd64            Build AAR for x86_64 only"
    echo "  clean            Clean build directory"
    echo "  help             Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  ANDROID_HOME          Path to Android SDK"
    echo "  ANDROID_NDK_HOME      Path to Android NDK"
    echo "  ANDROID_API_LEVEL     Android API level (default: 21)"
}

main() {
    case "${1:-all}" in
        all)
            check_requirements
            clean_build
            build_aar
            ;;
        arm|arm64|386|amd64)
            check_requirements
            clean_build
            build_specific_arch "$1"
            ;;
        clean)
            clean_build
            ;;
        help)
            show_usage
            ;;
        *)
            echo "Error: Unknown option '$1'"
            show_usage
            exit 1
            ;;
    esac
    
    echo ""
    echo "=========================================="
    echo "Build completed successfully!"
    echo "=========================================="
}

main "$@"

