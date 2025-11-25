#!/bin/bash

set -e

# Add gomobile to PATH
export PATH=$PATH:$(go env GOPATH)/bin

OUTPUT_DIR="./build"
FRAMEWORK_NAME="OpenIMCore.xcframework"

echo "=========================================="
echo "OpenIM SDK Core - iOS XCFramework Builder"
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

    if ! command -v xcodebuild &> /dev/null; then
        echo "Error: Xcode command line tools not found"
        exit 1
    fi

    echo " All requirements met"
}

clean_build() {
    echo "Cleaning previous iOS build..."
    rm -rf "$OUTPUT_DIR/$FRAMEWORK_NAME"
    mkdir -p "$OUTPUT_DIR"
    echo " Clean completed"
}

build_xcframework() {
    echo "Building XCFramework for iOS..."
    echo "Target packages: ./open_im_sdk/ ./open_im_sdk_callback/"

    gomobile bind \
        -v \
        -trimpath \
        -ldflags="-s -w" \
        -target=ios \
        -o "$OUTPUT_DIR/$FRAMEWORK_NAME" \
        ./open_im_sdk/ \
        ./open_im_sdk_callback/

    if [ -d "$OUTPUT_DIR/$FRAMEWORK_NAME" ]; then
        echo " XCFramework built successfully: $OUTPUT_DIR/$FRAMEWORK_NAME"
        ls "$OUTPUT_DIR/$FRAMEWORK_NAME"
    else
        echo "Error: XCFramework build failed"
        exit 1
    fi
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  all      Build iOS XCFramework (default)"
    echo "  clean    Clean build directory"
    echo "  help     Show this help message"
}

main() {
    case "${1:-all}" in
        all)
            check_requirements
            clean_build
            build_xcframework
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
    echo "iOS build completed!"
    echo "=========================================="
}

main "$@"

