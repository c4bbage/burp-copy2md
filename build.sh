#!/bin/bash

# Setup color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Output colored information
info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

# Create necessary directories
mkdir -p build/classes/java/main
mkdir -p build/libs
mkdir -p lib

# Check and download Burp Extension API JAR file
if [ ! -f "lib/burp-extender-api-2.3.jar" ]; then
  info "Downloading Burp Extension API..."
  curl -L -s -o lib/burp-extender-api-2.3.jar https://repo1.maven.org/maven2/net/portswigger/burp/extender/burp-extender-api/2.3/burp-extender-api-2.3.jar
  if [ $? -ne 0 ]; then
    warn "Failed to download Burp Extension API, please check your network connection"
    exit 1
  fi
  info "Burp Extension API download completed"
else
  info "Using existing Burp Extension API"
fi

# Compile Java files
info "Compiling Java source files..."
javac -cp lib/burp-extender-api-2.3.jar -d build/classes/java/main src/main/java/burp/*.java
if [ $? -ne 0 ]; then
  warn "Compilation failed, please check the errors above"
  exit 1
fi
info "Compilation completed"

# Create JAR file
info "Creating JAR file..."
jar -cf build/libs/burp-copy2md.jar -C build/classes/java/main .
if [ $? -ne 0 ]; then
  warn "Failed to create JAR file"
  exit 1
fi
info "JAR file created: build/libs/burp-copy2md.jar"

# Display JAR file contents
info "JAR file contents:"
jar tf build/libs/burp-copy2md.jar | sort

info "Build completed! JAR file located at: build/libs/burp-copy2md.jar"
info "Usage: Load this JAR file in the Extender tab of Burp Suite" 