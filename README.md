# Burp Suite Copy to Markdown Extension

When analyzing web sites through a series of HTTP requests using Burp Suite, I prefer to place all requests in a complete document for analysis, making it easy to search, add code, notes, and other information. This allows me to quickly process them into a technical document organized by requests. This extension provides functionality for Burp Suite to convert HTTP requests and responses to Markdown format, supporting automatic generation of document table of contents and hostname lists, facilitating systematic organization and analysis of network interaction data.

## Features

- Copy single or multiple requests from Proxy History to Markdown
- Copy requests and responses from Intercept to Markdown
- Copy requests and responses from Repeater to Markdown
- Automatically format as clean Markdown, with URL path as title
- **New**: Automatically generate document table of contents and hostname list
- **New**: Include corresponding hostname in each request title

## Build Method

This project uses a simple shell script `build.sh` for building, no longer depending on Gradle:

```bash
# Give execution permission to the script
chmod +x build.sh

# Execute the build
./build.sh
```

The script will automatically:
1. Download necessary dependencies (Burp Suite API)
2. Compile Java source code
3. Package into a JAR file

After building, the JAR file will be located at `build/libs/burp-copy2md.jar`.

## Usage

1. After loading the extension, right-click in the following locations to see the "Copy to Markdown" option:
   - Proxy History - supports multi-selection
   - Intercept
   - Repeater

2. Click the "Copy to Markdown" option to automatically copy formatted Markdown to the clipboard

3. Paste the content into any Markdown-supporting editor

## Markdown Format

The copied content format is as follows:

```markdown
# HTTP Request and Response Report

## Hostnames

- example.com
- api.example.org

## Table of Contents

1. [/api/login](#apilogin)
2. [/logout](#logout)

## /api/login (example.com)
### request
```
HTTP request content
```
### response
```
HTTP response content
```

## /logout (example.com)
### request
```
HTTP request content
```
### response
```
HTTP response content
```
```

## Installation

1. In Burp Suite, go to the Extender tab
2. Click the "Add" button
3. Select the generated JAR file (`build/libs/burp-copy2md.jar`)
4. Click "Next" to complete the installation

## Project Cleanup

This project initially used Gradle for building, but due to Java version compatibility issues, it now uses direct compilation. The following files are no longer needed and can be safely deleted:

- `build.gradle`
- `gradle.properties`
- `gradle/` directory
- `gradlew`
- `gradlew.bat`

## Development Information

- Language: Java
- Build Tool: Direct use of javac and jar commands (via build.sh script)
- Burp Extension API Version: 2.3 