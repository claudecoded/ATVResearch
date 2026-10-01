# ATVResearch

Apple TV firmware research and binary analysis toolkit builded with C++ and Cmake

ATVResearch is a research-oriented command-line toolkit for inspecting firmware archives and Apple binary formats.

The project focuses on offline analysis of firmware and binary artifacts.

## Features

Current features:

- IPSW archive inspection
- IPSW archive listing
- IPSW archive extraction
- Mach-O detection
- 32-bit Mach-O parsing
- 64-bit Mach-O parsing
- Universal/FAT binary detection
- ARM architecture detection
- ARM64 architecture detection
- x86 architecture detection
- x86_64 architecture detection
- Mach-O segment inspection
- Mach-O load command inspection
- Bounds-checked binary reading
- Automated tests
- GitHub Actions CI

## Requirements

- C++17 compiler
- CMake 3.20 or newer
- Ninja
- libarchive

### macOS

Install dependencies with Homebrew:

```bash
brew install cmake ninja libarchive
