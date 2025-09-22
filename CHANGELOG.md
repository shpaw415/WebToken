# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-09-19

### Added
- Initial release of WebToken library
- AES-256-CBC encryption with HMAC integrity verification
- JWT-like payload structure with expiration and issuer validation
- Timing attack protection with constant-time comparison
- Secure cookie handling with configurable options
- Token rotation and validation features
- Weak secret detection and validation
- Size limits and security best practices
- Plain cookie support with same security options
- TypeScript support with comprehensive type definitions
- Comprehensive documentation and examples

### Security
- Implemented timing-safe string comparison to prevent timing attacks
- Added HMAC integrity verification for all encrypted tokens
- Enforced minimum secret length (32 characters) for security
- Added weak secret pattern detection

## [Unreleased]

### Planned
- Additional encryption algorithm support (AES-256-GCM)
- Token refresh functionality
- Session storage backends (Redis, Database)
- Advanced security features (rate limiting, IP binding)