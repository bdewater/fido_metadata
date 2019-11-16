# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2019-11-16
### Added
- This CHANGELOG.md file.
- Add helper method to build a `OpenSSL::X509::Store` from a metadata statement root certificates

### Changed
- JWT verification to match implementation [submitted upstream](https://github.com/jwt/ruby-jwt/pull/338) to `ruby-jwt`

### Removed
- Drop `securecompare` gem for OpenSSL gem 2.2's implementation, with a Ruby fallback for older versions

## [0.1.0] - 2019-11-13
### Added
- Extracted from [webauthn-ruby PR 208](https://github.com/cedarcode/webauthn-ruby/pull/208) after discussion with the maintainers. Thanks for the feedback @grzuy and @brauliomartinezlm!

[0.1.0]: https://github.com/bdewater/fido_metadata/releases/tag/v0.1.0
