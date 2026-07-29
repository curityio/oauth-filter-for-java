## OAuth Filter for Java Changelog

## Unreleased

- Support `aud` claim in JWT when it's specified as an array rather than a string.
- Allow JWT validators to configure a Set of accepted audiences, not just one.
- Minimum Java version requirement changed to 15.

## 4.0.0 (2023-11-27)

- Added support for EdDSA signatures.
- Added support for `okp` JWK key type.
- Improved JWK decoding and JWKS validation coverage with new tests.
- Migrated from `javax.servlet` API to `jakarta.servlet` API.
- Updated dependencies (including `jose4j` and `guava`).
- Updated README documentation.

## 3.0.0 (2021-05-27)

- Changed groupID to `io.curity` and package name to `io.curity.oauth`.
- Updated dependencies.
