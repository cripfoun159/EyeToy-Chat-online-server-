# Changelog

## V032

- Fixed the V031 MAS diagnostic crash caused by `v031_tls_fail_echoes` being initialized in the wrong handler.
- Kept the TLS-failure / MAS-close experiment unchanged otherwise.
- Added cleaner public-repository defaults and documentation.

## V031

- Added tracking for fatal TLS errors by client IP.
- Added post-TLS-failure MAS ECHO counting.
- Added a controlled MAS socket close for the disconnect-screen test.

## V030

- Added SCERT/RSA diagnostics around the Medius global key and client modulus.
- Added crypto-state fingerprints around the main MAS handshake and Policy path.
