# EyeToy Chat Community Server V032

Experimental preservation build focused on the disconnect-state observed after the legacy TLS stage.

## Highlights

- fixes the V031 post-TLS MAS ECHO counter crash;
- preserves the working MUIS / Universe / MAS / SCERT flow;
- keeps VersionServer `0x86/0x87` and Policy `0x47/0x48` behavior unchanged;
- records fatal TLS certificate rejection;
- tracks MAS ECHO packets after the TLS failure;
- tests a controlled MAS socket close after the configured threshold.

## Current known blocker

EyeToy reaches TLS 1.0 on TCP 10443. Historical certificate probes tested during development are rejected with fatal TLS alert `certificate_expired` before ClientKeyExchange.

The public release does not include historical certificates extracted from Sony/SCEE media. Locally generated test certificates are included only for interoperability diagnostics.

## Testing request

When testing V032, please report what EyeToy does immediately after the `V031-MAS-CONTROLLED-CLOSE` marker:

- returns to menu;
- remains on disconnect screen;
- retries;
- reconnects to MAS;
- produces a different error.

Attach sanitized logs/raw protocol captures when possible.
