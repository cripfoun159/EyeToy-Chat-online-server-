 EyeToy Chat Community Server

Community server project for bringing the European online services of **EyeToy: Chat (PlayStation 2)** back to life

The project is still experimental. The current goal is to understand the original network flow well enough to let an unmodified game connect to a replacement server.

## Current status

A good part of the original connection sequence is already working

- DNS redirection
- DNAS path
- update check (`BUILD 194`)
- MUIS connection and universe information
- Medius / SCERT RSA handshake
- session key exchange
- MAS connection on port `10075`
- VersionServer request / response (`0x86` / `0x87`)
- Policy request / response (`0x47` / `0x48`)

The main problem right now is the HTTPS/TLS step used by the update service. The client accepts the TLS 1.0 handshake far enough to inspect the certificate, then rejects the historical test material with `certificate_expired`.

After that error the MAS connection stays alive and the game keeps sending ECHO packets. V032 adds a controlled MAS close so we can see whether the client is waiting for the server to end the session before leaving the disconnect screen.

See [docs/STATUS.md](docs/STATUS.md) for the latest details.

## Running the server

Requirements:

- Python 3
- Windows or Linux
- PS2 / PCSX2 on the same network as the server

Run:

```bash
python server.py
```

For a quick internal test:

```bash
python server.py --selftest
```

The server prints the IP address to use as the primary and secondary DNS on the PS2.

## Logs

Logs are written under `logs/`. Packet payloads used for protocol research may also be written under `logs/raw/`.

When reporting a problem, the most useful things are:

- the server log from one clean connection attempt;
- what was visible on the PS2 when it stopped progressing;
- whether the game was still animated/responding;
- RAW packets if they were produced.

Please remove private network information before posting logs publicly if needed.

## Repository layout

```text
server.py                 main server
config.json               server configuration
http_root/                files served over HTTP
logs/                     local logs (ignored by git)
tls/                      local/generated TLS material
tools/                    research and ISO scanning tools
docs/                     protocol notes and current status
```

## Historical certificates

Some experiments use public certificates found while researching old EyeToy: Chat material. Those original Sony/SCEE files are **not included in this repository**.

The server can still run without them. If you are doing your own research and have the same material from your own copy, see [docs/HISTORICAL_CERTS.md](docs/HISTORICAL_CERTS.md).

## Contributing

Packet captures, protocol notes and tests on real PS2 hardware are welcome. If you discover a new message layout or a different behaviour, open an issue and include enough information to reproduce it.

## Disclaimer

This is an unofficial preservation and interoperability project. It is not affiliated with Sony Interactive Entertainment or Sony Computer Entertainment Europe.


