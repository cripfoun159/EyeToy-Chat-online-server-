# EyeToy Chat Community Server 0.3.0-beta1

Community server implementation for the PAL EyeToy: Chat restoration project.

This release is intended for a public VPS deployment where Apache2 and BIND9
are already used by other PS2 online projects.

## VPS layout

```text
Internet
  |
  +-- Apache2 :80 / :443       existing services
  |
  +-- Apache2 :10443           plain HTTP for EyeToy Chat
          |
          +--> 127.0.0.1:18080  EyeToy Chat HTTP service
  |
  +-- BIND9 :53                existing DNS service
  |
  +-- EyeToy Medius             historical TCP/UDP ports
```

The public EyeToy HTTP endpoint is **plain HTTP on port 10443**. There is no
TLS listener in this deployment profile. Apache does not need to terminate
TLS for EyeToy Chat.

The Python server therefore does not bind :80, :443, :10443 or :53.

## DNS

Add these three A records to the existing BIND9 configuration:

- `eyetoychat-master.online.scee.com`
- `eyetoychat-update.online.scee.com`
- `vmail.online.scee.com`

They should point to the VPS public IPv4.

See `deploy/bind9/eyetoychat.conf.example`.

## Apache2

Enable the normal reverse-proxy modules:

```sh
a2enmod proxy proxy_http
```

Install the example vhost from `deploy/apache2/eyetoychat-10443.conf`, then reload
Apache.

Port 10443 is deliberately not an SSL virtual host.

## Server

Run the self-test:

```sh
python3 server.py --selftest
```

Start:

```sh
python3 server.py
```

For a VPS installation, use `deploy/install-vps.sh` and the supplied systemd
unit.

## Included functionality

The current implementation includes the previously working Medius login,
MUIS/MAS/MLS path, multilingual room hierarchy, TEXT256 rooms, room-scoped
chat/presence, buddy/social state, ignore/block handling, profiles, VideoMail
HTTP handling, AdFeed, NAT reflection and opaque BinaryMessage capture/relay.

The ISO research additions include capture/diagnostic support for:

- VOICE16
- CreateGame / JoinGame / GameWorld traffic
- JoinP2P / DME / StreamMedia investigation
- ETChatPhotosMediusGame
- photo and thumbnail requests
- incoming/outgoing call signalling
- Battleships / Chess / Checkers
- announcements
- locations
- usage policy
- ScreenSaver
- patch/update traffic

These research paths are intentionally capture-driven. The server does not
invent unverified DME, StreamMedia or game packet responses.

## Public repository hygiene

Do not commit:

- `logs/`
- `media_store/`
- `social_state.json`
- private keys
- local VPS configuration
- personal test captures

The repository contains no private TLS key material.

## Historical compatibility

The PS2 client is an old HTTP/1.0/Medius client. Keep the Apache proxy simple:
no authentication layer, no HTTP/2 requirement and no TLS on :10443.
