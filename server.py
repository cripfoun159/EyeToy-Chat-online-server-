#!/usr/bin/env python3
"""
EyeToy: Chat PS2 - Community Server V032 - fixed MAS disconnect-state diagnostics
No third-party dependencies.

Purpose:
- Keep the working EyeToy Chat DNS / update / MUIS path.
- Advertise an active EyeToy Chat universe and route the game to MAS TCP/10075.
- Perform the PS2 SCERT crypto/connect handshake on MAS.
- Answer Lobby/0x03 MediusSessionBeginRequest with Lobby/0x04 success.
- Keep V019's proven Lobby/0x86 -> Lobby/0x87 VersionServer response unchanged.
- Keep V020's accepted post-VersionServer replies for class4/0x0A and
  SetLocalizationParams 0xA3/0xA4.
- Lock MediusGetPolicyResponse 0x48 to the pad_before_287 layout accepted by
  the V023 trace.
- Accept EyeToy's legacy TLS 1.0 connection on TCP/10443 with a tiny pure-Python
  TLS_RSA_WITH_RC4_128_SHA endpoint, decrypt the next HTTPS request, and answer
  it with the same local HTTP content engine.

Important:
V019 proved the 79-byte VersionServer response is accepted by EyeToy. V020 then
proved EyeToy advances after the 0x0B and 0xA4 replies. V021 reached 0x47 and
sent a 290-byte 0x48, but EyeToy displayed "Impossible de récupérer règles
d'usage". V023 showed that packed_284 is retried but pad_before_287 stops the 0x47 loop.
Immediately afterwards EyeToy opens TLS 1.0 to eyetoychat-update.online.scee.com
on TCP/10443. V030 keeps the accepted 0x48 layout and targets that
new TLS stage.
"""

import argparse
import asyncio
import datetime as dt
import json
import hashlib
import hmac
import os
import socket
import select
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
HTTP_ROOT = ROOT / "http_root"
PRINT_LOCK = threading.Lock()
VERSION = "V031"

# These names are forced in code on purpose. V003 could accidentally run with an
# older config.json, which caused gate1.eu.dnas.playstation.org to be forwarded
# upstream and return NXDOMAIN (-611 on the PS2).
FORCED_DNS_EXACT = {
    "eyetoychat-master.online.scee.com",
    "eyetoychat-update.online.scee.com",
    "vmail.online.scee.com",
}
FORCED_DNS_SUFFIXES = ()

def normalize_dns_name(name: str) -> str:
    return name.strip().lower().rstrip(".")

def is_forced_dns_name(name: str, configured=()):
    n = normalize_dns_name(name)
    configured_set = {normalize_dns_name(x) for x in configured}
    return n in FORCED_DNS_EXACT or n in configured_set or any(n.endswith(s) for s in FORCED_DNS_SUFFIXES)


def now():
    return dt.datetime.now().astimezone().isoformat(timespec="milliseconds")


def safe_print(*args, **kwargs):
    with PRINT_LOCK:
        print(*args, **kwargs, flush=True)


def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def local_ipv4():
    # Find the LAN address used for outbound traffic without sending data.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
    except OSError:
        ip = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()
    return ip


def hexdump(data: bytes, width=16, limit=8192):
    data = data[:limit]
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off+width]
        hx = " ".join(f"{b:02X}" for b in chunk)
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04X}  {hx:<{width*3}}  {txt}")
    return "\n".join(lines)


def ensure_dirs(cfg):
    (ROOT / cfg.get("log_dir", "logs")).mkdir(parents=True, exist_ok=True)
    HTTP_ROOT.mkdir(parents=True, exist_ok=True)


def log_event(cfg, kind, text, payload=None):
    log_dir = ROOT / cfg.get("log_dir", "logs")
    stamp = dt.datetime.now().strftime("%Y%m%d")
    path = log_dir / f"eyetoy_{stamp}.log"
    msg = f"[{now()}] [{kind}] {text}\n"
    if payload is not None:
        msg += hexdump(payload, limit=int(cfg.get("log_payload_limit", 8192))) + "\n"
    with path.open("a", encoding="utf-8", errors="replace") as f:
        f.write(msg)
    safe_print(msg.rstrip())


# ---------------- DNS ----------------

def parse_dns_name(packet: bytes, offset=12):
    labels = []
    i = offset
    while i < len(packet):
        ln = packet[i]
        i += 1
        if ln == 0:
            break
        if ln & 0xC0:
            raise ValueError("compressed DNS name not expected in question")
        if i + ln > len(packet):
            raise ValueError("truncated DNS question")
        labels.append(packet[i:i+ln].decode("ascii", errors="replace"))
        i += ln
    if i + 4 > len(packet):
        raise ValueError("missing QTYPE/QCLASS")
    qtype, qclass = struct.unpack("!HH", packet[i:i+4])
    return ".".join(labels).lower(), qtype, qclass, i + 4


def build_a_response(query: bytes, answer_ip: str):
    """Build a conservative recursive-resolver style reply for an overridden host.

    V001 used AA=1/RA=0. Some old Sony network stacks are strict about resolver
    flags, so V002 behaves like the recursive DNS server configured by the user:
    QR=1, RD copied, RA=1, AA=0, RCODE=NOERROR.
    """
    if len(query) < 12:
        raise ValueError("short DNS query")
    tid = query[:2]
    flags = struct.unpack("!H", query[2:4])[0]
    qdcount = struct.unpack("!H", query[4:6])[0]
    if qdcount != 1:
        raise ValueError(f"unsupported QDCOUNT={qdcount}")
    _, qtype, qclass, qend = parse_dns_name(query)

    # QR=1; preserve OPCODE and RD; RA=1; NOERROR. Do not claim authority.
    response_flags = 0x8000 | (flags & 0x7800) | (flags & 0x0100) | 0x0080
    # A (1) or ANY (255) receives our IPv4 override. Other types get NODATA.
    ancount = 1 if qclass == 1 and qtype in (1, 255) else 0
    header = tid + struct.pack("!HHHHH", response_flags, 1, ancount, 0, 0)
    question = query[12:qend]
    if ancount:
        rdata = socket.inet_aton(answer_ip)
        # Repeat the full QNAME instead of a compression pointer. Slightly larger,
        # but maximally simple for old clients.
        qname_wire = query[12:qend-4]
        answer = qname_wire + struct.pack("!HHIH", 1, 1, 60, len(rdata)) + rdata
    else:
        answer = b""
    return header + question + answer


def detect_dns_upstreams(configured):
    """Return usable IPv4 recursive DNS servers, preferring the Windows adapter."""
    if configured and str(configured).lower() != "auto":
        values = configured if isinstance(configured, list) else [configured]
        return [str(x) for x in values]

    found = []
    if os.name == "nt":
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "(Get-DnsClientServerAddress -AddressFamily IPv4 | "
                "Where-Object {$_.ServerAddresses.Count -gt 0}).ServerAddresses | "
                "Select-Object -Unique"
            ]
            out = subprocess.check_output(cmd, text=True, timeout=5, errors="ignore")
            for line in out.splitlines():
                ip = line.strip()
                try:
                    socket.inet_aton(ip)
                except OSError:
                    continue
                if ip not in ("0.0.0.0", "127.0.0.1") and ip not in found:
                    found.append(ip)
        except Exception:
            pass

    # Public fallbacks only if adapter discovery fails or the first resolver is unavailable.
    for ip in ("1.1.1.1", "8.8.8.8"):
        if ip not in found:
            found.append(ip)
    return found


def forward_dns_udp(data: bytes, upstreams, port=53, timeout=1.5):
    last_error = None
    for upstream in upstreams:
        us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        us.settimeout(timeout)
        try:
            us.sendto(data, (upstream, port))
            resp, _ = us.recvfrom(65535)
            return resp, upstream
        except OSError as e:
            last_error = e
        finally:
            us.close()
    raise OSError(f"aucun DNS upstream ne répond: {last_error}")


def first_a_from_dns(packet: bytes):
    """Best-effort extraction of the first IPv4 A record from a DNS response."""
    try:
        if len(packet) < 12:
            return None
        qd, an = struct.unpack("!HH", packet[4:8])
        off = 12
        # Skip questions (normal queries here contain one uncompressed QNAME).
        for _ in range(qd):
            while off < len(packet):
                ln = packet[off]
                if ln == 0:
                    off += 1
                    break
                if ln & 0xC0:
                    off += 2
                    break
                off += 1 + ln
            off += 4
        for _ in range(an):
            if off >= len(packet): return None
            if packet[off] & 0xC0:
                off += 2
            else:
                while off < len(packet):
                    ln=packet[off]; off += 1
                    if ln == 0: break
                    off += ln
            if off + 10 > len(packet): return None
            typ, cls, ttl, rdlen = struct.unpack("!HHIH", packet[off:off+10])
            off += 10
            if off + rdlen > len(packet): return None
            rdata=packet[off:off+rdlen]
            if typ == 1 and cls == 1 and rdlen == 4:
                return socket.inet_ntoa(rdata)
            off += rdlen
    except Exception:
        return None
    return None


class DNSServer(threading.Thread):
    daemon = True
    def __init__(self, cfg, advertise_ip):
        super().__init__(name="DNS-UDP")
        self.cfg = cfg
        self.advertise_ip = advertise_ip
        self.names = {normalize_dns_name(x) for x in cfg.get("dns_names", [])} | FORCED_DNS_EXACT
        self.upstreams = detect_dns_upstreams(cfg.get("dns_upstream", "auto"))
        self.sock = None

    def process(self, data, addr):
        try:
            name, qtype, qclass, _ = parse_dns_name(data)
        except Exception as e:
            log_event(self.cfg, "DNS", f"paquet invalide de {addr}: {e}", data)
            return None

        log_event(self.cfg, "DNS-QUERY", f"{addr[0]}:{addr[1]} -> {name} type={qtype} class={qclass}", data)
        if addr[0] == self.advertise_ip:
            log_event(self.cfg, "DNS-NOTE", f"La requête vient de {addr[0]}, qui est aussi l’IP du PC serveur. Cela peut être PCSX2 lancé sur ce PC, test_dns/nslookup, ou un autre processus local.")
        n = normalize_dns_name(name)
        dnas_names = {normalize_dns_name(x) for x in self.cfg.get("dnas_names", [])}
        is_dnas = n in dnas_names or n.endswith(".dnas.playstation.org")

        # V008: DO NOT point DNAS to this PC. Ask the PS2 community DNS for the
        # current DNAS address and return its reply unchanged to the console.
        if is_dnas:
            dnas_upstreams = self.cfg.get("dnas_dns_upstreams", ["45.7.228.197"])
            if isinstance(dnas_upstreams, str):
                dnas_upstreams = [dnas_upstreams]
            try:
                response, upstream = forward_dns_udp(
                    data, dnas_upstreams,
                    int(self.cfg.get("dns_upstream_port", 53)),
                    float(self.cfg.get("dnas_dns_timeout", 3.0))
                )
                target = first_a_from_dns(response)
                suffix = f" -> DNAS {target}" if target else ""
                log_event(self.cfg, "DNAS-DNS-PASSTHRU",
                          f"{addr[0]}:{addr[1]} demande {name} via DNS {upstream}{suffix}", response)
                return response
            except OSError as e:
                log_event(self.cfg, "DNAS-DNS-FAIL", f"échec DNS communautaire pour {name}: {e}")
                return None

        # EyeToy/SCEE service names still point to this local PC.
        if is_forced_dns_name(name, self.names):
            response = build_a_response(data, self.advertise_ip)
            log_event(self.cfg, "DNS-HIT", f"{addr[0]}:{addr[1]} demande {name} type={qtype} -> {self.advertise_ip}", response)
            return response

        try:
            response, upstream = forward_dns_udp(
                data, self.upstreams,
                int(self.cfg.get("dns_upstream_port", 53)),
                float(self.cfg.get("dns_timeout", 1.5))
            )
            log_event(self.cfg, "DNS-FWD", f"{addr[0]}:{addr[1]} demande {name} type={qtype} via {upstream}", response)
            return response
        except OSError as e:
            log_event(self.cfg, "DNS-FWD", f"échec upstream pour {name}: {e}")
            return None

    def run(self):
        bind_ip = self.cfg.get("bind_ip", "0.0.0.0")
        port = int(self.cfg.get("dns_port", 53))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((bind_ip, port))
        except OSError as e:
            log_event(self.cfg, "ERROR", f"DNS UDP impossible sur {bind_ip}:{port}: {e}")
            return
        log_event(self.cfg, "DNS", f"UDP écoute sur {bind_ip}:{port}; EyeToy -> {self.advertise_ip}; upstreams={self.upstreams}")
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
                response = self.process(data, addr)
                if response:
                    self.sock.sendto(response, addr)
            except Exception as e:
                log_event(self.cfg, "ERROR", f"boucle DNS UDP: {e}")


class DNSTCPServer(threading.Thread):
    """RFC-style DNS over TCP. Old clients normally use UDP, but supporting TCP
    removes another possible source of the PS2 -611 validation failure."""
    daemon = True
    def __init__(self, cfg, advertise_ip):
        super().__init__(name="DNS-TCP")
        self.cfg = cfg
        self.worker = DNSServer(cfg, advertise_ip)

    def run(self):
        bind_ip = self.cfg.get("bind_ip", "0.0.0.0")
        port = int(self.cfg.get("dns_port", 53))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((bind_ip, port))
            s.listen(16)
        except OSError as e:
            log_event(self.cfg, "ERROR", f"DNS TCP impossible sur {bind_ip}:{port}: {e}")
            return
        log_event(self.cfg, "DNS", f"TCP écoute sur {bind_ip}:{port}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def handle(self, conn, addr):
        conn.settimeout(5)
        try:
            hdr = conn.recv(2)
            if len(hdr) != 2:
                return
            need = struct.unpack("!H", hdr)[0]
            data = b""
            while len(data) < need:
                chunk = conn.recv(need - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) != need:
                log_event(self.cfg, "DNS-TCP", f"requête tronquée de {addr}", data)
                return
            response = self.worker.process(data, addr)
            if response:
                conn.sendall(struct.pack("!H", len(response)) + response)
        except Exception as e:
            log_event(self.cfg, "ERROR", f"DNS TCP {addr}: {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass


# ---------------- HTTP / TCP capture ----------------

def guess_tls(data: bytes):
    if len(data) >= 3 and data[0] in (0x14, 0x15, 0x16, 0x17):
        version = {0x0300: "SSLv3", 0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2"}.get(
            int.from_bytes(data[1:3], "big"), f"0x{data[1:3].hex()}"
        )
        return version
    return None


def build_update_index(cfg):
    """Generate the update catalogue format expected by EyeToy: Chat.

    Reverse engineering of MAINGAME.MSN shows that BUILD is a *numeric root
    attribute*.  The client only enumerates mkdir/update/pad entries when the
    server BUILD is greater than the local build.  BUILD <= 194 therefore means
    "no newer update" for this SCES-52154 while still letting the XML parser complete normally.
    """
    mode = str(cfg.get("update_mode", "no_update")).strip().lower()
    build = int(cfg.get("update_build", 194))
    if mode == "no_update":
        # 0xC2 / 194 is the exact local build returned by this SCES-52154.
        build = int(cfg.get("update_build", 194))
    # CRLF is deliberately conservative for an old HTTP/XML client.
    return (f'<?xml version="1.0" encoding="UTF-8"?>\r\n'
            f'<patches BUILD="{build}"/>\r\n').encode("utf-8")


def make_http_response(status_line: bytes, ctype: bytes, body: bytes, method: str):
    headers = (
        b"Content-Type: " + ctype + b"\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"Cache-Control: no-cache\r\n"
        b"Connection: close\r\n\r\n"
    )
    return status_line + headers + (b"" if method.upper() == "HEAD" else body)


def http_response_for(request: bytes, cfg):
    try:
        head = request.decode("iso-8859-1", errors="replace")
        first = head.splitlines()[0]
        method, target, _ = first.split(" ", 2)
        path = urlsplit(target).path
    except Exception:
        return None, None, None

    method = method.upper()
    if method not in {"GET", "HEAD"}:
        body = b"EyeToy Chat Local Server V011\n"
        response = make_http_response(b"HTTP/1.0 200 OK\r\n", b"text/plain", body, method)
        return response, path, body

    # Critical endpoint: never depend on a stale file left from V007.
    if path.rstrip("/").lower() == "/qa_patches/index.xml":
        body = build_update_index(cfg)
        response = make_http_response(b"HTTP/1.0 200 OK\r\n", b"text/xml; charset=UTF-8", body, method)
        return response, path, body

    rel = path.lstrip("/") or "index.txt"
    candidate = (HTTP_ROOT / rel).resolve()
    try:
        candidate.relative_to(HTTP_ROOT.resolve())
    except ValueError:
        candidate = HTTP_ROOT / "index.txt"
    if candidate.is_file():
        body = candidate.read_bytes()
        ctype = b"text/xml; charset=UTF-8" if candidate.suffix.lower() == ".xml" else b"text/plain"
        status = b"HTTP/1.0 200 OK\r\n"
    else:
        body = b"EyeToy Chat Local Server V014\nNo content for this path yet.\n"
        ctype = b"text/plain"
        status = b"HTTP/1.0 404 Not Found\r\n"
    return make_http_response(status, ctype, body, method), path, body



# --- V031 cross-service disconnect-state diagnostics ---------------------------
# TLS/10443 and MAS/10075 run in separate threads.  EyeToy keeps MAS alive after
# a fatal TLS certificate alert, so V031 records the alert by client IP and lets
# the MAS thread perform a controlled socket-close experiment after a short grace.
_TLS_FAILURES = {}
_TLS_FAILURES_LOCK = threading.Lock()

def v031_note_tls_failure(client_ip: str, profile: str, alert_text: str) -> None:
    with _TLS_FAILURES_LOCK:
        _TLS_FAILURES[str(client_ip)] = {
            "time": time.time(), "profile": str(profile), "alert": str(alert_text), "consumed": False
        }

def v031_get_tls_failure(client_ip: str):
    with _TLS_FAILURES_LOCK:
        item = _TLS_FAILURES.get(str(client_ip))
        return dict(item) if item else None

def v031_consume_tls_failure(client_ip: str) -> None:
    with _TLS_FAILURES_LOCK:
        if str(client_ip) in _TLS_FAILURES:
            _TLS_FAILURES[str(client_ip)]["consumed"] = True

# --- EyeToy legacy TLS 1.0 update endpoint (V031) ------------------------------
#
# The V023 trace proves that after the second PolicyResponse (pad_before_287),
# EyeToy opens a TLS 1.0 connection to eyetoychat-update.online.scee.com:10443.
# Modern OpenSSL builds often disable the only cipher suites advertised by this
# 2004 client (RC4/3DES), so V030 keeps the tiny TLS subset and adds trust-anchor diagnostics in
# Python instead of depending on the host OpenSSL configuration.
#
# Implemented path:
#   TLS 1.0 + TLS_RSA_WITH_RC4_128_SHA (0x0005)
#   RSA PKCS#1 v1.5 ClientKeyExchange
#   TLS 1.0 MD5/SHA1 PRF
#   HMAC-SHA1 record authentication
#   RC4 record protection
#   HTTP request capture + local HTTP response over the encrypted channel
#
# This is a compatibility probe for the local EyeToy client, not a general TLS
# server. It intentionally supports only the exact legacy flow observed here.
TLS10_VERSION = b"\x03\x01"
TLS_CONTENT_CHANGE_CIPHER_SPEC = 20
TLS_CONTENT_ALERT = 21
TLS_CONTENT_HANDSHAKE = 22
TLS_CONTENT_APPLICATION_DATA = 23
TLS_HS_CLIENT_HELLO = 1
TLS_HS_SERVER_HELLO = 2
TLS_HS_CERTIFICATE = 11
TLS_HS_SERVER_HELLO_DONE = 14
TLS_HS_CLIENT_KEY_EXCHANGE = 16
TLS_HS_FINISHED = 20
TLS_RSA_WITH_RC4_128_SHA = 0x0005
TLS_RSA_WITH_RC4_128_MD5 = 0x0004
TLS_CERT_DER_PATH = ROOT / "tls" / "update_server.der"
TLS_CERT_PROFILES = {
    # Original V024 self-signed certificate.
    "selfsigned_v024": [ROOT / "tls" / "update_server.der"],
    # Minimal legacy-style SHA1/RSA certificate, exact historical hostname,
    # broad validity window, almost no X.509 extensions.
    "legacy_minimal": [ROOT / "tls" / "legacy_v1_wide.der"],
    # Same RSA key/hostname but with normal serverAuth/SAN/keyUsage extensions.
    "legacy_v3_san": [ROOT / "tls" / "legacy_v3_san.der"],
    # Explicit leaf + local CA chain. This is diagnostic only: the generated CA
    # is not expected to be trusted by EyeToy, but it tells us whether the old
    # parser behaves differently when a chain is present.
    "generated_chain": [ROOT / "tls" / "generated_chain_leaf.der", ROOT / "tls" / "generated_ca.der"],
    # Exact SCEE MIS root CA extracted from the EyeToy Chat Europe beta (2004-05-10).
    # Diagnostic probe only: the client disc contains the public CA certificate but
    # not its private key, so this profile can prove trust if ClientKeyExchange is
    # reached, but it cannot complete the RSA handshake.
    "historical_scee_root_probe": [ROOT / "tls" / "scee_mis_root_2002.der"],
    # Second self-signed CA-like certificate found in the same beta image.
    # CN=43.194.211.76, O=Test Cert, RSA-2048, MD5/RSA, CA:TRUE.
    # It is associated with beta-era endpoints/strings and is a diagnostic
    # trust-anchor probe only; its private key was not found in the client image.
    "beta_test_ca_probe": [ROOT / "tls" / "beta_test_ca_43.194.211.76.der"],
}
TLS_CERT_STATE_PATH = ROOT / "tls" / "cert_diagnostics_state.json"
TLS_CERT_LEGACY_STATE_PATH = ROOT / "tls" / "cert_cycle_state.txt"

# Private half matching tls/update_server.der. This is an intentionally local,
# self-signed compatibility certificate bundled only to terminate the legacy
# EyeToy update TLS connection.
TLS_RSA_N = int(
    "a1f2e44ee27f6d89d58c6b984090f67e21fa73311572447dc8a3cf054ae4ee13"
    "6e369a8a59f1fcd9d976c99b9bd281e3e053613ab7deb59006a08d8fc13c3fe5"
    "b3b12727b6fa96f3baf1ecfbeeb5b4e5bc2b3773aee7ca39572638376b65fc4c"
    "dad6634ca4793bfdd5267e1b374e38e68d145a7e721649189a9d547cffd4d451",
    16,
)
TLS_RSA_D = int(
    "653dbcf07bb401bc6b1daf9dacaf73090320d8a654abec995db6da128af176cb"
    "fad873e00dbeb3bd54af67f5b981ede591354ed130652fc7ebfcaec2b1a082a8"
    "8da1585b758a25372159a28583683296565a8b52f1b54891e5133c2bcc1bcd1b"
    "01f1817d7becb5b871a4f3222cd3261a3bb273e08146a74a3adfb6443438f509",
    16,
)
TLS_RSA_E = 65537
TLS_RSA_K = (TLS_RSA_N.bit_length() + 7) // 8

TLS_ALERT_DESCRIPTIONS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 70: "protocol_version",
    71: "insufficient_security", 80: "user_canceled", 90: "user_canceled",
}


def _tls_u24(n: int) -> bytes:
    return int(n).to_bytes(3, "big")


def _tls_hs(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type & 0xFF]) + _tls_u24(len(body)) + body


def _tls_record(content_type: int, payload: bytes, version: bytes = TLS10_VERSION) -> bytes:
    return bytes([content_type & 0xFF]) + version + struct.pack("!H", len(payload)) + payload


def _recv_exact(conn, count: int) -> bytes:
    out = bytearray()
    while len(out) < count:
        chunk = conn.recv(count - len(out))
        if not chunk:
            raise EOFError(f"socket fermée ({len(out)}/{count} octets)")
        out += chunk
    return bytes(out)


def _tls_recv_record(conn):
    hdr = _recv_exact(conn, 5)
    length = struct.unpack("!H", hdr[3:5])[0]
    if length > 18432:
        raise ValueError(f"record TLS anormalement long: {length}")
    payload = _recv_exact(conn, length)
    return hdr[0], hdr[1:3], payload, hdr + payload


def _tls_iter_handshakes(payload: bytes):
    off = 0
    while off + 4 <= len(payload):
        n = int.from_bytes(payload[off+1:off+4], "big")
        end = off + 4 + n
        if end > len(payload):
            break
        raw = payload[off:end]
        yield raw[0], raw[4:], raw
        off = end
    return off


def _tls_parse_client_hello(payload: bytes):
    items = list(_tls_iter_handshakes(payload))
    if not items or items[0][0] != TLS_HS_CLIENT_HELLO:
        raise ValueError("premier record TLS sans ClientHello complet")
    _, body, raw = items[0]
    if len(body) < 2 + 32 + 1:
        raise ValueError("ClientHello trop court")
    version = body[:2]
    client_random = body[2:34]
    off = 34
    sid_len = body[off]; off += 1
    off += sid_len
    if off + 2 > len(body):
        raise ValueError("ClientHello tronqué avant cipher_suites")
    suites_len = struct.unpack("!H", body[off:off+2])[0]; off += 2
    if off + suites_len > len(body) or suites_len % 2:
        raise ValueError("liste cipher_suites ClientHello invalide")
    suites = [struct.unpack("!H", body[i:i+2])[0] for i in range(off, off+suites_len, 2)]
    off += suites_len
    compression = []
    if off < len(body):
        comp_len = body[off]; off += 1
        compression = list(body[off:off+comp_len])
    return {
        "version": version,
        "client_random": client_random,
        "cipher_suites": suites,
        "compression": compression,
        "handshake_raw": raw,
    }


def _tls_p_hash(secret: bytes, seed: bytes, hash_name: str, size: int) -> bytes:
    digestmod = getattr(hashlib, hash_name)
    a = seed
    out = bytearray()
    while len(out) < size:
        a = hmac.new(secret, a, digestmod).digest()
        out += hmac.new(secret, a + seed, digestmod).digest()
    return bytes(out[:size])


def tls10_prf(secret: bytes, label: bytes, seed: bytes, size: int) -> bytes:
    # TLS 1.0 PRF = P_MD5(S1, label+seed) XOR P_SHA1(S2, label+seed).
    half = (len(secret) + 1) // 2
    s1 = secret[:half]
    s2 = secret[len(secret)-half:]
    full_seed = label + seed
    a = _tls_p_hash(s1, full_seed, "md5", size)
    b = _tls_p_hash(s2, full_seed, "sha1", size)
    return bytes(x ^ y for x, y in zip(a, b))


class TLSRC4:
    def __init__(self, key: bytes):
        if not key:
            raise ValueError("clé RC4 vide")
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        self.s = s
        self.i = 0
        self.j = 0

    def crypt(self, data: bytes) -> bytes:
        s = self.s
        i = self.i
        j = self.j
        out = bytearray(len(data))
        for n, val in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) & 0xFF]
            out[n] = val ^ k
        self.i = i
        self.j = j
        return bytes(out)


class TLS10RC4RecordCipher:
    def __init__(self, mac_secret: bytes, key: bytes, mac_name: str):
        self.mac_secret = mac_secret
        self.stream = TLSRC4(key)
        self.mac_name = mac_name
        self.mac_len = hashlib.new(mac_name).digest_size
        self.seq = 0

    def _mac(self, content_type: int, version: bytes, plain: bytes) -> bytes:
        hdr = self.seq.to_bytes(8, "big") + bytes([content_type]) + version + struct.pack("!H", len(plain))
        return hmac.new(self.mac_secret, hdr + plain, getattr(hashlib, self.mac_name)).digest()

    def encrypt(self, content_type: int, version: bytes, plain: bytes) -> bytes:
        mac = self._mac(content_type, version, plain)
        self.seq += 1
        return self.stream.crypt(plain + mac)

    def decrypt(self, content_type: int, version: bytes, ciphertext: bytes):
        decoded = self.stream.crypt(ciphertext)
        if len(decoded) < self.mac_len:
            self.seq += 1
            raise ValueError("record RC4 trop court pour le MAC")
        plain = decoded[:-self.mac_len]
        got = decoded[-self.mac_len:]
        expected = self._mac(content_type, version, plain)
        self.seq += 1
        return plain, hmac.compare_digest(got, expected), got, expected


def _tls_rsa_pkcs1_v15_decrypt(ciphertext: bytes) -> bytes:
    if len(ciphertext) != TLS_RSA_K:
        # Left-pad shorter encodings; reject oversized ones.
        if len(ciphertext) > TLS_RSA_K:
            raise ValueError(f"RSA ClientKeyExchange {len(ciphertext)} octets > modulus {TLS_RSA_K}")
        ciphertext = ciphertext.rjust(TLS_RSA_K, b"\x00")
    c = int.from_bytes(ciphertext, "big")
    if c >= TLS_RSA_N:
        raise ValueError("RSA ciphertext >= modulus")
    em = pow(c, TLS_RSA_D, TLS_RSA_N).to_bytes(TLS_RSA_K, "big")
    if len(em) < 11 or not em.startswith(b"\x00\x02"):
        raise ValueError("padding RSA PKCS#1 v1.5 invalide")
    sep = em.find(b"\x00", 2)
    if sep < 10:
        raise ValueError("padding RSA PKCS#1 v1.5 trop court")
    premaster = em[sep+1:]
    if len(premaster) != 48:
        raise ValueError(f"PreMasterSecret longueur inattendue: {len(premaster)}")
    return premaster


def _tls_finished_verify(master: bytes, label: bytes, transcript: bytes) -> bytes:
    seed = hashlib.md5(transcript).digest() + hashlib.sha1(transcript).digest()
    return tls10_prf(master, label, seed, 12)


def _tls_key_schedule(premaster: bytes, client_random: bytes, server_random: bytes, suite: int):
    master = tls10_prf(premaster, b"master secret", client_random + server_random, 48)
    if suite == TLS_RSA_WITH_RC4_128_SHA:
        mac_name, mac_len = "sha1", 20
    elif suite == TLS_RSA_WITH_RC4_128_MD5:
        mac_name, mac_len = "md5", 16
    else:
        raise ValueError(f"suite TLS non supportée: 0x{suite:04X}")
    key_block_len = mac_len * 2 + 16 * 2
    kb = tls10_prf(master, b"key expansion", server_random + client_random, key_block_len)
    off = 0
    client_mac = kb[off:off+mac_len]; off += mac_len
    server_mac = kb[off:off+mac_len]; off += mac_len
    client_key = kb[off:off+16]; off += 16
    server_key = kb[off:off+16]
    return master, TLS10RC4RecordCipher(client_mac, client_key, mac_name), TLS10RC4RecordCipher(server_mac, server_key, mac_name)


def _tls_alert_text(payload: bytes) -> str:
    if len(payload) < 2:
        return f"alert tronquée: {payload.hex()}"
    level, desc = payload[0], payload[1]
    return f"level={level} description={desc} ({TLS_ALERT_DESCRIPTIONS.get(desc, 'inconnue')})"


def _tls_state_path(cfg):
    raw = str(cfg.get("update_tls_cert_state_file", "tls/cert_diagnostics_state.json")).strip()
    p = Path(raw)
    if not p.is_absolute():
        p = ROOT / p
    return p


def _tls_default_cert_state(profiles):
    return {
        "version": 1,
        "accepted_profile": None,
        "attempts": 0,
        "profiles": {p: "untested" for p in profiles},
        "history": [],
        "last_selected": None,
        "last_result": None,
    }


def _tls_load_cert_state(cfg, profiles):
    path = _tls_state_path(cfg)
    state = _tls_default_cert_state(profiles)
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            state.update({k: v for k, v in loaded.items() if k != "profiles"})
            got_profiles = loaded.get("profiles", {})
            if isinstance(got_profiles, dict):
                for p in profiles:
                    v = str(got_profiles.get(p, "untested"))
                    state["profiles"][p] = v if v in ("untested", "rejected", "accepted", "error", "trusted_probe") else "untested"
    except Exception:
        pass
    # Keep only currently configured profiles in the active status map.
    state["profiles"] = {p: state.get("profiles", {}).get(p, "untested") for p in profiles}
    if state.get("accepted_profile") not in profiles:
        state["accepted_profile"] = None
    if not isinstance(state.get("history"), list):
        state["history"] = []
    try:
        state["attempts"] = int(state.get("attempts", 0))
    except Exception:
        state["attempts"] = 0
    return state


def _tls_save_cert_state(cfg, state):
    path = _tls_state_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _tls_cert_state_summary(state, profiles):
    return ", ".join(f"{p}={state.get('profiles', {}).get(p, 'untested')}" for p in profiles)


def _tls_choose_cert_profile(cfg):
    configured = cfg.get("update_tls_cert_profiles", list(TLS_CERT_PROFILES))
    profiles = [str(x).strip() for x in configured if str(x).strip() in TLS_CERT_PROFILES]
    if not profiles:
        profiles = list(TLS_CERT_PROFILES)
    requested = str(cfg.get("update_tls_cert_profile", "auto_cycle")).strip()
    if requested and requested != "auto_cycle":
        if requested not in TLS_CERT_PROFILES:
            raise ValueError(f"update_tls_cert_profile inconnu: {requested!r}")
        return requested, None, profiles, None, False

    state = _tls_load_cert_state(cfg, profiles)
    accepted = state.get("accepted_profile")
    exhausted = False
    if accepted in profiles:
        profile = accepted
    else:
        profile = next((p for p in profiles if state["profiles"].get(p) not in ("rejected", "trusted_probe")), None)
        if profile is None:
            exhausted = True
            profile = profiles[0]
    slot = profiles.index(profile)
    state["attempts"] = int(state.get("attempts", 0)) + 1
    state["last_selected"] = profile
    state["last_result"] = "selected"
    _tls_save_cert_state(cfg, state)
    return profile, slot, profiles, state, exhausted


def _tls_mark_cert_result(cfg, profile, result, detail=""):
    configured = cfg.get("update_tls_cert_profiles", list(TLS_CERT_PROFILES))
    profiles = [str(x).strip() for x in configured if str(x).strip() in TLS_CERT_PROFILES]
    if not profiles:
        profiles = list(TLS_CERT_PROFILES)
    state = _tls_load_cert_state(cfg, profiles)
    if profile in state["profiles"]:
        state["profiles"][profile] = result
    if result == "accepted":
        state["accepted_profile"] = profile
    state["last_selected"] = profile
    state["last_result"] = result
    state["history"].append({
        "time": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "profile": profile,
        "result": result,
        "detail": detail,
    })
    state["history"] = state["history"][-32:]
    _tls_save_cert_state(cfg, state)
    return state, profiles


def _tls_log_persistent_state(cfg):
    configured = cfg.get("update_tls_cert_profiles", list(TLS_CERT_PROFILES))
    profiles = [str(x).strip() for x in configured if str(x).strip() in TLS_CERT_PROFILES]
    if not profiles:
        profiles = list(TLS_CERT_PROFILES)
    state = _tls_load_cert_state(cfg, profiles)
    accepted = state.get("accepted_profile")
    nxt = accepted or next((p for p in profiles if state["profiles"].get(p) not in ("rejected", "trusted_probe")), None)
    exhausted = nxt is None
    log_event(cfg, "UPDATE-TLS-CERT-STATE", f"persistant={_tls_state_path(cfg)}; {_tls_cert_state_summary(state, profiles)}; accepted={accepted}; next={nxt}; exhausted={exhausted}")
    return state, profiles

def _tls_load_cert_chain(profile):
    paths = TLS_CERT_PROFILES[profile]
    ders = []
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"certificat V030 absent: {path}")
        ders.append(path.read_bytes())
    return ders


def _tls_send_server_flight(conn, client_hello, cfg):
    offered = client_hello["cipher_suites"]
    preferred = int(cfg.get("update_tls_cipher", TLS_RSA_WITH_RC4_128_SHA))
    if preferred in offered and preferred in (TLS_RSA_WITH_RC4_128_SHA, TLS_RSA_WITH_RC4_128_MD5):
        suite = preferred
    elif TLS_RSA_WITH_RC4_128_SHA in offered:
        suite = TLS_RSA_WITH_RC4_128_SHA
    elif TLS_RSA_WITH_RC4_128_MD5 in offered:
        suite = TLS_RSA_WITH_RC4_128_MD5
    else:
        raise ValueError("EyeToy n'offre ni RSA/RC4-SHA (0x0005) ni RSA/RC4-MD5 (0x0004)")

    profile, slot, profiles, state, exhausted = _tls_choose_cert_profile(cfg)
    cert_chain = _tls_load_cert_chain(profile)
    cert_bytes = b"".join(_tls_u24(len(cert)) + cert for cert in cert_chain)
    cert_fps = [hashlib.sha1(cert).hexdigest() for cert in cert_chain]
    if slot is None:
        cycle_txt = "mode_manuel"
        state_txt = "manual"
    else:
        cycle_txt = f"slot={slot}/{len(profiles)-1}; persistent_attempt={state.get('attempts', 0)}"
        state_txt = _tls_cert_state_summary(state, profiles)
    log_event(
        cfg, "UPDATE-TLS-CERT-PROFILE",
        f"profile={profile}; {cycle_txt}; chain_len={len(cert_chain)}; sha1={cert_fps}; ordre={profiles}; state=[{state_txt}]; exhausted={exhausted}"
    )
    if exhausted:
        log_event(cfg, "UPDATE-TLS-ALL-CERTS-REJECTED", "Les profils generes sont deja rejetes; V030 connait les deux ancres beta (SCEE MIS et Test Cert 43.194.211.76) et les sonde separement")

    server_random = int(time.time()).to_bytes(4, "big") + os.urandom(28)
    sh_body = TLS10_VERSION + server_random + b"\x00" + struct.pack("!H", suite) + b"\x00"
    sh = _tls_hs(TLS_HS_SERVER_HELLO, sh_body)
    cert_hs = _tls_hs(TLS_HS_CERTIFICATE, _tls_u24(len(cert_bytes)) + cert_bytes)
    done = _tls_hs(TLS_HS_SERVER_HELLO_DONE, b"")
    conn.sendall(_tls_record(TLS_CONTENT_HANDSHAKE, sh))
    conn.sendall(_tls_record(TLS_CONTENT_HANDSHAKE, cert_hs))
    conn.sendall(_tls_record(TLS_CONTENT_HANDSHAKE, done))
    log_event(
        cfg, "UPDATE-TLS-SERVER-FLIGHT",
        f"ServerHello TLS1.0 envoyé; cipher=0x{suite:04X}; profile={profile}; certs={len(cert_chain)}; cert_bytes={sum(map(len, cert_chain))}; ServerHelloDone"
    )
    return suite, server_random, sh + cert_hs + done, profile


def handle_update_tls_v027(conn, addr, cfg):
    """Terminate just enough TLS 1.0 to reveal EyeToy's HTTPS request on 10443."""
    conn.settimeout(float(cfg.get("update_tls_timeout", 12.0)))
    try:
        ctype, version, payload, raw = _tls_recv_record(conn)
        log_event(cfg, "TCP/10443", f"connexion {addr[0]}:{addr[1]} -> TCP/10443, {len(raw)} octets; handshake probable {guess_tls(raw) or version.hex()}", raw)
        if ctype != TLS_CONTENT_HANDSHAKE:
            raise ValueError(f"premier record TLS type={ctype}, attendu Handshake(22)")
        ch = _tls_parse_client_hello(payload)
        offered_txt = ",".join(f"0x{x:04X}" for x in ch["cipher_suites"])
        log_event(
            cfg, "UPDATE-TLS-CLIENTHELLO",
            f"TLS version={ch['version'].hex()}; ciphers=[{offered_txt}]; compression={ch['compression']}"
        )
        if ch["version"] != TLS10_VERSION:
            log_event(cfg, "UPDATE-TLS-WARN", f"ClientHello annonce {ch['version'].hex()}, V031 répond TLS1.0")

        suite, server_random, server_flight_hs, cert_profile = _tls_send_server_flight(conn, ch, cfg)
        transcript = bytearray(ch["handshake_raw"] + server_flight_hs)
        premaster = None
        master = None
        client_cipher = None
        server_cipher = None
        ccs_seen = False
        finished_ok = False
        handshake_buffer = bytearray()

        # ClientKeyExchange -> CCS -> encrypted Finished.
        for _ in range(16):
            rtype, rver, rpayload, rraw = _tls_recv_record(conn)
            if rtype == TLS_CONTENT_ALERT and not ccs_seen:
                alert_txt = _tls_alert_text(rpayload)
                log_event(cfg, "UPDATE-TLS-ALERT", f"profile={cert_profile}; Alerte TLS reçue avant chiffrement: " + alert_txt, rraw)
                v031_note_tls_failure(addr[0], cert_profile, alert_txt)
                log_event(cfg, "V031-DISCONNECT-STATE", f"TLS fatal enregistré pour client={addr[0]}; profile={cert_profile}; alert={alert_txt}; MAS sera observé avant fermeture contrôlée")
                state, profiles = _tls_mark_cert_result(cfg, cert_profile, "rejected", alert_txt)
                log_event(cfg, "UPDATE-TLS-CERT-REJECTED", f"profile={cert_profile}; client a rejeté le certificat/handshake avant ClientKeyExchange; state=[{_tls_cert_state_summary(state, profiles)}]")
                remaining = [p for p in profiles if state['profiles'].get(p) not in ('rejected', 'trusted_probe')]
                if not remaining:
                    log_event(cfg, "UPDATE-TLS-ALL-CERTS-REJECTED", "Tous les profils TLS de V030 ont ete rejetes. La CA SCEE historique est identifiee; prochaine cible: certificat serveur historique + cle privee correspondante, ou autre materiel de signature serveur.")
                else:
                    log_event(cfg, "UPDATE-TLS-CERT-NEXT", f"Prochaine tentative persistante: {remaining[0]}")
                return
            if rtype == TLS_CONTENT_HANDSHAKE and not ccs_seen:
                handshake_buffer += rpayload
                consumed = 0
                while len(handshake_buffer) - consumed >= 4:
                    n = int.from_bytes(handshake_buffer[consumed+1:consumed+4], "big")
                    end = consumed + 4 + n
                    if end > len(handshake_buffer):
                        break
                    hsraw = bytes(handshake_buffer[consumed:end])
                    hstype = hsraw[0]
                    body = hsraw[4:]
                    transcript += hsraw
                    log_event(cfg, "UPDATE-TLS-HANDSHAKE-RX", f"handshake type={hstype} len={len(body)}", hsraw)
                    if hstype == TLS_HS_CLIENT_KEY_EXCHANGE:
                        if cert_profile in ("historical_scee_root_probe", "beta_test_ca_probe"):
                            probe_name = "SCEE MIS root 2002" if cert_profile == "historical_scee_root_probe" else "beta Test Cert CN=43.194.211.76"
                            state, profiles = _tls_mark_cert_result(cfg, cert_profile, "trusted_probe", f"ClientKeyExchange recu avec {probe_name} presente comme certificat serveur")
                            log_event(cfg, "UPDATE-TLS-TRUST-ANCHOR-ACCEPTED", f"EyeToy a accepte {probe_name} assez loin pour envoyer ClientKeyExchange. C'est une preuve de reconnaissance/trust suffisante pour ce probe, mais ce certificat CA n'est pas un certificat serveur final. Sa cle privee n'est pas disponible cote client; arret volontaire avant dechiffrement RSA.")
                            log_event(cfg, "UPDATE-TLS-NEXT-STEP", "Chercher le certificat serveur historique (leaf) et sa cle privee correspondante. Le scanner V030 cartographie aussi les CA, endpoints beta et marqueurs de cles privees.")
                            return
                        if len(body) >= 2:
                            declared = struct.unpack("!H", body[:2])[0]
                            encrypted = body[2:2+declared] if declared <= len(body)-2 else body
                        else:
                            encrypted = body
                        if len(encrypted) != TLS_RSA_K and len(body) == TLS_RSA_K:
                            encrypted = body
                        premaster = _tls_rsa_pkcs1_v15_decrypt(encrypted)
                        state, profiles = _tls_mark_cert_result(cfg, cert_profile, "accepted", "ClientKeyExchange recu")
                        log_event(cfg, "UPDATE-TLS-CERT-ACCEPTED", f"profile={cert_profile}; EyeToy a dépassé le Certificate et envoyé ClientKeyExchange; profil verrouille dans l'etat persistant")
                        log_event(
                            cfg, "UPDATE-TLS-RSA-OK",
                            f"ClientKeyExchange RSA déchiffré; PreMasterSecret={len(premaster)} octets; client_version={premaster[:2].hex()}"
                        )
                    consumed = end
                if consumed:
                    del handshake_buffer[:consumed]
                continue
            if rtype == TLS_CONTENT_CHANGE_CIPHER_SPEC:
                if rpayload != b"\x01":
                    raise ValueError(f"ChangeCipherSpec inattendu: {rpayload.hex()}")
                if premaster is None:
                    raise ValueError("ChangeCipherSpec reçu avant ClientKeyExchange RSA")
                master, client_cipher, server_cipher = _tls_key_schedule(
                    premaster, ch["client_random"], server_random, suite
                )
                ccs_seen = True
                log_event(cfg, "UPDATE-TLS-CCS", "ChangeCipherSpec client reçu; clés TLS 1.0 dérivées")
                continue
            if rtype == TLS_CONTENT_HANDSHAKE and ccs_seen:
                plain, mac_ok, got_mac, expected_mac = client_cipher.decrypt(rtype, rver, rpayload)
                log_event(
                    cfg, "UPDATE-TLS-FINISHED-RX",
                    f"Finished chiffré déchiffré; MAC={'OK' if mac_ok else 'ERREUR'}; plain_len={len(plain)}",
                    plain
                )
                if not mac_ok:
                    log_event(cfg, "UPDATE-TLS-MAC-ERROR", f"MAC reçu={got_mac.hex()} attendu={expected_mac.hex()}")
                    return
                items = list(_tls_iter_handshakes(plain))
                if not items or items[0][0] != TLS_HS_FINISHED:
                    raise ValueError("premier handshake chiffré n'est pas Finished")
                _, fbody, fraw = items[0]
                expected_verify = _tls_finished_verify(master, b"client finished", bytes(transcript))
                finished_ok = hmac.compare_digest(fbody, expected_verify)
                log_event(
                    cfg, "UPDATE-TLS-FINISHED-CHECK",
                    f"verify_data client={'OK' if finished_ok else 'ERREUR'}; reçu={fbody.hex()} attendu={expected_verify.hex()}"
                )
                if not finished_ok:
                    return
                transcript += fraw
                server_verify = _tls_finished_verify(master, b"server finished", bytes(transcript))
                server_finished = _tls_hs(TLS_HS_FINISHED, server_verify)
                conn.sendall(_tls_record(TLS_CONTENT_CHANGE_CIPHER_SPEC, b"\x01"))
                protected = server_cipher.encrypt(TLS_CONTENT_HANDSHAKE, TLS10_VERSION, server_finished)
                conn.sendall(_tls_record(TLS_CONTENT_HANDSHAKE, protected))
                log_event(cfg, "UPDATE-TLS-HANDSHAKE-OK", f"TLS 1.0 établi; cipher=0x{suite:04X}; Server Finished envoyé")
                break
            log_event(cfg, "UPDATE-TLS-UNEXPECTED", f"record avant fin handshake type={rtype} version={rver.hex()} len={len(rpayload)}", rraw)
        else:
            raise TimeoutError("handshake TLS non terminé")

        if not finished_ok:
            return

        # Capture the decrypted HTTP request the V023 trace could not reveal.
        request = bytearray()
        for _ in range(32):
            rtype, rver, rpayload, rraw = _tls_recv_record(conn)
            if rtype in (TLS_CONTENT_APPLICATION_DATA, TLS_CONTENT_ALERT, TLS_CONTENT_HANDSHAKE):
                plain, mac_ok, got_mac, expected_mac = client_cipher.decrypt(rtype, rver, rpayload)
                if not mac_ok:
                    log_event(cfg, "UPDATE-TLS-MAC-ERROR", f"post-handshake type={rtype}; reçu={got_mac.hex()} attendu={expected_mac.hex()}")
                    return
                if rtype == TLS_CONTENT_APPLICATION_DATA:
                    request += plain
                    log_event(cfg, "UPDATE-TLS-HTTP-RX", f"HTTP chiffré déchiffré: +{len(plain)} octets (total={len(request)})", plain)
                    if b"\r\n\r\n" in request or b"\n\n" in request:
                        break
                elif rtype == TLS_CONTENT_ALERT:
                    log_event(cfg, "UPDATE-TLS-ALERT", "Alerte TLS chiffrée: " + _tls_alert_text(plain), plain)
                    return
                else:
                    log_event(cfg, "UPDATE-TLS-POST-HS", f"handshake postérieur type={rtype}, len={len(plain)}", plain)
            elif rtype == TLS_CONTENT_CHANGE_CIPHER_SPEC:
                log_event(cfg, "UPDATE-TLS-POST-HS", "CCS supplémentaire ignoré")
            else:
                log_event(cfg, "UPDATE-TLS-UNEXPECTED", f"record type={rtype} après handshake", rraw)
        if not request:
            log_event(cfg, "UPDATE-TLS-NO-HTTP", "TLS établi mais aucune donnée HTTP reçue")
            return

        response, path, body = http_response_for(bytes(request), cfg)
        if response is None:
            body = b"EyeToy Chat Local TLS V030\n"
            response = make_http_response(b"HTTP/1.0 200 OK\r\n", b"text/plain", body, "GET")
            path = "<non-parse>"
        protected = server_cipher.encrypt(TLS_CONTENT_APPLICATION_DATA, TLS10_VERSION, response)
        conn.sendall(_tls_record(TLS_CONTENT_APPLICATION_DATA, protected))
        log_event(
            cfg, "UPDATE-TLS-HTTP-TX",
            f"Réponse HTTPS envoyée pour path={path!r}; http_len={len(response)}; body_len={len(body) if body is not None else 0}",
            response
        )
        if path and path.rstrip("/").lower() == "/qa_patches/index.xml":
            log_event(cfg, "UPDATE-TLS-INDEX", f"Catalogue HTTPS mode={cfg.get('update_mode', 'no_update')} BUILD={cfg.get('update_build', 194)}", body)

        # Graceful encrypted close_notify (warning=1, description=0).
        alert_plain = b"\x01\x00"
        alert_enc = server_cipher.encrypt(TLS_CONTENT_ALERT, TLS10_VERSION, alert_plain)
        conn.sendall(_tls_record(TLS_CONTENT_ALERT, alert_enc))
        log_event(cfg, "UPDATE-TLS-DONE", "HTTPS local terminé proprement (close_notify envoyé)")
    except socket.timeout:
        log_event(cfg, "UPDATE-TLS-TIMEOUT", f"Timeout TLS/10443 avec {addr[0]}:{addr[1]}")
    except EOFError as e:
        log_event(cfg, "UPDATE-TLS-EOF", f"Connexion TLS/10443 fermée par le client: {e}")
    except Exception as e:
        log_event(cfg, "UPDATE-TLS-ERROR", f"TLS/10443 {addr}: {type(e).__name__}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


# --- SCERT / Medius PS2 crypto -------------------------------------------------
# Default Medius RSA authentication key used by the SCE-RT PS2 stack.
MEDIUS_RSA_N = int("10315955513017997681600210131013411322695824559688299373570246338038100843097466504032586443986679280716603540690692615875074465586629501752500179100369237")
MEDIUS_RSA_E = 17
MEDIUS_RSA_D = int("4854567300243763614870687120476899445974505675147434999327174747312047455575182761195687859800492317495944895566174677168271650454805328075020357360662513")

# V030: known public Medius keys used only for identification/diagnostics.
# The GLOBAL key above is the one already used by V030 for RSA_AUTH.
KNOWN_MEDIUS_RSA_MODULI = {
    "GLOBAL_MEDIUS_KEY": MEDIUS_RSA_N,
    "CLIENT_AUTH_UYA_PS2_NTSC": int("10818698864852529169654939372314224042721443840878792146188116838905755590786829011691246645307492409247191122437625676104042595209630473880013285201907563"),
    "CLIENT_AUTH_DL_PS2_NTSC": int("10050356962645816905344862325421678999857135586090561898962595162395705959736196531277029037839492627511844645395487066542742912877963865473424548324115559"),
}

def _rsa_modulus_bytes(n: int, byteorder: str = "big") -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    return raw if byteorder == "big" else raw[::-1]

def medius_rsa_identity(n: int) -> dict:
    be = _rsa_modulus_bytes(n, "big")
    le = be[::-1]
    known = [name for name, value in KNOWN_MEDIUS_RSA_MODULI.items() if value == n]
    return {
        "bits": n.bit_length(),
        "bytes": len(be),
        "odd": bool(n & 1),
        "sha1_be": hashlib.sha1(be).hexdigest(),
        "sha1_le": hashlib.sha1(le).hexdigest(),
        "sha256_be": hashlib.sha256(be).hexdigest(),
        "known": known,
    }

def log_scert_rsa_identity(cfg, scope: str, n: int, role: str) -> None:
    if not bool(cfg.get("scert_rsa_diagnostics", True)):
        return
    ident = medius_rsa_identity(n)
    names = ",".join(ident["known"]) if ident["known"] else "unknown/ephemeral"
    log_event(
        cfg, f"{scope}-RSA-IDENTITY",
        f"{role}: bits={ident['bits']}; bytes={ident['bytes']}; e_assumed={MEDIUS_RSA_E}; "
        f"odd={ident['odd']}; known={names}; sha1_be={ident['sha1_be']}; "
        f"sha1_le={ident['sha1_le']}; sha256_be={ident['sha256_be']}"
    )

def log_scert_crypto_state(cfg, scope: str, stage: str, rc_key: bytes | None, plain: bytes | None = None, frame: bytes | None = None) -> None:
    if not bool(cfg.get("scert_crypto_state_diagnostics", True)):
        return
    parts = [f"stage={stage}"]
    if rc_key is not None:
        parts += [f"rc_len={len(rc_key)}", f"rc_sha1={hashlib.sha1(rc_key).hexdigest()}", f"rc_sha256={hashlib.sha256(rc_key).hexdigest()}"]
    if plain is not None:
        parts += [f"plain_len={len(plain)}", f"plain_sha1={hashlib.sha1(plain).hexdigest()}"]
    if frame is not None:
        parts += [f"frame_len={len(frame)}", f"frame_sha1={hashlib.sha1(frame).hexdigest()}"]
    log_event(cfg, f"{scope}-CRYPTO-STATE", "; ".join(parts))

CTX_RC_CLIENT_SESSION = 3
CTX_RSA_AUTH = 7

RT_NAMES = {
    0: "RT_MSG_CLIENT_CONNECT_TCP", 1: "RT_MSG_CLIENT_DISCONNECT",
    2: "RT_MSG_CLIENT_APP_BROADCAST", 3: "RT_MSG_CLIENT_APP_SINGLE",
    4: "RT_MSG_CLIENT_APP_LIST", 5: "RT_MSG_CLIENT_ECHO",
    6: "RT_MSG_SERVER_CONNECT_REJECT", 7: "RT_MSG_SERVER_CONNECT_ACCEPT_TCP",
    8: "RT_MSG_SERVER_CONNECT_NOTIFY", 9: "RT_MSG_SERVER_DISCONNECT_NOTIFY",
    10: "RT_MSG_SERVER_APP", 11: "RT_MSG_CLIENT_APP_TOSERVER",
    12: "RT_MSG_UDP_APP", 13: "RT_MSG_CLIENT_SET_RECV_FLAG",
    14: "RT_MSG_CLIENT_SET_AGG_TIME", 15: "RT_MSG_CLIENT_FLUSH_ALL",
    16: "RT_MSG_CLIENT_FLUSH_SINGLE", 17: "RT_MSG_SERVER_FORCED_DISCONNECT",
    18: "RT_MSG_CLIENT_CRYPTKEY_PUBLIC", 19: "RT_MSG_SERVER_CRYPTKEY_PEER",
    20: "RT_MSG_SERVER_CRYPTKEY_GAME", 21: "RT_MSG_CLIENT_CONNECT_TCP_AUX_UDP",
    22: "RT_MSG_CLIENT_CONNECT_AUX_UDP", 23: "RT_MSG_CLIENT_CONNECT_READY_AUX_UDP",
    24: "RT_MSG_SERVER_INFO_AUX_UDP", 25: "RT_MSG_SERVER_CONNECT_ACCEPT_AUX_UDP",
    26: "RT_MSG_SERVER_CONNECT_COMPLETE", 27: "RT_MSG_CLIENT_CRYPTKEY_PEER",
    28: "RT_MSG_SERVER_SYSTEM_MESSAGE", 29: "RT_MSG_SERVER_CHEAT_QUERY",
    30: "RT_MSG_SERVER_MEMORY_POKE", 31: "RT_MSG_SERVER_ECHO",
    32: "RT_MSG_CLIENT_DISCONNECT_WITH_REASON", 33: "RT_MSG_CLIENT_CONNECT_READY_TCP",
    34: "RT_MSG_SERVER_CONNECT_REQUIRE", 35: "RT_MSG_CLIENT_CONNECT_READY_REQUIRE",
    36: "RT_MSG_CLIENT_HELLO", 37: "RT_MSG_SERVER_HELLO",
}

def ps2_sha1_4(data: bytes, context: int) -> bytes:
    h = bytearray(hashlib.sha1(data).digest()[:4])
    h[3] = (h[3] & 0x1F) | ((context & 7) << 5)
    return bytes(h)

def rsa_auth_decrypt(ciphertext: bytes, wanted_hash: bytes):
    """Raw PS2 Medius RSA, little-endian byte representation, including N-add retry."""
    if len(ciphertext) > 64:
        return None, False
    c = int.from_bytes(ciphertext, "little", signed=False)
    m = pow(c, MEDIUS_RSA_D, MEDIUS_RSA_N)
    for candidate in (m, m + MEDIUS_RSA_N):
        nbytes = max(1, (candidate.bit_length() + 7) // 8)
        if nbytes > len(ciphertext):
            continue
        plain = candidate.to_bytes(nbytes, "little").ljust(len(ciphertext), b"\x00")
        if ps2_sha1_4(plain, CTX_RSA_AUTH) == wanted_hash:
            return plain, True
    return None, False

def rsa_auth_encrypt_for_client(plain: bytes, client_modulus: int):
    h = ps2_sha1_4(plain, CTX_RSA_AUTH)
    m = int.from_bytes(plain, "little", signed=False)
    c = pow(m, MEDIUS_RSA_E, client_modulus)
    return c.to_bytes(len(plain), "little"), h

def _ps2_rc4_setkey(key: bytes, h: bytes):
    state = [255 - i for i in range(256)]
    key_index = li = cipher_index = id_index = 0
    if h is not None and len(h) == 4:
        while True:
            v1 = h[id_index]
            id_index = (id_index + 1) & 3
            temp = state[cipher_index]
            v1 += li
            li = (temp + v1) & 0xFF
            state[cipher_index] = state[li]
            state[li] = temp
            cipher_index = (cipher_index + 5) & 0xFF
            if cipher_index == 0:
                break
        key_index = li = cipher_index = id_index = 0
    while True:
        key_byte = key[key_index] + li
        key_index = (key_index + 1) & 0x3F
        cipher_byte = state[cipher_index]
        cipher_value = cipher_byte & 0xFF
        li = (cipher_byte + key_byte) & 0xFF
        t0 = state[li]
        state[cipher_index] = t0
        state[li] = cipher_value
        cipher_index = (cipher_index + 3) & 0xFF
        if cipher_index == 0:
            break
    return state

def ps2_rc4_decrypt(key: bytes, data: bytes, h: bytes):
    state = _ps2_rc4_setkey(key, h)
    x = y = 0
    out = bytearray()
    for c in data:
        y = (y + 5) & 0xFF
        v0 = state[y]
        a2 = v0 & 0xFF
        x = (v0 + x) & 0xFF
        v0 = state[x]
        state[y] = v0 & 0xFF
        state[x] = a2
        a0 = c
        idx = (v0 + a2) & 0xFF
        a0 ^= state[idx]
        out.append(a0)
        x = (state[a0] + x) & 0xFF
    return bytes(out)

def ps2_rc4_encrypt(key: bytes, data: bytes, h: bytes):
    state = _ps2_rc4_setkey(key, h)
    x = y = 0
    out = bytearray()
    for a in data:
        x = (x + 5) & 0xFF
        y = (y + state[x]) & 0xFF
        state[x], state[y] = state[y], state[x]
        out.append(a ^ state[(state[x] + state[y]) & 0xFF])
        y = (state[a] + y) & 0xFF
    return bytes(out)

def scert_make_encrypted(rt_id: int, payload: bytes, key: bytes, context: int):
    h = ps2_sha1_4(payload, context)
    if context == CTX_RC_CLIENT_SESSION:
        cipher = ps2_rc4_encrypt(key, payload, h)
    else:
        raise ValueError("scert_make_encrypted only supports RC client session here")
    return bytes([rt_id | 0x80]) + struct.pack("<H", len(payload)) + h + cipher

def scert_extract_frames(buf: bytes):
    frames = []
    pos = 0
    while len(buf) - pos >= 3:
        raw_id = buf[pos]
        ln = struct.unpack_from("<H", buf, pos + 1)[0]
        overhead = 7 if raw_id & 0x80 else 3
        total = overhead + ln
        if len(buf) - pos < total:
            break
        frames.append(buf[pos:pos+total])
        pos += total
    return frames, buf[pos:]

def scert_decode_frame(frame: bytes, rc_key: bytes | None = None):
    raw_id = frame[0]
    rt_id = raw_id & 0x7F
    ln = struct.unpack_from("<H", frame, 1)[0]
    encrypted = bool(raw_id & 0x80)
    if encrypted:
        h = frame[3:7]
        cipher = frame[7:7+ln]
        ctx = (h[3] >> 5) & 7
        if rt_id == 18 and ctx == CTX_RSA_AUTH:
            plain, ok = rsa_auth_decrypt(cipher, h)
            return rt_id, encrypted, ctx, h, plain, ok
        if ctx == CTX_RC_CLIENT_SESSION and rc_key is not None:
            plain = ps2_rc4_decrypt(rc_key, cipher, h)
            ok = ps2_sha1_4(plain, ctx) == h
            return rt_id, encrypted, ctx, h, plain, ok
        return rt_id, encrypted, ctx, h, None, False
    return rt_id, False, None, None, frame[3:3+ln], True


def parse_client_connect_tcp_old(payload: bytes):
    """Parse the pre-Medius-1.09 RT_MSG_CLIENT_CONNECT_TCP layout."""
    if len(payload) < 73:
        raise ValueError(f"CLIENT_CONNECT_TCP trop court: {len(payload)} octets")
    target_world_id = struct.unpack_from("<I", payload, 0)[0]
    unk0 = payload[4]
    app_id = struct.unpack_from("<i", payload, 5)[0]
    client_key = payload[9:73]
    extra = payload[73:]
    return target_world_id, unk0, app_id, client_key, extra


def medius_ip_field(ip: str) -> bytes:
    packed = ip.encode("ascii", errors="strict")
    if len(packed) > 15:
        raise ValueError(f"IPv4 trop long pour champ Medius: {ip}")
    return packed.ljust(16, b"\x00")


def make_server_connect_accept_tcp_old(ip: str, rc_key: bytes, player_id=0, player_count=1):
    payload = b"\x01\x08\x10" + struct.pack("<HH", player_id, player_count) + medius_ip_field(ip)
    return payload, scert_make_encrypted(7, payload, rc_key, CTX_RC_CLIENT_SESSION)


def make_server_connect_complete(rc_key: bytes, arg1=1):
    payload = struct.pack("<H", arg1)
    return payload, scert_make_encrypted(26, payload, rc_key, CTX_RC_CLIENT_SESSION)


# --- Medius MUIS application layer --------------------------------------------
# Based on Horizon's RT.Models layouts for Medius 1.x.
MEDIUS_CLASS_LOBBY = 1
MEDIUS_CLASS_LOBBY_EXT = 4
MEDIUS_GET_UNIVERSE_INFORMATION = 0xC8
MEDIUS_UNIVERSE_NEWS_RESPONSE = 0xC9
MEDIUS_UNIVERSE_VARIABLE_INFORMATION_RESPONSE = 0x11

INFO_UNIVERSES   = 1 << 0
INFO_NEWS        = 1 << 1
INFO_ID          = 1 << 2
INFO_NAME        = 1 << 3
INFO_DNS         = 1 << 4
INFO_DESCRIPTION = 1 << 5
INFO_STATUS      = 1 << 6
INFO_BILLING     = 1 << 7
INFO_EXTRAINFO   = 1 << 8
INFO_SVO_URL     = 1 << 9

MESSAGEID_MAXLEN = 21
NEWS_MAXLEN = 256
UNIVERSENAME_MAXLEN = 128
UNIVERSEDNS_MAXLEN = 128
UNIVERSEDESCRIPTION_MAXLEN = 256
UNIVERSE_BSP_MAXLEN = 8
UNIVERSE_BSP_NAME_MAXLEN = 128
UNIVERSE_EXTENDED_INFO_MAXLEN = 128


def medius_fixed_string(text: str, size: int) -> bytes:
    """Medius fixed UTF-8/ASCII field: NUL-terminated when room exists, zero padded."""
    raw = (text or "").encode("utf-8", errors="replace")
    if size <= 0:
        return b""
    if len(raw) >= size:
        raw = raw[:size-1]
    return raw + b"\x00" * (size - len(raw))


def parse_get_universe_information(payload: bytes):
    """Parse Lobby/0xC8 request captured from EyeToy Chat.

    Wire layout after class/type:
      MessageID[21], pad[3], InfoType u32, CharacterEncoding i32, Language i32
    """
    if len(payload) < 38:
        raise ValueError(f"GetUniverseInformation trop court: {len(payload)} octets")
    if payload[0] != MEDIUS_CLASS_LOBBY or payload[1] != MEDIUS_GET_UNIVERSE_INFORMATION:
        raise ValueError(f"pas Lobby/0xC8: class={payload[0]:02X} type={payload[1]:02X}")
    message_id = payload[2:2+MESSAGEID_MAXLEN]
    pad = payload[23:26]
    info_type = struct.unpack_from("<I", payload, 26)[0]
    char_encoding = struct.unpack_from("<i", payload, 30)[0]
    language = struct.unpack_from("<i", payload, 34)[0]
    return {
        "message_id": message_id,
        "pad": pad,
        "info_type": info_type,
        "character_encoding": char_encoding,
        "language": language,
        "extra": payload[38:],
    }


def info_filter_names(info: int):
    flags = [
        (INFO_UNIVERSES, "UNIVERSES"), (INFO_NEWS, "NEWS"), (INFO_ID, "ID"),
        (INFO_NAME, "NAME"), (INFO_DNS, "DNS"), (INFO_DESCRIPTION, "DESCRIPTION"),
        (INFO_STATUS, "STATUS"), (INFO_BILLING, "BILLING"),
        (INFO_EXTRAINFO, "EXTRAINFO"), (INFO_SVO_URL, "SVO_URL"),
    ]
    return [name for bit, name in flags if info & bit]


def make_universe_variable_information_response(message_id: bytes, info_filter: int,
                                                  endpoint: str, port: int,
                                                  name: str, description: str,
                                                  universe_id: int = 1,
                                                  status: int = 0,
                                                  user_count: int = 0,
                                                  max_users: int = 0,
                                                  end_of_list: bool = True) -> bytes:
    """Serialize LobbyExt/0x11 exactly according to requested InfoFilter fields."""
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError(f"MessageID doit faire {MESSAGEID_MAXLEN} octets")
    out = bytearray([MEDIUS_CLASS_LOBBY_EXT, MEDIUS_UNIVERSE_VARIABLE_INFORMATION_RESPONSE])
    out += message_id
    out += struct.pack("<i", 0)                 # MediusSuccess
    out += struct.pack("<I", info_filter)
    if info_filter & INFO_ID:
        out += struct.pack("<I", universe_id)
    if info_filter & INFO_NAME:
        out += medius_fixed_string(name, UNIVERSENAME_MAXLEN)
    if info_filter & INFO_DNS:
        out += medius_fixed_string(endpoint, UNIVERSEDNS_MAXLEN)
        out += struct.pack("<i", int(port))
    if info_filter & INFO_DESCRIPTION:
        out += medius_fixed_string(description, UNIVERSEDESCRIPTION_MAXLEN)
    if info_filter & INFO_STATUS:
        out += struct.pack("<iii", int(status), int(user_count), int(max_users))
    if info_filter & INFO_BILLING:
        out += medius_fixed_string("", UNIVERSE_BSP_MAXLEN)
        out += medius_fixed_string("", UNIVERSE_BSP_NAME_MAXLEN)
    if info_filter & INFO_EXTRAINFO:
        out += medius_fixed_string("", UNIVERSE_EXTENDED_INFO_MAXLEN)
    # Horizon's UniverseVariableInformationResponse serializer does not emit SVO_URL here.
    out += bytes([1 if end_of_list else 0, 0, 0, 0])
    return bytes(out)


def make_universe_news_response(message_id: bytes, news: str, end_of_list: bool = True) -> bytes:
    """Serialize Lobby/0xC9 MediusUniverseNewsResponse."""
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError(f"MessageID doit faire {MESSAGEID_MAXLEN} octets")
    out = bytearray([MEDIUS_CLASS_LOBBY, MEDIUS_UNIVERSE_NEWS_RESPONSE])
    out += message_id
    out += b"\x00\x00\x00"
    out += struct.pack("<i", 0)                 # MediusSuccess
    out += medius_fixed_string(news, NEWS_MAXLEN)
    out += bytes([1 if end_of_list else 0, 0, 0, 0])
    return bytes(out)

def save_muis_plain(cfg, prefix: str, addr, data: bytes):
    raw_dir = ROOT / cfg.get("log_dir", "logs") / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    name = f"{prefix}_{addr[0].replace('.', '_')}_{addr[1]}_{stamp}.bin"
    path = raw_dir / name
    path.write_bytes(data)
    log_event(cfg, "MUIS-SAVE", f"Payload déchiffré sauvegardé: {path.relative_to(ROOT)}")
    return path

def handle_muis_v014(conn, addr, cfg):
    conn.settimeout(4.0)
    log_event(cfg, "MUIS-CONNECT", f"Connexion TCP MUIS acceptée depuis {addr[0]}:{addr[1]} -> 10080; handshake + Active Universe V015")
    buffer = b""
    rc_key = None
    peer_sent = False
    connect_accepted = False
    application_id = None
    deadline = time.time() + 45.0
    frame_count = 0
    v031_tls_fail_echoes = 0
    v031_close_requested = False
    try:
        while time.time() < deadline:
            frames, buffer = scert_extract_frames(buffer)
            if not frames:
                try:
                    data = conn.recv(8192)
                except socket.timeout:
                    continue
                if not data:
                    break
                buffer += data
                log_event(cfg, "MUIS-RX", f"{len(data)} octets reçus depuis {addr[0]}:{addr[1]}", data)
                frames, buffer = scert_extract_frames(buffer)

            for frame in frames:
                frame_count += 1
                rt_id, encrypted, ctx, h, plain, ok = scert_decode_frame(frame, rc_key)
                name = RT_NAMES.get(rt_id, f"RT_MSG_{rt_id}")
                log_event(cfg, "MUIS-FRAME", f"#{frame_count} {name} id={rt_id} encrypted={encrypted} ctx={ctx} len={struct.unpack_from('<H', frame, 1)[0]} decrypt_ok={ok}", frame)
                if plain is not None:
                    log_event(cfg, "MUIS-PLAIN", f"#{frame_count} {name} plaintext {len(plain)} octets", plain)

                if rt_id == 18 and encrypted and ok and plain is not None and not peer_sent:
                    client_modulus = int.from_bytes(plain, "little", signed=False)
                    log_scert_rsa_identity(cfg, "MUIS", client_modulus, "RT_MSG_CLIENT_CRYPTKEY_PUBLIC modulus")
                    rc_key = os.urandom(64)
                    cipher, rhash = rsa_auth_encrypt_for_client(rc_key, client_modulus)
                    reply = bytes([0x80 | 19]) + struct.pack("<H", 64) + rhash + cipher
                    conn.sendall(reply)
                    peer_sent = True
                    log_event(cfg, "MUIS-RSA-OK", "RT_MSG_CLIENT_CRYPTKEY_PUBLIC déchiffré et hash SHA1 validé avec la GLOBAL MEDIUS KEY")
                    log_scert_crypto_state(cfg, "MUIS", "after_rsa_peer_key", rc_key, plain=plain, frame=reply)
                    log_event(cfg, "MUIS-SESSION-KEY", "Clé RC_CLIENT_SESSION locale générée (64 octets)", rc_key)
                    log_event(cfg, "MUIS-TX", "RT_MSG_SERVER_CRYPTKEY_PEER envoyé (id=19, RSA_AUTH)", reply)
                    continue

                if rt_id == 0 and peer_sent and ok and plain is not None and not connect_accepted:
                    try:
                        world_id, unk0, application_id, client_key, extra = parse_client_connect_tcp_old(plain)
                    except Exception as e:
                        log_event(cfg, "MUIS-CONNECT-PARSE-FAIL", str(e), plain)
                        continue
                    log_event(cfg, "MUIS-CONNECT-PARSED", f"CLIENT_CONNECT_TCP old-layout: TargetWorldId={world_id} (0x{world_id:08X}), UNK0=0x{unk0:02X}, AppId={application_id}, key64={len(client_key)} octets, extra={len(extra)}")
                    accept_payload, accept_frame = make_server_connect_accept_tcp_old(addr[0], rc_key, player_id=0, player_count=1)
                    complete_payload, complete_frame = make_server_connect_complete(rc_key, arg1=1)
                    conn.sendall(accept_frame)
                    conn.sendall(complete_frame)
                    connect_accepted = True
                    log_event(cfg, "MUIS-TX", f"RT_MSG_SERVER_CONNECT_ACCEPT_TCP envoyé (id=7, client IP={addr[0]}, PlayerId=0, PlayerCount=1)", accept_frame)
                    log_event(cfg, "MUIS-TX-PLAIN", "SERVER_CONNECT_ACCEPT_TCP plaintext", accept_payload)
                    log_event(cfg, "MUIS-TX", "RT_MSG_SERVER_CONNECT_COMPLETE envoyé (id=26, ARG1=1)", complete_frame)
                    log_event(cfg, "MUIS-TX-PLAIN", "SERVER_CONNECT_COMPLETE plaintext", complete_payload)
                    log_event(cfg, "MUIS-STAGE", f"SCERT CONNECT accepté pour AppId={application_id}. Attente du premier message Medius applicatif.")
                    continue

                if rt_id == 33 and connect_accepted and ok and plain is not None:
                    complete_payload, complete_frame = make_server_connect_complete(rc_key, arg1=1)
                    conn.sendall(complete_frame)
                    log_event(cfg, "MUIS-TX", "CLIENT_CONNECT_READY_TCP reçu -> SERVER_CONNECT_COMPLETE renvoyé", complete_frame)
                    continue

                if rt_id == 5 and connect_accepted and ok and plain is not None:
                    echo = scert_make_encrypted(5, plain, rc_key, CTX_RC_CLIENT_SESSION)
                    conn.sendall(echo)
                    log_event(cfg, "MUIS-ECHO", "RT_MSG_CLIENT_ECHO reçu et renvoyé", echo)
                    continue

                if rt_id == 11 and connect_accepted and ok and plain is not None:
                    save_muis_plain(cfg, "muis_app", addr, plain)
                    nc = plain[0] if len(plain) >= 1 else None
                    mt = plain[1] if len(plain) >= 2 else None
                    log_event(cfg, "MUIS-APP", f"RT_MSG_CLIENT_APP_TOSERVER déchiffré: {len(plain)} octets; NetMessageClass={nc}; MessageType={mt}; AppId={application_id}", plain)

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_GET_UNIVERSE_INFORMATION:
                        try:
                            req = parse_get_universe_information(plain)
                            info = req["info_type"]
                            endpoint = cfg.get("_runtime_advertise_ip") or local_ipv4()
                            configured_endpoint = str(cfg.get("universe_endpoint", "auto"))
                            if configured_endpoint.lower() != "auto":
                                endpoint = configured_endpoint
                            next_port = int(cfg.get("universe_next_port", 10075))
                            uname = str(cfg.get("universe_name", "EyeToy Chat Europe"))
                            udesc = str(cfg.get("universe_description", "EyeToy Chat Community Server"))
                            news = str(cfg.get("universe_news", "EyeToy Chat Community Server"))
                            flags = ",".join(info_filter_names(info)) or "NONE"
                            mid_print = req["message_id"].split(b"\x00",1)[0].decode("ascii", errors="replace")
                            log_event(cfg, "MUIS-UNIVERSE-REQ",
                                      f"MediusGetUniverseInformationRequest: MessageID={mid_print!r}; InfoType=0x{info:08X} [{flags}]; CharacterEncoding={req['character_encoding']}; Language={req['language']}; extra={len(req['extra'])}", plain)

                            u_payload = make_universe_variable_information_response(
                                req["message_id"], info, endpoint, next_port, uname, udesc,
                                universe_id=int(cfg.get("universe_id", 1)),
                                status=int(cfg.get("universe_status", 2)),
                                user_count=int(cfg.get("universe_user_count", 0)),
                                max_users=int(cfg.get("universe_max_users", 64)),
                                end_of_list=True)
                            u_frame = scert_make_encrypted(10, u_payload, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(u_frame)
                            log_event(cfg, "MUIS-UNIVERSE-TX",
                                      f"UniverseVariableInformationResponse -> {endpoint}:{next_port}; name={uname!r}; InfoFilter=0x{info:08X}; Status={int(cfg.get('universe_status', 2))}; Users={int(cfg.get('universe_user_count', 0))}/{int(cfg.get('universe_max_users', 64))}; EndOfList=1",
                                      u_payload)
                            log_event(cfg, "MUIS-UNIVERSE-TX-SCERT", "RT_MSG_SERVER_APP chiffré envoyé (UniverseVariableInformationResponse)", u_frame)

                            if info & INFO_NEWS:
                                n_payload = make_universe_news_response(req["message_id"], news, end_of_list=True)
                                n_frame = scert_make_encrypted(10, n_payload, rc_key, CTX_RC_CLIENT_SESSION)
                                conn.sendall(n_frame)
                                log_event(cfg, "MUIS-NEWS-TX", f"UniverseNewsResponse envoyé; News={news!r}; EndOfList=1", n_payload)
                                log_event(cfg, "MUIS-NEWS-TX-SCERT", "RT_MSG_SERVER_APP chiffré envoyé (UniverseNewsResponse)", n_frame)

                            log_event(cfg, "MUIS-STAGE", f"UniverseInformation répondue. EyeToy Chat est orienté vers {endpoint}:{next_port}; attente de la connexion au service suivant.")
                        except Exception as e:
                            log_event(cfg, "MUIS-UNIVERSE-ERROR", f"Décodage/réponse Lobby/0xC8 impossible: {e}", plain)
                    else:
                        log_event(cfg, "MUIS-NEXT", f"Message Medius non encore géré: class={nc} type={mt}")
                    continue

                if peer_sent and rt_id not in (18, 0, 33, 5, 11):
                    if ok:
                        log_event(cfg, "MUIS-NEXT", f"Message SCERT suivant capturé: {name} (id={rt_id})")
                    else:
                        log_event(cfg, "MUIS-NEXT", f"Message SCERT suivant reçu mais non déchiffré: {name} ctx={ctx}")
    except Exception as e:
        log_event(cfg, "ERROR", f"MUIS V015 {addr}: {e}")
    finally:
        if buffer:
            log_event(cfg, "MUIS-TAIL", f"Données SCERT incomplètes restantes: {len(buffer)} octets", buffer)
        try:
            conn.close()
        except OSError:
            pass



# --- Medius MAS SessionBegin ---------------------------------------------------
MEDIUS_SESSION_BEGIN_REQUEST = 0x03
MEDIUS_SESSION_BEGIN_RESPONSE = 0x04
SESSIONKEY_MAXLEN = 17


def parse_session_begin_request(payload: bytes):
    """Lobby/0x03 MediusSessionBeginRequest.

    Layout: class/type, MessageID[21], pad[3], MediusConnectionType i32.
    """
    if len(payload) < 30:
        raise ValueError(f"SessionBegin trop court: {len(payload)} octets")
    if payload[0] != MEDIUS_CLASS_LOBBY or payload[1] != MEDIUS_SESSION_BEGIN_REQUEST:
        raise ValueError(f"pas Lobby/0x03: class={payload[0]:02X} type={payload[1]:02X}")
    message_id = payload[2:2+MESSAGEID_MAXLEN]
    pad = payload[23:26]
    connection_class = struct.unpack_from("<i", payload, 26)[0]
    return {
        "message_id": message_id,
        "pad": pad,
        "connection_class": connection_class,
        "extra": payload[30:],
    }


def make_session_begin_response(message_id: bytes, session_key: str, status_code: int = 0) -> bytes:
    """Lobby/0x04 MediusSessionBeginResponse (Medius 1.x)."""
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError(f"MessageID doit faire {MESSAGEID_MAXLEN} octets")
    # Horizon serializes SessionKey as a fixed SESSIONKEY_MAXLEN=17 string.
    key = medius_fixed_string(session_key, SESSIONKEY_MAXLEN)
    return (bytes([MEDIUS_CLASS_LOBBY, MEDIUS_SESSION_BEGIN_RESPONSE]) +
            message_id + b"\x00\x00\x00" +
            struct.pack("<i", int(status_code)) + key + b"\x00\x00\x00")


# --- Medius MAS VersionServer --------------------------------------------------
# EyeToy Chat sends a stable 40-byte Lobby/0x86 request immediately after a
# successful SessionBegin: class/type + MessageID[21] + SessionKey[17].
#
# V018 tried MessageID + pad + StatusCode. EyeToy rejected it and immediately
# repeated 0x86. Reverse engineering EyeToy's own RTMediusConnection code gives
# a stronger game-specific clue: it copies 0x38 (56) bytes from response offset
# 0x15 (21) into its version-string buffer and parses "Medius %s Server Version
# X.Y.Z" (or a fallback without the word Version). V019 therefore sends
# MessageID[21] + VersionString[56].
MEDIUS_VERSION_SERVER_REQUEST = 0x86
MEDIUS_VERSION_SERVER_RESPONSE = 0x87
VERSION_SERVER_STRING_LEN = 0x38


def parse_version_server_request(payload: bytes):
    """Parse the 40-byte Lobby/0x86 request observed from EyeToy Chat.

    Observed layout: class/type, MessageID[21], SessionKey[17], optional extra.
    The MessageID is opaque binary data and must be echoed byte-for-byte.
    """
    minimum = 2 + MESSAGEID_MAXLEN + SESSIONKEY_MAXLEN
    if len(payload) < minimum:
        raise ValueError(f"VersionServer trop court: {len(payload)} octets (minimum {minimum})")
    if payload[0] != MEDIUS_CLASS_LOBBY or payload[1] != MEDIUS_VERSION_SERVER_REQUEST:
        raise ValueError(f"pas Lobby/0x86: class={payload[0]:02X} type={payload[1]:02X}")
    message_id = payload[2:2+MESSAGEID_MAXLEN]
    key_raw = payload[2+MESSAGEID_MAXLEN:2+MESSAGEID_MAXLEN+SESSIONKEY_MAXLEN]
    session_key = key_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return {
        "message_id": message_id,
        "session_key_raw": key_raw,
        "session_key": session_key,
        "extra": payload[minimum:],
    }


def make_version_server_response(message_id: bytes, version_string: str) -> bytes:
    """Build the EyeToy-specific Lobby/0x87 response (79 bytes total)."""
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError(f"MessageID doit faire {MESSAGEID_MAXLEN} octets")
    raw = str(version_string).encode("ascii", errors="strict")
    if len(raw) >= VERSION_SERVER_STRING_LEN:
        raise ValueError(
            f"mas_version_string trop longue: {len(raw)} octets; maximum {VERSION_SERVER_STRING_LEN - 1}"
        )
    field = raw + b"\x00" + (b"\x00" * (VERSION_SERVER_STRING_LEN - len(raw) - 1))
    return bytes([MEDIUS_CLASS_LOBBY, MEDIUS_VERSION_SERVER_RESPONSE]) + message_id + field


# --- V020 post-VersionServer probes ------------------------------------------
# V019 proved that the 79-byte Lobby/0x87 is accepted. Immediately afterwards
# EyeToy sends class 4/type 0x0A (82 bytes), then class 1/type 0xA3 (50 bytes).
# V020 tested adjacent responses 0x0B and 0xA4 and EyeToy advanced. Horizon's
# public enum identifies 0xA3/0xA4 as SetLocalizationParams request/response,
# but the exact payload layouts used here remain experimental. V021 keeps them.
MEDIUS_EXT_PROBE_CLASS = 0x04
MEDIUS_EXT_PROBE_REQUEST = 0x0A
MEDIUS_EXT_PROBE_RESPONSE_DEFAULT = 0x0B
MEDIUS_A3_PROBE_CLASS = MEDIUS_CLASS_LOBBY
MEDIUS_A3_PROBE_REQUEST = 0xA3
MEDIUS_A3_PROBE_RESPONSE_DEFAULT = 0xA4

# V023 policy diagnostics. The V022 trace proved that EyeToy does NOT reconnect
# between rejected 0x48 replies: it retries 0x47 repeatedly on the same MAS TCP
# connection. Therefore auto_cycle must advance per 0x47 request, not per MAS
# connection. Keep the same four serializer candidates so the first four retries
# exercise every V022 layout without requiring an ISO/server restart.
MEDIUS_POLICY_CLASS = MEDIUS_CLASS_LOBBY
MEDIUS_POLICY_REQUEST = 0x47
MEDIUS_POLICY_RESPONSE = 0x48
POLICY_MAXLEN = 256
POLICY_RESPONSE_MODES = (
    "packed_284",       # MessageID + Status + Policy + EndOfText
    "pad_before_287",  # MessageID + 3 pad + Status + Policy + EndOfText
    "tail_pad_287",    # MessageID + Status + Policy + EndOfText + 3 pad
    "v021_290",        # V021: pad before Status and after EndOfText
)


def parse_ext0a_request(payload: bytes):
    """Parse only the byte layout proven by the V019 capture.

    Observed: class/type + MessageID[21] + SessionKey[17] + reserved[6]
              + blob_len(u32 LE) + blob[blob_len].
    The observed blob_len is 32 and the blob is all zero under the current test.
    """
    fixed = 2 + MESSAGEID_MAXLEN + SESSIONKEY_MAXLEN + 6 + 4
    if len(payload) < fixed:
        raise ValueError(f"class4/0x0A trop court: {len(payload)} octets (minimum {fixed})")
    if payload[0] != MEDIUS_EXT_PROBE_CLASS or payload[1] != MEDIUS_EXT_PROBE_REQUEST:
        raise ValueError(f"pas class4/0x0A: class={payload[0]:02X} type={payload[1]:02X}")
    off = 2
    message_id = payload[off:off+MESSAGEID_MAXLEN]; off += MESSAGEID_MAXLEN
    key_raw = payload[off:off+SESSIONKEY_MAXLEN]; off += SESSIONKEY_MAXLEN
    reserved = payload[off:off+6]; off += 6
    blob_len = struct.unpack_from("<I", payload, off)[0]; off += 4
    if blob_len > len(payload) - off:
        raise ValueError(f"class4/0x0A blob_len={blob_len} dépasse les {len(payload)-off} octets restants")
    blob = payload[off:off+blob_len]
    extra = payload[off+blob_len:]
    session_key = key_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return {
        "message_id": message_id,
        "session_key_raw": key_raw,
        "session_key": session_key,
        "reserved": reserved,
        "blob_len": blob_len,
        "blob": blob,
        "extra": extra,
    }


def parse_a3_request(payload: bytes):
    """Conservative parser for the 50-byte class1/0xA3 capture.

    Only MessageID[21] and the final two little-endian u32 values are exposed.
    In the V019 capture those tail values are 2 and 8. Their meaning is not
    asserted by V020; the middle bytes stay opaque.
    """
    minimum = 2 + MESSAGEID_MAXLEN + 8
    if len(payload) < minimum:
        raise ValueError(f"class1/0xA3 trop court: {len(payload)} octets (minimum {minimum})")
    if payload[0] != MEDIUS_A3_PROBE_CLASS or payload[1] != MEDIUS_A3_PROBE_REQUEST:
        raise ValueError(f"pas class1/0xA3: class={payload[0]:02X} type={payload[1]:02X}")
    message_id = payload[2:2+MESSAGEID_MAXLEN]
    opaque = payload[2+MESSAGEID_MAXLEN:-8]
    tail0, tail1 = struct.unpack_from("<II", payload, len(payload)-8)
    return {
        "message_id": message_id,
        "opaque": opaque,
        "tail0": tail0,
        "tail1": tail1,
    }


def parse_policy_request(payload: bytes):
    """Conservative parser for EyeToy's Lobby/0x47 packet.

    The V021 capture is 46 bytes. MessageID[21] is kept because the surrounding
    Medius messages use it consistently. The last 4 bytes are interpreted as the
    little-endian policy type (0 = Usage in the capture). The 19 bytes in between
    remain opaque; V021's SessionKey[17]+pad[2] interpretation is retained only
    as a diagnostic candidate and is NOT used to validate/reject the request.
    """
    minimum = 2 + MESSAGEID_MAXLEN + 4
    if len(payload) < minimum:
        raise ValueError(f"class1/0x47 Policy trop court: {len(payload)} octets (minimum {minimum})")
    if payload[0] != MEDIUS_POLICY_CLASS or payload[1] != MEDIUS_POLICY_REQUEST:
        raise ValueError(f"pas class1/0x47 Policy: class={payload[0]:02X} type={payload[1]:02X}")
    message_id = payload[2:2+MESSAGEID_MAXLEN]
    policy_type = struct.unpack_from("<i", payload, len(payload)-4)[0]
    opaque = payload[2+MESSAGEID_MAXLEN:-4]

    # V021's former interpretation, kept for logging only.
    legacy_key_raw = opaque[:SESSIONKEY_MAXLEN] if len(opaque) >= SESSIONKEY_MAXLEN else opaque
    legacy_reserved = opaque[SESSIONKEY_MAXLEN:SESSIONKEY_MAXLEN+2] if len(opaque) >= SESSIONKEY_MAXLEN else b""
    legacy_key = legacy_key_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return {
        "message_id": message_id,
        "opaque": opaque,
        "policy_type": policy_type,
        "legacy_session_key_raw": legacy_key_raw,
        "legacy_session_key": legacy_key,
        "legacy_reserved": legacy_reserved,
    }


def make_policy_response(message_id: bytes, policy_text: str, status_code: int = 0,
                         end_of_text: bool = True, mode: str = "packed_284") -> bytes:
    """Build a Lobby/0x48 PolicyResponse using a selected legacy alignment mode.

    All candidates keep the same semantic fields and differ only in the three-byte
    alignment before StatusCode and/or after EndOfText. This makes V023 a clean
    wire-layout experiment while preserving the working SCERT framing.
    """
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError(f"MessageID doit faire {MESSAGEID_MAXLEN} octets")
    if mode not in POLICY_RESPONSE_MODES:
        raise ValueError(f"mas_policy_response_mode inconnu: {mode!r}; choix={POLICY_RESPONSE_MODES}")
    policy_field = medius_fixed_string(policy_text, POLICY_MAXLEN)
    head = bytes([MEDIUS_POLICY_CLASS, MEDIUS_POLICY_RESPONSE]) + message_id
    status = struct.pack("<i", int(status_code))
    end = b"\x01" if end_of_text else b"\x00"
    if mode == "packed_284":
        return head + status + policy_field + end
    if mode == "pad_before_287":
        return head + b"\x00\x00\x00" + status + policy_field + end
    if mode == "tail_pad_287":
        return head + status + policy_field + end + b"\x00\x00\x00"
    if mode == "v021_290":
        return head + b"\x00\x00\x00" + status + policy_field + end + b"\x00\x00\x00"
    raise AssertionError(mode)


def choose_policy_response_mode(cfg, request_index: int = 0):
    """Choose the 0x48 serializer for the current 0x47 request.

    V022 advanced once per MAS connection, but the V022 capture showed that
    EyeToy keeps the same MAS connection alive and retries 0x47 hundreds of
    times when it rejects a PolicyResponse. V023 therefore advances on EACH
    0x47 request. request_index is zero-based within the current MAS connection.
    """
    requested = str(cfg.get("mas_policy_response_mode", "auto_cycle")).strip().lower()
    if requested != "auto_cycle":
        if requested not in POLICY_RESPONSE_MODES:
            raise ValueError(f"mas_policy_response_mode={requested!r} invalide")
        return requested, None

    configured = cfg.get("mas_policy_response_modes", list(POLICY_RESPONSE_MODES))
    modes = [str(x).strip().lower() for x in configured if str(x).strip().lower() in POLICY_RESPONSE_MODES]
    if not modes:
        modes = list(POLICY_RESPONSE_MODES)
    index = max(0, int(request_index))
    return modes[index % len(modes)], index


def load_policy_text(cfg, policy_type: int) -> tuple[str, str]:
    """Load policy.<type>.txt, falling back to policy.0.txt / a short local text."""
    root = Path(__file__).resolve().parent
    policy_dir = root / str(cfg.get("mas_policy_dir", "http_root/policies"))
    candidates = [policy_dir / f"policy.{int(policy_type)}.txt", policy_dir / "policy.0.txt"]
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8", errors="replace").strip(), str(candidate.relative_to(root))
        except OSError:
            pass
    return str(cfg.get("mas_policy_default_text", "EyeToy Chat Community Server policy")), "config/default"


def make_probe_status_response(net_class: int, response_type: int, message_id: bytes, status_code: int = 0, mode: str = "mid_pad_status") -> bytes:
    """Build a deliberately small experimental response for V020.

    mid_pad_status: class/type + MessageID[21] + pad[3] + int32 status (30 bytes)
    mid_status:     class/type + MessageID[21] + int32 status (27 bytes)
    """
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError(f"MessageID doit faire {MESSAGEID_MAXLEN} octets")
    head = bytes([int(net_class) & 0xFF, int(response_type) & 0xFF]) + message_id
    if mode == "mid_pad_status":
        return head + b"\x00\x00\x00" + struct.pack("<i", int(status_code))
    if mode == "mid_status":
        return head + struct.pack("<i", int(status_code))
    raise ValueError(f"mode de réponse probe inconnu: {mode!r}")


def handle_mas_v023(conn, addr, cfg):
    """Medius Authentication Server stage for EyeToy Chat.

    Performs the PS2 SCERT handshake, accepts CLIENT_CONNECT_TCP, answers the
    first Lobby/0x03 MediusSessionBeginRequest with a successful
    MediusSessionBeginResponse, then answers Lobby/0x86 with the 79-byte
    MessageID[21] + VersionString[56] Lobby/0x87 layout inferred from EyeToy's
    own binary. It retains the V020 responses for class4/0x0A and class1/0xA3.
    V023 recognizes Lobby/0x47 MediusGetPolicyRequest and cycles the 0x48
    serializer candidate on every 0x47 retry within the same MAS connection.
    The request tail is logged as
    opaque data so a misleading SessionKey comparison cannot hide the real
    wire-layout problem. ECHO remains alive.
    """
    conn.settimeout(4.0)
    port = int(cfg.get("mas_exact_port", cfg.get("universe_next_port", 10075)))
    log_event(cfg, "MAS-CONNECT", f"Connexion TCP MAS acceptée depuis {addr[0]}:{addr[1]} -> {port}; handshake + SessionBegin + VersionServer + post-version probes + Policy V032")
    buffer = b""
    rc_key = None
    peer_sent = False
    connect_accepted = False
    application_id = None
    first_app_seen = False
    session_begin_answered = False
    version_server_answered = False
    version_req_count = 0
    ext0a_req_count = 0
    a3_req_count = 0
    policy_req_count = 0
    policy_connection_mode = None
    policy_auto_index = None
    ext0a_answered = False
    a3_answered = False
    policy_answered = False
    deadline = time.time() + float(cfg.get("mas_capture_timeout", 300.0))
    frame_count = 0
    # V032: state local a chaque connexion MAS.
    v031_tls_fail_echoes = 0
    v031_close_requested = False
    try:
        while time.time() < deadline:
            frames, buffer = scert_extract_frames(buffer)
            if not frames:
                try:
                    data = conn.recv(8192)
                except socket.timeout:
                    continue
                if not data:
                    break
                buffer += data
                log_event(cfg, "MAS-RX", f"{len(data)} octets reçus depuis {addr[0]}:{addr[1]}", data)
                frames, buffer = scert_extract_frames(buffer)

            for frame in frames:
                frame_count += 1
                rt_id, encrypted, ctx, h, plain, ok = scert_decode_frame(frame, rc_key)
                name = RT_NAMES.get(rt_id, f"RT_MSG_{rt_id}")
                log_event(cfg, "MAS-FRAME", f"#{frame_count} {name} id={rt_id} encrypted={encrypted} ctx={ctx} len={struct.unpack_from('<H', frame, 1)[0]} decrypt_ok={ok}", frame)
                if plain is not None:
                    log_event(cfg, "MAS-PLAIN", f"#{frame_count} {name} plaintext {len(plain)} octets", plain)

                if rt_id == 18 and encrypted and ok and plain is not None and not peer_sent:
                    client_modulus = int.from_bytes(plain, "little", signed=False)
                    log_scert_rsa_identity(cfg, "MAS", client_modulus, "RT_MSG_CLIENT_CRYPTKEY_PUBLIC modulus")
                    rc_key = os.urandom(64)
                    cipher, rhash = rsa_auth_encrypt_for_client(rc_key, client_modulus)
                    reply = bytes([0x80 | 19]) + struct.pack("<H", 64) + rhash + cipher
                    conn.sendall(reply)
                    peer_sent = True
                    log_event(cfg, "MAS-RSA-OK", "RT_MSG_CLIENT_CRYPTKEY_PUBLIC déchiffré et hash validé avec la GLOBAL MEDIUS KEY; clé RC_CLIENT_SESSION générée")
                    log_scert_crypto_state(cfg, "MAS", "after_rsa_peer_key", rc_key, plain=plain, frame=reply)
                    log_event(cfg, "MAS-TX", "RT_MSG_SERVER_CRYPTKEY_PEER envoyé (id=19, RSA_AUTH)", reply)
                    continue

                if rt_id == 0 and peer_sent and ok and plain is not None and not connect_accepted:
                    try:
                        world_id, unk0, application_id, client_key, extra = parse_client_connect_tcp_old(plain)
                        log_event(cfg, "MAS-CONNECT-PARSED", f"CLIENT_CONNECT_TCP old-layout: TargetWorldId={world_id} (0x{world_id:08X}), UNK0=0x{unk0:02X}, AppId={application_id}, key64={len(client_key)} octets, extra={len(extra)}")
                    except Exception as e:
                        log_event(cfg, "MAS-CONNECT-PARSE-FAIL", str(e), plain)
                        application_id = None

                    ip = cfg.get("_runtime_advertise_ip") or local_ipv4()
                    accept_plain, accept_frame = make_server_connect_accept_tcp_old(ip, rc_key, player_id=0, player_count=1)
                    conn.sendall(accept_frame)
                    log_event(cfg, "MAS-TX", f"RT_MSG_SERVER_CONNECT_ACCEPT_TCP envoyé (id=7, client IP={ip}, PlayerId=0, PlayerCount=1)", accept_frame)
                    log_event(cfg, "MAS-TX-PLAIN", "SERVER_CONNECT_ACCEPT_TCP plaintext", accept_plain)

                    complete_plain, complete_frame = make_server_connect_complete(rc_key, arg1=1)
                    conn.sendall(complete_frame)
                    log_event(cfg, "MAS-TX", "RT_MSG_SERVER_CONNECT_COMPLETE envoyé (id=26, ARG1=1)", complete_frame)
                    log_event(cfg, "MAS-TX-PLAIN", "SERVER_CONNECT_COMPLETE plaintext", complete_plain)
                    connect_accepted = True
                    log_event(cfg, "MAS-STAGE", f"SCERT MAS CONNECT accepté pour AppId={application_id}. Attente du premier message Medius d'authentification.")
                    continue

                if rt_id == 5 and connect_accepted and ok and plain is not None:
                    echo = scert_make_encrypted(5, plain, rc_key, CTX_RC_CLIENT_SESSION)
                    conn.sendall(echo)
                    log_event(cfg, "MAS-ECHO", "RT_MSG_CLIENT_ECHO reçu et renvoyé", echo)
                    fail = v031_get_tls_failure(addr[0]) if bool(cfg.get("v031_disconnect_state_enabled", True)) else None
                    if fail and not fail.get("consumed"):
                        age = max(0.0, time.time() - float(fail.get("time", time.time())))
                        v031_tls_fail_echoes += 1
                        log_event(cfg, "V031-MAS-AFTER-TLS-FAIL", f"echo_after_fail={v031_tls_fail_echoes}; age={age:.1f}s; alert={fail.get('alert')}; profile={fail.get('profile')}; MAS toujours vivant")
                        min_echoes = max(1, int(cfg.get("v031_disconnect_after_echoes", 3)))
                        grace = max(0.0, float(cfg.get("v031_disconnect_grace_seconds", 25.0)))
                        mode = str(cfg.get("v031_disconnect_test_mode", "socket_close")).strip().lower()
                        if v031_tls_fail_echoes >= min_echoes and age >= grace and mode == "socket_close":
                            v031_consume_tls_failure(addr[0])
                            log_event(cfg, "V031-MAS-CONTROLLED-CLOSE", f"TEST socket_close: {v031_tls_fail_echoes} ECHO après échec TLS, age={age:.1f}s. Fermeture TCP MAS volontaire pour vérifier si EyeToy quitte l'écran de déconnexion.")
                            try:
                                conn.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
                            v031_close_requested = True
                            break
                    continue

                if rt_id == 11 and connect_accepted and ok and plain is not None:
                    nc = plain[0] if len(plain) >= 1 else None
                    mt = plain[1] if len(plain) >= 2 else None
                    is_version_req = (nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_VERSION_SERVER_REQUEST)
                    if is_version_req:
                        version_req_count += 1
                    interval = max(1, int(cfg.get("mas_version_retry_log_interval", 10)))
                    verbose_app = (not is_version_req) or version_req_count <= 2 or (version_req_count % interval == 0)
                    if verbose_app:
                        save_muis_plain(cfg, "mas_app", addr, plain)
                        log_event(cfg, "MAS-APP", f"RT_MSG_CLIENT_APP_TOSERVER déchiffré: {len(plain)} octets; NetMessageClass={nc}; MessageType={mt}; AppId={application_id}", plain)

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_SESSION_BEGIN_REQUEST:
                        try:
                            req = parse_session_begin_request(plain)
                            mid_hex = req["message_id"].hex(" ").upper()
                            cc = req["connection_class"]
                            cc_name = {0:"Modem",1:"Ethernet",2:"Wireless"}.get(cc, f"Unknown({cc})")
                            session_key = str(cfg.get("mas_session_key", "ETC0000000000001"))
                            log_event(cfg, "MAS-SESSION-BEGIN", f"MediusSessionBeginRequest: MessageID=[{mid_hex}]; ConnectionClass={cc} ({cc_name}); extra={len(req['extra'])}", plain)
                            response_plain = make_session_begin_response(req["message_id"], session_key, status_code=0)
                            response_frame = scert_make_encrypted(10, response_plain, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(response_frame)
                            log_event(cfg, "MAS-SESSION-TX", f"MediusSessionBeginResponse SUCCESS envoyé; SessionKey={session_key!r}", response_plain)
                            log_event(cfg, "MAS-SESSION-TX-SCERT", "RT_MSG_SERVER_APP chiffré envoyé (SessionBeginResponse)", response_frame)
                            first_app_seen = True
                            session_begin_answered = True
                        except Exception as e:
                            log_event(cfg, "MAS-SESSION-ERROR", f"Impossible de répondre au SessionBegin: {e}", plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_VERSION_SERVER_REQUEST:
                        try:
                            req = parse_version_server_request(plain)
                            mid_hex = req["message_id"].hex(" ").upper()
                            expected_key = str(cfg.get("mas_session_key", "ETC0000000000001"))
                            key_ok = (req["session_key"] == expected_key)
                            version_string = str(cfg.get(
                                "mas_version_string",
                                "Medius Authentication Server Version 1.51.0001"
                            ))
                            if verbose_app:
                                log_event(
                                    cfg, "MAS-VERSION-REQ",
                                    f"Lobby/0x86 VersionServer #{version_req_count}: MessageID=[{mid_hex}]; "
                                    f"SessionKey={req['session_key']!r}; key_match={key_ok}; "
                                    f"extra={len(req['extra'])}", plain
                                )
                            if version_req_count > 1 and verbose_app:
                                log_event(
                                    cfg, "MAS-VERSION-RETRY",
                                    f"EyeToy a redemandé Lobby/0x86 après notre 0x87; tentative #{version_req_count}."
                                )
                            response_plain = make_version_server_response(req["message_id"], version_string)
                            response_frame = scert_make_encrypted(
                                10, response_plain, rc_key, CTX_RC_CLIENT_SESSION
                            )
                            conn.sendall(response_frame)
                            log_scert_crypto_state(cfg, "MAS", "tx_0x87", rc_key, plain=response_plain, frame=response_frame)
                            if verbose_app:
                                log_event(
                                    cfg, "MAS-VERSION-TX",
                                    f"Lobby/0x87 VersionServerResponse envoyé; "
                                    f"layout=MessageID[21]+VersionString[56]; len={len(response_plain)}; "
                                    f"version={version_string!r}", response_plain
                                )
                                log_event(
                                    cfg, "MAS-VERSION-TX-SCERT",
                                    "RT_MSG_SERVER_APP chiffré envoyé (VersionServerResponse)",
                                    response_frame
                                )
                            version_server_answered = True
                        except Exception as e:
                            log_event(cfg, "MAS-VERSION-ERROR", f"Impossible de répondre au Lobby/0x86: {e}", plain)
                        continue

                    # V020 probe 1: exact class4/0x0A packet first seen after the
                    # accepted VersionServer response. Response class4/0x0B is an
                    # explicit experiment and can be disabled/changed in config.
                    if nc == MEDIUS_EXT_PROBE_CLASS and mt == MEDIUS_EXT_PROBE_REQUEST:
                        ext0a_req_count += 1
                        try:
                            req = parse_ext0a_request(plain)
                            expected_key = str(cfg.get("mas_session_key", "ETC0000000000001"))
                            key_ok = (req["session_key"] == expected_key)
                            zero_blob = bool(req["blob"]) and all(b == 0 for b in req["blob"])
                            log_event(
                                cfg, "MAS-EXT0A-REQ",
                                f"class4/0x0A probe #{ext0a_req_count}: SessionKey={req['session_key']!r}; "
                                f"key_match={key_ok}; reserved={req['reserved'].hex(' ').upper()}; "
                                f"blob_len={req['blob_len']}; blob_all_zero={zero_blob}; extra={len(req['extra'])}",
                                plain
                            )
                            if bool(cfg.get("mas_ext0a_probe_enabled", True)):
                                response_type = int(cfg.get("mas_ext0a_response_type", MEDIUS_EXT_PROBE_RESPONSE_DEFAULT))
                                mode = str(cfg.get("mas_ext0a_response_mode", "mid_pad_status"))
                                response_plain = make_probe_status_response(
                                    MEDIUS_EXT_PROBE_CLASS, response_type, req["message_id"], 0, mode
                                )
                                response_frame = scert_make_encrypted(10, response_plain, rc_key, CTX_RC_CLIENT_SESSION)
                                conn.sendall(response_frame)
                                log_event(
                                    cfg, "MAS-EXT0A-TX",
                                    f"PROBE expérimental envoyé: class=4 type=0x{response_type:02X}; "
                                    f"mode={mode}; StatusCode=0; len={len(response_plain)}",
                                    response_plain
                                )
                                log_event(cfg, "MAS-EXT0A-TX-SCERT", "RT_MSG_SERVER_APP chiffré envoyé (probe class4/0x0A)", response_frame)
                                ext0a_answered = True
                            else:
                                log_event(cfg, "MAS-EXT0A-SKIP", "Probe class4/0x0A désactivé dans config.json")
                        except Exception as e:
                            log_event(cfg, "MAS-EXT0A-ERROR", f"Impossible d'analyser/répondre au class4/0x0A: {e}", plain)
                        continue

                    # V020 probe 2: class1/0xA3 follows class4/0x0A in the V019
                    # capture. Only the byte layout is trusted; type 0xA4 is an
                    # adjacent-ID response experiment, not a verified name/layout.
                    if nc == MEDIUS_A3_PROBE_CLASS and mt == MEDIUS_A3_PROBE_REQUEST:
                        a3_req_count += 1
                        try:
                            req = parse_a3_request(plain)
                            log_event(
                                cfg, "MAS-A3-REQ",
                                f"class1/0xA3 probe #{a3_req_count}: opaque_len={len(req['opaque'])}; "
                                f"tail_u32_0={req['tail0']}; tail_u32_1={req['tail1']}",
                                plain
                            )
                            if bool(cfg.get("mas_a3_probe_enabled", True)):
                                response_type = int(cfg.get("mas_a3_response_type", MEDIUS_A3_PROBE_RESPONSE_DEFAULT))
                                mode = str(cfg.get("mas_a3_response_mode", "mid_pad_status"))
                                response_plain = make_probe_status_response(
                                    MEDIUS_A3_PROBE_CLASS, response_type, req["message_id"], 0, mode
                                )
                                response_frame = scert_make_encrypted(10, response_plain, rc_key, CTX_RC_CLIENT_SESSION)
                                conn.sendall(response_frame)
                                log_event(
                                    cfg, "MAS-A3-TX",
                                    f"PROBE expérimental envoyé: class=1 type=0x{response_type:02X}; "
                                    f"mode={mode}; StatusCode=0; len={len(response_plain)}",
                                    response_plain
                                )
                                log_event(cfg, "MAS-A3-TX-SCERT", "RT_MSG_SERVER_APP chiffré envoyé (probe class1/0xA3)", response_frame)
                                a3_answered = True
                            else:
                                log_event(cfg, "MAS-A3-SKIP", "Probe class1/0xA3 désactivé dans config.json")
                        except Exception as e:
                            log_event(cfg, "MAS-A3-ERROR", f"Impossible d'analyser/répondre au class1/0xA3: {e}", plain)
                        continue

                    # V024: V023 proved pad_before_287 is the first layout that stops the
                    # immediate 0x47 retry. The config now locks pad_before_287; the old
                    # serializer list remains available only for manual diagnostics.
                    if nc == MEDIUS_POLICY_CLASS and mt == MEDIUS_POLICY_REQUEST:
                        policy_req_count += 1
                        try:
                            req = parse_policy_request(plain)
                            policy_name = {0: "Usage", 1: "Privacy"}.get(req["policy_type"], f"Unknown({req['policy_type']})")
                            log_event(
                                cfg, "MAS-POLICY-REQ",
                                f"MediusGetPolicyRequest 0x47 #{policy_req_count}: "
                                f"MessageID=[{req['message_id'].hex(' ').upper()}]; "
                                f"opaque_len={len(req['opaque'])}; opaque=[{req['opaque'].hex(' ').upper()}]; "
                                f"legacy_key_candidate={req['legacy_session_key']!r}; "
                                f"legacy_reserved={req['legacy_reserved'].hex(' ').upper()}; "
                                f"Policy={req['policy_type']} ({policy_name})",
                                plain
                            )
                            if bool(cfg.get("mas_policy_enabled", True)):
                                # V024: fixed mode from config (pad_before_287); auto_cycle still works if manually re-enabled.
                                policy_connection_mode, policy_auto_index = choose_policy_response_mode(
                                    cfg, request_index=policy_req_count - 1
                                )
                                cycle_note = (
                                    f"; retry_index={policy_auto_index}; cycle_slot="
                                    f"{policy_auto_index % max(1, len(cfg.get('mas_policy_response_modes', list(POLICY_RESPONSE_MODES))))}"
                                    if policy_auto_index is not None else "; mode_manuel"
                                )
                                log_event(
                                    cfg, "MAS-POLICY-MODE",
                                    f"Serializer 0x48 pour requête 0x47 #{policy_req_count}: "
                                    f"{policy_connection_mode}{cycle_note}. "
                                    f"Ordre auto={cfg.get('mas_policy_response_modes', list(POLICY_RESPONSE_MODES))}"
                                )
                                policy_text, policy_source = load_policy_text(cfg, req["policy_type"])
                                response_plain = make_policy_response(
                                    req["message_id"], policy_text, status_code=0, end_of_text=True,
                                    mode=policy_connection_mode
                                )
                                response_frame = scert_make_encrypted(10, response_plain, rc_key, CTX_RC_CLIENT_SESSION)
                                conn.sendall(response_frame)
                                log_event(
                                    cfg, "MAS-POLICY-TX",
                                    f"MediusGetPolicyResponse 0x48 envoyé; mode={policy_connection_mode}; "
                                    f"StatusCode=0; Policy={req['policy_type']} ({policy_name}); source={policy_source!r}; "
                                    f"text_len={len(policy_text.encode('utf-8', errors='replace'))}; "
                                    f"EndOfText=1; len={len(response_plain)}",
                                    response_plain
                                )
                                log_scert_crypto_state(cfg, "MAS", "tx_0x48", rc_key, plain=response_plain, frame=response_frame)
                                log_event(cfg, "MAS-POLICY-TX-SCERT", "RT_MSG_SERVER_APP chiffré envoyé (MediusGetPolicyResponse 0x48 V030)", response_frame)
                                policy_answered = True
                            else:
                                log_event(cfg, "MAS-POLICY-SKIP", "Réponse Policy 0x47/0x48 désactivée dans config.json")
                        except Exception as e:
                            log_event(cfg, "MAS-POLICY-ERROR", f"Impossible d'analyser/répondre au MediusGetPolicyRequest 0x47: {e}", plain)
                        continue

                    if not first_app_seen:
                        first_app_seen = True
                        log_event(cfg, "MAS-NEXT", f"Premier message Medius MAS inattendu: class={nc} type={mt}", plain)
                    elif policy_answered:
                        log_event(cfg, "MAS-NEXT", f"NOUVEAU message Medius capturé après MediusGetPolicyResponse 0x48 V030: class={nc} type={mt}", plain)
                    elif ext0a_answered or a3_answered:
                        log_event(cfg, "MAS-NEXT", f"NOUVEAU message Medius capturé après probes V020: class={nc} type={mt}", plain)
                    elif version_server_answered:
                        log_event(cfg, "MAS-NEXT", f"Message Medius suivant capturé après VersionServer: class={nc} type={mt}", plain)
                    elif session_begin_answered:
                        log_event(cfg, "MAS-NEXT", f"Message Medius suivant capturé après SessionBegin: class={nc} type={mt}", plain)
                    else:
                        log_event(cfg, "MAS-NEXT", f"Message Medius suivant capturé: class={nc} type={mt}", plain)
                    continue

                if peer_sent and rt_id not in (18, 0, 33, 5, 11):
                    if ok:
                        log_event(cfg, "MAS-NEXT", f"Message SCERT suivant capturé: {name} (id={rt_id})")
                    else:
                        log_event(cfg, "MAS-NEXT", f"Message SCERT suivant reçu mais non déchiffré: {name} ctx={ctx}")
    except Exception as e:
        log_event(cfg, "ERROR", f"MAS V030 {addr}: {e}")
    finally:
        if buffer:
            log_event(cfg, "MAS-TAIL", f"Données SCERT incomplètes restantes: {len(buffer)} octets", buffer)
        try:
            conn.close()
        except OSError:
            pass

class MASListener(threading.Thread):
    """Dedicated listener for the Medius Authentication Server.

    This deliberately owns TCP/10075 so an old generic probe path can never
    swallow the MAS handshake.
    """
    daemon = True
    def __init__(self, cfg):
        super().__init__(name="MAS-Dedicated")
        self.cfg = cfg
        self.port = int(cfg.get("mas_exact_port", cfg.get("universe_next_port", 10075)))

    def run(self):
        bind_ip = self.cfg.get("bind_ip", "0.0.0.0")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((bind_ip, self.port))
            s.listen(32)
        except OSError as e:
            log_event(self.cfg, "ERROR", f"MAS TCP {self.port} impossible: {e}")
            return
        log_event(self.cfg, "MAS-LISTEN", f"listener MAS dédié actif sur {bind_ip}:{self.port} (V030)")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_mas_v023, args=(conn, addr, self.cfg), daemon=True).start()

class TCPProbe(threading.Thread):
    daemon = True
    def __init__(self, cfg, port):
        super().__init__(name=f"TCP-{port}")
        self.cfg = cfg
        self.port = port

    def run(self):
        bind_ip = self.cfg.get("bind_ip", "0.0.0.0")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((bind_ip, self.port))
            s.listen(32)
        except OSError as e:
            log_event(self.cfg, "ERROR", f"TCP {self.port} impossible: {e}")
            return
        log_event(self.cfg, "TCP", f"écoute sur {bind_ip}:{self.port}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def handle(self, conn, addr):
        if self.port == int(self.cfg.get("muis_exact_port", 10080)):
            return handle_muis_v014(conn, addr, self.cfg)
        if self.port == int(self.cfg.get("update_tls_port", 10443)) and bool(self.cfg.get("update_tls_enabled", True)):
            return handle_update_tls_v027(conn, addr, self.cfg)
        conn.settimeout(5.0)
        chunks = []
        try:
            # Some protocols wait for the server to speak first; keep the socket alive briefly.
            try:
                first = conn.recv(8192)
            except socket.timeout:
                first = b""
            if first:
                chunks.append(first)
                tls = guess_tls(first)
                desc = f"connexion {addr[0]}:{addr[1]} -> TCP/{self.port}, {len(first)} octets"
                if tls:
                    desc += f"; handshake probable {tls}"
                tag = f"TCP/{self.port}"
                log_event(self.cfg, tag, desc, first)
                if self.port == int(self.cfg.get("muis_exact_port", 10080)):
                    log_event(self.cfg, "MUIS-RAW", f"Premier paquet MUIS reçu sur TCP/{self.port} depuis {addr[0]}:{addr[1]} ({len(first)} octets)", first)
                    try:
                        rawdir = ROOT / self.cfg.get("log_dir", "logs") / "raw"
                        rawdir.mkdir(parents=True, exist_ok=True)
                        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                        rawpath = rawdir / f"muis_{addr[0].replace('.', '_')}_{addr[1]}_{stamp}.bin"
                        rawpath.write_bytes(first)
                        log_event(self.cfg, "MUIS-SAVE", f"Paquet brut sauvegardé: {rawpath.relative_to(ROOT)}")
                    except Exception as e:
                        log_event(self.cfg, "ERROR", f"Sauvegarde paquet MUIS: {e}")
                elif self.port == 10443:
                    log_event(self.cfg, "UPDATE-10443", f"Connexion TCP/10443 observée depuis {addr[0]}:{addr[1]} (port update historique, pas MUIS)", first)

                if self.port in set(map(int, self.cfg.get("http_plain_ports", [80, 443]))) and first.startswith((b"GET ", b"HEAD ", b"POST ")):
                    response, path, body = http_response_for(first, self.cfg)
                    if response:
                        conn.sendall(response)
                        log_event(self.cfg, "HTTP", f"{addr[0]} -> {path}; réponse={len(response)} octets")
                        if path and path.rstrip("/").lower() == "/qa_patches/index.xml":
                            log_event(self.cfg, "UPDATE-INDEX", f"Réponse catalogue mode={self.cfg.get('update_mode', 'no_update')} BUILD={self.cfg.get('update_build', 194)}", body)
                else:
                    # Read a little more without inventing a Medius reply yet.
                    while sum(map(len, chunks)) < int(self.cfg.get("log_payload_limit", 8192)):
                        try:
                            more = conn.recv(4096)
                        except socket.timeout:
                            break
                        if not more:
                            break
                        chunks.append(more)
                        log_event(self.cfg, f"TCP/{self.port}", f"suite {addr[0]}:{addr[1]}, {len(more)} octets", more)
            else:
                log_event(self.cfg, f"TCP/{self.port}", f"connexion {addr[0]}:{addr[1]} sans données dans les 5 s")
        except Exception as e:
            log_event(self.cfg, "ERROR", f"TCP/{self.port} {addr}: {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass


class UDPProbe(threading.Thread):
    daemon = True
    def __init__(self, cfg, port):
        super().__init__(name=f"UDP-{port}")
        self.cfg = cfg
        self.port = port

    def run(self):
        bind_ip = self.cfg.get("bind_ip", "0.0.0.0")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((bind_ip, self.port))
        except OSError as e:
            log_event(self.cfg, "ERROR", f"UDP {self.port} impossible: {e}")
            return
        log_event(self.cfg, "UDP", f"écoute sur {bind_ip}:{self.port}")
        while True:
            try:
                data, addr = s.recvfrom(65535)
                log_event(self.cfg, f"UDP/{self.port}", f"{addr[0]}:{addr[1]} -> {len(data)} octets", data)
            except Exception as e:
                log_event(self.cfg, "ERROR", f"UDP/{self.port}: {e}")



class NetstatWatcher(threading.Thread):
    """Windows-only diagnostic helper.

    It does not intercept traffic. It records local TCP connections whose remote
    destination is in the Medius/MUIS candidate range or the hard-coded IP seen
    in the EyeToy Chat binary. This helps identify a connection that bypasses
    our local DNS/listeners (for example a hard-coded destination).
    """
    daemon = True
    def __init__(self, cfg):
        super().__init__(name="NETSTAT-WATCH")
        self.cfg = cfg
        self.seen = set()

    def run(self):
        if os.name != "nt" or not self.cfg.get("netstat_watch", True):
            return
        log_event(self.cfg, "NETSTAT", "surveillance des connexions sortantes Medius/MUIS active")
        while True:
            try:
                cp = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=3)
                current = set()
                for line in cp.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 5 or parts[0].upper() != "TCP":
                        continue
                    local, remote, state, pid = parts[1], parts[2], parts[3], parts[4]
                    # Windows IPv4 output is generally IP:port. Keep parsing deliberately permissive.
                    try:
                        rip, rport_s = remote.rsplit(":", 1)
                        rport = int(rport_s)
                    except Exception:
                        continue
                    interesting = (10000 <= rport <= 11000) or rip.endswith("43.194.211.76")
                    if not interesting:
                        continue
                    item = (local, remote, state, pid)
                    current.add(item)
                    if item not in self.seen:
                        log_event(self.cfg, "NETSTAT-MUIS", f"{local} -> {remote} state={state} pid={pid}")
                self.seen = current
            except Exception as e:
                log_event(self.cfg, "NETSTAT", f"surveillance impossible: {e}")
                return
            time.sleep(0.35)

def make_placeholder_files(cfg):
    files = {
        "index.txt": "EyeToy Chat Local Server V030 - historical SCEE CA probe\n",
        "chatroom_hierarchy_1_51.xml": "<?xml version=\"1.0\"?><chatrooms></chatrooms>\n",
        "announcements/announcements.0.txt": "EyeToy Chat local server V008\n",
        "policies/policy.0.txt": "EyeToy Chat local server test policy\n"
    }
    for rel, content in files.items():
        p = HTTP_ROOT / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_text(content, encoding="utf-8")

    # Always overwrite this one so an old V007 XML cannot survive an upgrade.
    idx = HTTP_ROOT / "qa_patches" / "index.xml"
    idx.parent.mkdir(parents=True, exist_ok=True)
    idx.write_bytes(build_update_index(cfg))


def selftest(cfg, advertise_ip):
    safe_print("[SELFTEST] DNS parser/response...")
    # example.com A query, txid 0x1234
    qname = b"\x07example\x03com\x00"
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
    name, qt, qc, _ = parse_dns_name(query)
    assert name == "example.com" and qt == 1 and qc == 1
    response = build_a_response(query, advertise_ip)
    assert socket.inet_aton(advertise_ip) in response
    xml = build_update_index(cfg)
    assert b'<patches BUILD="194"/>' in xml
    req = b"GET /qa_patches/index.xml HTTP/1.0\r\nHost: eyetoychat-update.online.scee.com\r\n\r\n"
    http, path, body = http_response_for(req, cfg)
    assert path == "/qa_patches/index.xml" and b"HTTP/1.0 200 OK" in http and body == xml
    safe_print("[SELFTEST] UPDATE XML -> <patches BUILD=\"194\"/>")
    safe_print("[SELFTEST] EyeToy DNS local -> " + advertise_ip)
    safe_print("[SELFTEST] DNAS = passthrough DNS communautaire; UPDATE attendu explicitement sur TCP/80")
    safe_print("[SELFTEST] MUIS exact -> TCP/10080; univers actif -> MAS TCP/10075")
    captured = bytes.fromhex("92 40 00 4E 3E 85 E8 16 63 B9 C6 18 05 B1 C5 D6 18 3C 1D 49 08 AB 29 AE 08 81 4A 59 FE BD A2 B4 1F 0D 1F 1F C0 CF E8 B2 24 F0 DE B9 D4 97 EB 1E BB C2 82 5A 9B F3 92 74 3C F2 27 E5 9D 37 48 4F B9 D8 57 6F 6E BB 9C")
    rid, enc, ctx, hh, plain, ok = scert_decode_frame(captured)
    assert rid == 18 and enc and ctx == 7 and ok and plain is not None and len(plain) == 64
    test_rc = bytes(range(64))
    cipher, rh = rsa_auth_encrypt_for_client(test_rc, int.from_bytes(plain, "little"))
    reply = bytes([0x93, 0x40, 0x00]) + rh + cipher
    assert len(reply) == 71
    rc_h = ps2_sha1_4(b"V014", CTX_RC_CLIENT_SESSION)
    rc_key = bytes(range(64))
    assert ps2_rc4_decrypt(rc_key, ps2_rc4_encrypt(rc_key, b"V014", rc_h), rc_h) == b"V014"
    captured_connect_plain = bytes.fromhex("01 08 87 01 00 3A 29 00 00 9E 40 CF 82 12 CA CF 64 10 40 0A C0 89 D5 F8 ED ED 48 26 A6 48 C8 F4 18 2F E1 A9 AA 14 A2 32 0E 86 76 CB A6 A1 83 7B CC 22 58 D3 B8 70 EB 28 92 48 2D AC 82 FA A6 68 C1 55 F9 43 A9 00 89 D8 48")
    wid, unk, appid, ckey, extra = parse_client_connect_tcp_old(captured_connect_plain)
    assert wid == 0x01870801 and unk == 0 and appid == 10554 and len(ckey) == 64 and not extra
    ap, af = make_server_connect_accept_tcp_old("192.168.1.75", rc_key)
    cp, cf = make_server_connect_complete(rc_key)
    assert len(ap) == 23 and len(af) == 30 and ap[:7] == bytes.fromhex("01 08 10 00 00 01 00")
    assert ap[7:] == b"192.168.1.75".ljust(16, b"\x00")
    assert cp == b"\x01\x00" and len(cf) == 9
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(af, rc_key)
    assert rid == 7 and enc and ctx == 3 and ok and pp == ap
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(cf, rc_key)
    assert rid == 26 and enc and ctx == 3 and ok and pp == cp
    safe_print("[SELFTEST] Capture réelle -> RT_MSG_CLIENT_CRYPTKEY_PUBLIC RSA_AUTH: déchiffrement/hash OK")
    safe_print("[SELFTEST] Capture CLIENT_CONNECT_TCP -> old-layout AppId=10554 confirmé")
    safe_print("[SELFTEST] SERVER_CONNECT_ACCEPT_TCP old-layout -> framing RC OK")
    safe_print("[SELFTEST] SERVER_CONNECT_COMPLETE ARG1=1 -> framing RC OK")
    safe_print("[SELFTEST] PS2 RC_CLIENT_SESSION encrypt/decrypt: OK")
    captured_universe = bytes.fromhex("01 C8 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 7A 00 00 00 02 00 00 00 02 00 00 00")
    ur = parse_get_universe_information(captured_universe)
    assert ur["info_type"] == 0x7A and ur["character_encoding"] == 2 and ur["language"] == 2
    assert set(info_filter_names(ur["info_type"])) == {"NEWS", "NAME", "DNS", "DESCRIPTION", "STATUS"}
    uresp = make_universe_variable_information_response(ur["message_id"], ur["info_type"], advertise_ip, int(cfg.get("universe_next_port", 10075)), "EyeToy Chat Europe", "EyeToy Chat Community Server")
    assert uresp[:2] == bytes([4, 0x11]) and len(uresp) == 563
    assert socket.inet_aton(advertise_ip) is not None and advertise_ip.encode("ascii") in uresp
    nresp = make_universe_news_response(ur["message_id"], "EyeToy Chat Community Server")
    assert nresp[:2] == bytes([1, 0xC9]) and len(nresp) == 290
    uf = scert_make_encrypted(10, uresp, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(uf, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == uresp
    safe_print("[SELFTEST] Lobby/0xC8 -> InfoType 0x7A = NEWS+NAME+DNS+DESCRIPTION+STATUS")
    safe_print(f"[SELFTEST] Universe response -> {advertise_ip}:{int(cfg.get('universe_next_port', 10075))}")
    safe_print("[SELFTEST] UniverseVariableInformationResponse + UniverseNewsResponse framing: OK")

    # Real EyeToy Chat MAS capture from V016-FIX1: Lobby/0x03 SessionBegin, Ethernet=1.
    captured_session_begin = bytes.fromhex(
        "01 03 38 00 82 01 00 00 00 00 00 00 00 00 00 00 "
        "00 00 28 2D 82 01 00 00 00 00 01 00 00 00"
    )
    sreq = parse_session_begin_request(captured_session_begin)
    assert sreq["connection_class"] == 1 and len(sreq["message_id"]) == MESSAGEID_MAXLEN and not sreq["extra"]
    sresp = make_session_begin_response(sreq["message_id"], str(cfg.get("mas_session_key", "ETC0000000000001")), status_code=0)
    assert len(sresp) == 50 and sresp[:2] == bytes([MEDIUS_CLASS_LOBBY, MEDIUS_SESSION_BEGIN_RESPONSE])
    assert sresp[2:23] == sreq["message_id"] and struct.unpack_from("<i", sresp, 26)[0] == 0
    sf = scert_make_encrypted(10, sresp, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(sf, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == sresp
    safe_print("[SELFTEST] MAS Lobby/0x03 SessionBegin réel -> Ethernet=1; Lobby/0x04 SUCCESS framing: OK")

    # Real EyeToy capture: Lobby/0x86 carries the exact SessionKey we returned.
    captured_version_server = bytes.fromhex(
        "01 86 33 00 82 01 00 00 00 00 00 00 00 00 00 00 "
        "00 00 45 54 43 30 00 "
        "45 54 43 30 30 30 30 30 30 30 30 30 30 30 30 31 00"
    )
    vreq = parse_version_server_request(captured_version_server)
    assert len(vreq["message_id"]) == MESSAGEID_MAXLEN
    assert vreq["session_key"] == "ETC0000000000001"
    assert not vreq["extra"]
    banner = str(cfg.get("mas_version_string", "Medius Authentication Server Version 1.51.0001"))
    vresp = make_version_server_response(vreq["message_id"], banner)
    assert len(vresp) == 2 + MESSAGEID_MAXLEN + VERSION_SERVER_STRING_LEN == 79
    assert vresp[:2] == bytes([MEDIUS_CLASS_LOBBY, MEDIUS_VERSION_SERVER_RESPONSE])
    assert vresp[2:23] == vreq["message_id"]
    version_field = vresp[23:23+VERSION_SERVER_STRING_LEN]
    assert version_field.split(b"\x00", 1)[0].decode("ascii") == banner
    assert version_field[-1] == 0
    vf = scert_make_encrypted(10, vresp, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(vf, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == vresp
    safe_print("[SELFTEST] MAS Lobby/0x86 réel -> SessionKey reconnue")
    safe_print(f"[SELFTEST] MAS Lobby/0x87 EyeToy layout 21+56 = {len(vresp)} octets; banner={banner!r}: OK")

    # Exact post-VersionServer packets captured with V019. Their semantic names
    # are intentionally not asserted; V020 tests only the observed byte layouts.
    captured_ext0a = bytes.fromhex(
        "04 0A 34 39 36 38 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 45 54 43 30 30 30 30 30 30 "
        "30 30 30 30 30 30 31 00 00 00 00 00 00 00 20 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00"
    )
    xreq = parse_ext0a_request(captured_ext0a)
    assert len(captured_ext0a) == 82
    assert xreq["session_key"] == "ETC0000000000001"
    assert xreq["blob_len"] == 32 and len(xreq["blob"]) == 32 and all(b == 0 for b in xreq["blob"])
    assert xreq["reserved"] == b"\x00" * 6 and not xreq["extra"]
    xtype = int(cfg.get("mas_ext0a_response_type", MEDIUS_EXT_PROBE_RESPONSE_DEFAULT))
    xmode = str(cfg.get("mas_ext0a_response_mode", "mid_pad_status"))
    xresp = make_probe_status_response(4, xtype, xreq["message_id"], 0, xmode)
    assert xresp[:2] == bytes([4, xtype & 0xFF]) and xresp[2:23] == xreq["message_id"]
    if xmode == "mid_pad_status": assert len(xresp) == 30
    if xmode == "mid_status": assert len(xresp) == 27
    xf = scert_make_encrypted(10, xresp, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(xf, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == xresp
    safe_print(f"[SELFTEST] V019 capture class4/0x0A -> blob_len=32; V020 probe 0x{xtype:02X} framing: OK")

    captured_a3 = bytes.fromhex(
        "01 A3 34 39 36 39 00 00 00 00 00 00 00 00 00 00 "
        "00 00 45 54 43 30 00 30 30 30 30 30 30 30 30 30 "
        "30 31 00 2D 82 01 00 00 00 00 02 00 00 00 08 00 "
        "00 00"
    )
    areq = parse_a3_request(captured_a3)
    assert len(captured_a3) == 50
    assert areq["tail0"] == 2 and areq["tail1"] == 8
    atype = int(cfg.get("mas_a3_response_type", MEDIUS_A3_PROBE_RESPONSE_DEFAULT))
    amode = str(cfg.get("mas_a3_response_mode", "mid_pad_status"))
    aresp = make_probe_status_response(1, atype, areq["message_id"], 0, amode)
    assert aresp[:2] == bytes([1, atype & 0xFF]) and aresp[2:23] == areq["message_id"]
    if amode == "mid_pad_status": assert len(aresp) == 30
    if amode == "mid_status": assert len(aresp) == 27
    af = scert_make_encrypted(10, aresp, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(af, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == aresp
    safe_print(f"[SELFTEST] V019 capture class1/0xA3 -> tail u32=2,8; V020 probe 0x{atype:02X} framing: OK")

    # Exact MediusGetPolicyRequest 0x47 captured after restarting the ISO with V020.
    captured_policy = bytes.fromhex(
        "01 47 36 00 82 01 00 00 00 00 00 00 00 00 00 00 "
        "00 00 45 54 43 30 00 30 30 30 30 30 30 30 30 30 "
        "30 31 00 2D 82 01 00 00 00 00 00 00 00 00"
    )
    preq = parse_policy_request(captured_policy)
    assert len(captured_policy) == 46
    assert len(preq["message_id"]) == MESSAGEID_MAXLEN
    assert len(preq["opaque"]) == 19
    assert preq["policy_type"] == 0
    policy_text, _ = load_policy_text(cfg, preq["policy_type"])
    expected_lengths = {
        "packed_284": 284,
        "pad_before_287": 287,
        "tail_pad_287": 287,
        "v021_290": 290,
    }
    for pmode in POLICY_RESPONSE_MODES:
        presp = make_policy_response(preq["message_id"], policy_text, 0, True, pmode)
        assert len(presp) == expected_lengths[pmode]
        assert presp[:2] == bytes([MEDIUS_POLICY_CLASS, MEDIUS_POLICY_RESPONSE])
        assert presp[2:23] == preq["message_id"]
        pf = scert_make_encrypted(10, presp, rc_key, CTX_RC_CLIENT_SESSION)
        rid, enc, ctx, hh, pp, ok = scert_decode_frame(pf, rc_key)
        assert rid == 10 and enc and ctx == 3 and ok and pp == presp
    chosen, idx = choose_policy_response_mode({**cfg, "mas_policy_response_mode": "pad_before_287"}, 0)
    assert chosen == "pad_before_287" and idx is None
    accepted = make_policy_response(preq["message_id"], policy_text, 0, True, chosen)
    assert len(accepted) == 287
    safe_print("[SELFTEST] V030 Policy 0x48 verrouillée sur pad_before_287 (287 octets): OK")

    # TLS 1.0 primitives used by the 10443 compatibility endpoint.
    sample_ch_record = bytes.fromhex(
        "16 03 01 00 4F 01 00 00 4B 03 01 6A 83 81 82 5F "
        "18 D9 B9 D8 EE 81 67 5B 8B C0 26 C4 DB 5E E2 CB "
        "C3 26 EB 21 5B 6D AB D0 C4 56 8F 00 00 24 00 66 "
        "00 16 00 13 00 0A 00 05 00 04 00 15 00 12 00 09 "
        "00 63 00 65 00 62 00 64 00 14 00 11 00 08 00 06 "
        "00 03 01 00"
    )
    assert guess_tls(sample_ch_record) == "TLS1.0"
    ch = _tls_parse_client_hello(sample_ch_record[5:])
    assert ch["version"] == TLS10_VERSION and TLS_RSA_WITH_RC4_128_SHA in ch["cipher_suites"]
    assert TLS_CERT_DER_PATH.is_file() and len(TLS_CERT_DER_PATH.read_bytes()) > 400
    for _pname, _paths in TLS_CERT_PROFILES.items():
        _available = _paths and all(_p.is_file() and len(_p.read_bytes()) > 300 for _p in _paths)
        if _pname in ("historical_scee_root_probe", "beta_test_ca_probe") and not _available:
            safe_print(f"[SELFTEST] {_pname}: optional historical material not present -> SKIP")
            continue
        assert _available, _pname
    test_secret = bytes(range(48))
    cr = bytes(range(32)); sr = bytes(range(32,64))
    master, cdec, senc = _tls_key_schedule(test_secret, cr, sr, TLS_RSA_WITH_RC4_128_SHA)
    assert len(master) == 48
    # Independent matching pair for record round-trip.
    _, c1, s1 = _tls_key_schedule(test_secret, cr, sr, TLS_RSA_WITH_RC4_128_SHA)
    _, c2, s2 = _tls_key_schedule(test_secret, cr, sr, TLS_RSA_WITH_RC4_128_SHA)
    ct = s1.encrypt(TLS_CONTENT_APPLICATION_DATA, TLS10_VERSION, b"GET / HTTP/1.0\r\n\r\n")
    pt, mac_ok, _, _ = s2.decrypt(TLS_CONTENT_APPLICATION_DATA, TLS10_VERSION, ct)
    assert mac_ok and pt == b"GET / HTTP/1.0\r\n\r\n"
    safe_print("[SELFTEST] V032 TLS1.0 + local certificate profiles + optional historical probes + PRF + RC4/HMAC: OK")
    safe_print("[SELFTEST] OK")
    return 0


def main():
    parser = argparse.ArgumentParser(description="EyeToy Chat PS2 Local Server V030")
    parser.add_argument("--ip", help="IPv4 LAN à renvoyer par le DNS (défaut: auto)")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    cfg = load_config()
    ensure_dirs(cfg)
    make_placeholder_files(cfg)
    advertise_ip = args.ip or cfg.get("advertise_ip", "auto")
    if advertise_ip == "auto":
        advertise_ip = local_ipv4()
    try:
        socket.inet_aton(advertise_ip)
    except OSError:
        safe_print(f"IP invalide: {advertise_ip}")
        return 2

    cfg["_runtime_advertise_ip"] = advertise_ip
    log_event(cfg, "VERSION", "EyeToyChat Server V032 - fixed MAS disconnect-state diagnostics")
    log_scert_rsa_identity(cfg, "SCERT", MEDIUS_RSA_N, "server RSA_AUTH key (GLOBAL MEDIUS KEY)")
    _tls_log_persistent_state(cfg)
    try:
        _hist = ROOT / "tls" / "scee_mis_root_2002.der"
        if _hist.is_file():
            _b = _hist.read_bytes()
            log_event(cfg, "UPDATE-TLS-HISTORICAL-CA", f"SCEE MIS root 2002 chargee; der_len={len(_b)}; sha1={hashlib.sha1(_b).hexdigest()}; source=EyeToy Chat Europe Beta 2004-05-10; private_key=absente_du_disque_client")
    except Exception as _e:
        log_event(cfg, "UPDATE-TLS-HISTORICAL-CA-ERROR", str(_e))
    try:
        _beta = ROOT / "tls" / "beta_test_ca_43.194.211.76.der"
        if _beta.is_file():
            _bb = _beta.read_bytes()
            log_event(cfg, "UPDATE-TLS-BETA-TEST-CA", f"Beta Test Cert charge; CN=43.194.211.76; der_len={len(_bb)}; sha1={hashlib.sha1(_bb).hexdigest()}; source=EyeToy Chat Europe Beta 2004-05-10; private_key=non_trouvee_dans_image_client")
    except Exception as _e:
        log_event(cfg, "UPDATE-TLS-BETA-TEST-CA-ERROR", str(_e))

    if args.selftest:
        return selftest(cfg, advertise_ip)

    safe_print("=" * 68)
    safe_print(" EyeToy: Chat PS2 - Community Server V032 - fixed MAS disconnect-state diagnostics")
    safe_print(f" IP locale annoncée : {advertise_ip}")
    safe_print(" Services EyeToy redirigés vers ce PC :")
    for x in ("eyetoychat-master.online.scee.com", "eyetoychat-update.online.scee.com", "vmail.online.scee.com"):
        safe_print(f"   {x} -> {advertise_ip}")
    safe_print(f" Update : /qa_patches/index.xml -> BUILD={cfg.get('update_build', 194)} ({cfg.get('update_mode', 'no_update')})")
    safe_print(" Update : ISO compagnon force explicitement TCP/80")
    safe_print(f" Update TLS : TLS1.0 TCP/{int(cfg.get('update_tls_port', 10443))}, profils certificats V030 + dual trust-anchor probes + capture HTTP")
    safe_print(" Policy 0x48 : pad_before_287 verrouillé d'après le passage observé en V023")
    safe_print(f" MUIS Universe : {cfg.get('universe_name', 'EyeToy Chat Europe')} -> {advertise_ip}:{int(cfg.get('universe_next_port', 10075))}")
    safe_print(f" MAS : SCERT crypto/connect actif sur TCP/{int(cfg.get('mas_exact_port', cfg.get('universe_next_port', 10075)))}; VersionServer OK + probes class4/0x0A et class1/0xA3")
    safe_print(" DNAS : direct vers le serveur communautaire")
    safe_print("   gate1.eu.dnas.playstation.org -> réponse du DNS communautaire")
    safe_print("   DNS DNAS upstream : " + ", ".join(cfg.get("dnas_dns_upstreams", ["45.7.228.197"])))
    safe_print("=" * 68)

    threads = [DNSServer(cfg, advertise_ip), DNSTCPServer(cfg, advertise_ip)]
    threads.append(NetstatWatcher(cfg))
    mas_port = int(cfg.get("mas_exact_port", cfg.get("universe_next_port", 10075)))
    threads.append(MASListener(cfg))
    for p in sorted(set(map(int, cfg.get("tcp_probe_ports", [])))):
        if p == mas_port:
            continue
        threads.append(TCPProbe(cfg, p))
    for p in sorted(set(map(int, cfg.get("udp_probe_ports", [])))):
        threads.append(UDPProbe(cfg, p))
    for t in threads:
        t.start()

    safe_print("\nServeur lancé. Sur la PS2, mets DNS primaire ET secondaire sur :", advertise_ip)
    safe_print("Puis lance EyeToy: Chat et tente la connexion en ligne.")
    safe_print("Les résultats apparaîtront ici et dans le dossier logs/. Ctrl+C pour arrêter.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        safe_print("\nArrêt demandé.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
