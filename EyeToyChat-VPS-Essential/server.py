#!/usr/bin/env python3
"""
EyeToy: Chat PS2 - Community Server 0.3.0
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
import re
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
VERSION = "0.3.0-beta1-public"

# V036 protocol confidence map.
# Keep capture-proven layouts separate from names inferred from public Medius work.
PROTOCOL_KNOWLEDGE = {
    "SCERT_RSA": ("confirmed", "64-byte client RSA modulus + 64-byte RC session key exchange captured and decoded"),
    "CLIENT_CONNECT_TCP": ("confirmed", "old PS2 layout; TargetWorldId=0x01870801, AppId=10554"),
    "SESSION_BEGIN_03_04": ("confirmed", "EyeToy capture + accepted response"),
    "VERSION_SERVER_86_87": ("confirmed", "0x87 is 79 bytes: MessageID[21] + VersionString[56]"),
    "EXT_0A_0B": ("experimental", "wire layout captured; adjacent 0x0B response advances client; semantics unknown"),
    "LOCALIZATION_A3_A4": ("probable", "public Medius naming suggests SetLocalizationParams; EyeToy payload tail 2,8 matches encoding/language candidates; exact layout remains experimental"),
    "POLICY_47_48": ("confirmed", "0x47 captured; pad_before_287 is first 0x48 layout that stopped immediate retry"),
    "POST_POLICY": ("confirmed", "client proceeds through AccountLogin, MLS, vmail configuration, announcements and chatroom hierarchy"),
    "CHATROOM_HTTP": ("confirmed", "13/13 V063 sessions reached intact hierarchy HTTP responses after successful MAS/MLS/TLS stages"),
    "POST_CHATROOM_XML": ("confirmed", "video-correlated capture proves AccountLogout can follow the local CouldNotReadFile/No EyeToy Chat settings memory-card error; do not treat logout alone as XML rejection"),
    "CHATROOM_MENU_METADATA": ("confirmed", "retail MAINGAME.MSN reads menu/chatroom title and icon; V065 restored both on the language menu"),
    "CHATROOM_CALLBACK_METADATA": ("confirmed", "retail callback requires root vmail_inbox_size plus localized chatroom_welcome%d and welcome%d/version before accepting the hierarchy"),
    "CHATROOM_PROFILE_VALUES": ("experimental", "V066 retains separately selectable Holding/1000 and Default/1 tuples; original SCEE wire mapping remains unproven"),
    "ACCOUNT_UPDATE_STATS_11_12": ("confirmed", "V067 capture emitted Lobby/0x11 AccountUpdateStats after public+private ProfileRetrieve; Horizon layout is MessageID[21]+SessionKey[17]+Stats[256], response Lobby/0x12 with status"),
    "BUDDY_INVITATIONS_08_09": ("confirmed", "V068 capture emitted LobbyExt/0x08 immediately after accepted AccountUpdateStats 0x12; public Medius implementations map 0x08/0x09 to GetBuddyInvitations request/response"),
    "MUIS_NORMAL_LOGIN_PATH": ("experimental", "V072 live trace disproved the V071 Universe Status=0 probe: client receives C9/news then disconnects without MAS. V074 keeps Status=2 and corrects the localized hierarchy callback suffix to English index 1 while preserving the AdFeed PNG probe"),
    "PROFILE_POST": ("confirmed", "V070 live capture sends POST /mt/servlet/ProfilePost with Content-Length=252; old TLS reader stopped at headers, so V071 reads and logs the complete binary body before ACK"),
    "SOCIAL_V075": ("experimental", "persistent account IDs, FindPlayer, buddy add/remove, D7 presence, profile persistence and chat relay use public Medius layouts; EyeToy-specific invitation confirmation flow still requires live capture"),
    "SOCIAL_V076_IGNORE": ("probable", "standard Medius Lobby 0xC0-0xC5 ignore/block list layouts match retail BlockSender/BlockedUsers UI strings"),
    "SOCIAL_V076_BINARY": ("probable", "standard LobbyExt 0x16/0x17 BinaryMessage/BinaryFwdMessage uses a 400-byte payload; V076 relays and captures it without guessing EyeToy semantics"),
    "VIDEOMAIL_V076": ("experimental", "retail Mail.PostURL/Mail.InboxURL/Mail.RetrieveURL/Mail.DeleteURL and HTTP field strings are confirmed; V076 stores/captures bodies but does not claim the original inbox XML schema"),
    "PHOTO_V076": ("experimental", "retail CHATROOMPHOTO%d, CHATROOM_LOCALPLAYERPROFILE, ETChatPhotosMediusGame and thumbnail feature flags confirm a separate photo path; V076 captures candidate HTTP/binary traffic without inventing its codec"),
    "PAL_MULTILANG_V077": ("confirmed", "live 2026-08-26 captures: English uses policy/announcements .1 and progresses; another PAL UI language uses .2 and stopped because hierarchy exposed only welcome1; V077 exposes callback suffixes 1..11"),
    "TEXT_ROOM_V078": ("experimental", "community configuration adds one TEXT256 room named Chat Francais on the already-working WorldID 1 tuple; room naming is an operator choice"),
    "ORIGINAL_HTTPS_V079": ("confirmed", "unpatched HTTPS path reaches TCP/10443 and retail chain is rejected with TLS alert 45 certificate_expired before ClientKeyExchange"),
    "NATIVE_TLS_CA_V080": ("experimental", "community RSA-1024 Root CA replaces only the XOR-obfuscated public trust anchor in MAINGAME.MSN; fresh SHA1/RSA update/vmail leaves are valid 2025-2036"),
    "DNAS21_ONLY_TLS_V082": ("confirmed", "V041/V046 delegated SCEE update and vmail chains reached ClientKeyExchange and completed TLS 1.0 with PS2 RTC set to 2006; no V080 Root-CA ISO patch is used"),
    "CLIENT_RTC_GUARD_V083": ("confirmed", "TLS 1.0 ClientHello random starts with gmt_unix_time; V083 decodes it and reports a direct 2006 clock fix when it falls outside the delegated SCEE certificate window"),
    "EVERGREEN_TLS_V085": ("experimental", "fresh 2000-2049 update/vmail leafs signed by the recovered EyeToy Chat Client key test whether the embedded historical certificate can be used without patching the retail trust root"),
    "TIMELESS_TRUST_V086": ("experimental", "V085 live traces proved a server-only chain cannot satisfy both trust and 2026 validity; V086 replaces only the XOR-obfuscated public trust anchor and serves matching 2000-2049 leaves"),
    "ROOM_TREE_V086": ("experimental", "community test tree mirrors the captured language -> theme -> TEXT256 room breadcrumb with Francais/English and General/Sport"),
}


# ---------------------------------------------------------------------------
# V037 X.509 Validation-Order Matrix diagnostics
#
# Current experimental evidence:
#   historical/beta expired material -> TLS alert 45 (certificate_expired)
#   beta date-mutated material        -> TLS alert 46 (certificate_unknown)
#
# V037 deliberately keeps the proven Medius/SCERT path unchanged and focuses
# on TLS certificate selection, reproducible matrix logging, and distinguishing
# certificate/time/trust/identity gates.  Alert names are observations, not
# assumptions about the client's internal validation implementation.
# ---------------------------------------------------------------------------
V037_TLS_MATRIX = [
    "v086_update_2000_2049",
    "v086_vmail_2000_2049",
    "v085_evergreen_leaf_only_update",
    "v085_selfissued_leaf_only_update",
    "v085_evergreen_chain_update",
    "retail_delegated_server_probe",
    "retail_delegated_vmail_probe",
    "v080_update_2026",
    "v080_vmail_2026",
    "retail_client_signed_probe",
    "beta_test_ca_probe",
    "beta_test_date_mutation_probe",
    "historical_scee_root_probe",
    "historical_scee_date_mutation_probe",
    "legacy_minimal",
    "legacy_v3_san",
    "generated_chain",
    "selfsigned_v024",
]
V037_TLS_ALERT_HINTS = {
    42: "bad_certificate",
    45: "certificate_expired",
    46: "certificate_unknown",
    48: "unknown_ca",
    51: "decrypt_error",
}


def _v037_matrix_paths(cfg):
    logdir = ROOT / str(cfg.get("log_dir", "logs"))
    logdir.mkdir(parents=True, exist_ok=True)
    return logdir / "tls_x509_matrix_v037.jsonl", logdir / "tls_x509_matrix_v037.tsv"


def _v037_record_tls_verdict(cfg, profile: str, outcome: str, detail: str = ""):
    """Persist one TLS certificate-validation result for cross-run comparison."""
    try:
        chain = _tls_load_cert_chain(profile)
        validity = [_tls_cert_validity_strings(c) for c in chain]
        sha1s = [hashlib.sha1(c).hexdigest() for c in chain]
    except Exception:
        chain, validity, sha1s = [], [], []
    row = {
        "time": now(),
        "profile": profile,
        "outcome": outcome,
        "detail": detail,
        "inference": _tls_alert_research_hint(detail, profile) if detail else "client_advanced",
        "chain_len": len(chain),
        "validity": validity,
        "sha1": sha1s,
    }
    jsonl, tsv = _v037_matrix_paths(cfg)
    with jsonl.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    new = not tsv.exists()
    with tsv.open("a", encoding="utf-8") as f:
        if new:
            f.write("time\tprofile\toutcome\tdetail\tinference\tvalidity\tsha1\n")
        f.write("{time}\t{profile}\t{outcome}\t{detail}\t{inference}\t{validity}\t{sha1}\n".format(
            **{k: str(v).replace("\t", " ").replace("\n", " ") for k, v in row.items()}
        ))
    log_event(cfg, "V037-X509-MATRIX-RESULT", f"profile={profile}; outcome={outcome}; detail={detail}; inference={row['inference']}; validity={validity}")


def _v037_reset_tls_matrix(cfg):
    """Reset persistent certificate state and V037 verdict files."""
    targets = [_tls_state_path(cfg), *_v037_matrix_paths(cfg)]
    for path in targets:
        try:
            if path.exists():
                path.unlink()
        except OSError as e:
            safe_print(f"[V037] impossible de supprimer {path}: {e}")
    safe_print("[V037] état TLS et matrice X.509 réinitialisés.")


def v035_print_tls_matrix_config(cfg):
    """Print a reproducible TLS experiment header without changing protocol behavior."""
    requested = str(cfg.get("update_tls_cert_profile", "")).strip()
    forced = str(cfg.get("v034_force_tls_profile", cfg.get("v035_force_tls_profile", ""))).strip()
    effective = forced or requested
    safe_print("[V037-TLS-MATRIX] requested=%s; forced=%s; effective=%s" %
               (requested or "<none>", forced or "<none>", effective or "<none>"))
    safe_print("[V037-TLS-MATRIX] available=" + ",".join(V037_TLS_MATRIX))
    safe_print("[V037-TLS-MATRIX] evidence=expired_material->45; beta_date_mutation->46")

def log_protocol_knowledge(cfg):
    if not bool(cfg.get("v034_log_protocol_confidence", True)):
        return
    for name, (confidence, note) in PROTOCOL_KNOWLEDGE.items():
        log_event(cfg, "V037-PROTOCOL-KNOWLEDGE", f"stage={name}; confidence={confidence}; {note}")

# These names are forced in code on purpose. V003 could accidentally run with an
# older config.json, which caused gate1.eu.dnas.playstation.org to be forwarded
# upstream and return NXDOMAIN (-611 on the PS2).
FORCED_DNS_EXACT = {
    "eyetoychat-master.online.scee.com",
    "eyetoychat-update.online.scee.com",
    "vmail.online.scee.com",
}
FORCED_DNS_SUFFIXES = ()

# V044: remember which EyeToy/SCEE hostname each client resolved most recently.
# TLS 1.0 ClientHello has no SNI, but EyeToy performs a DNS lookup immediately
# before TCP/10443, so this is a reliable local hostname-selection signal.
V044_SERVICE_DNS_LOCK = threading.Lock()
V044_SERVICE_DNS = {}  # client_ip -> (normalized_host, monotonic_time)
V044_LOGIN_STATE_LOCK = threading.Lock()
V044_LOGIN_STATE = {}  # client_ip -> account/session metadata from MAS login

# V075 persistent social layer.  It intentionally lives beside server.py so a
# community operator can back it up independently from packet/log captures.
V075_SOCIAL_LOCK = threading.RLock()
V075_ACTIVE_LOCK = threading.RLock()
V075_ACTIVE_SESSIONS = {}  # account_id -> {conn, rc_key, send_lock, client_ip, application_id, lobby_world_id, lobby_name}


def v075_social_state_path(cfg):
    rel = str(cfg.get("v075_social_state_file", "social_state.json"))
    path = (ROOT / rel).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError:
        path = ROOT / "social_state.json"
    return path


def _v075_default_social_state(cfg):
    return {"version": 2, "next_account_id": max(1, int(cfg.get("mas_account_id", 1))), "accounts": {}}


def _v075_load_social_unlocked(cfg):
    path = v075_social_state_path(cfg)
    if not path.is_file():
        return _v075_default_social_state(cfg)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("root is not object")
        data["version"] = max(2, int(data.get("version", 1) or 1))
        data.setdefault("next_account_id", max(1, int(cfg.get("mas_account_id", 1))))
        data.setdefault("accounts", {})
        for rec in data.get("accounts", {}).values():
            if not isinstance(rec, dict):
                continue
            rec.setdefault("buddies", [])
            rec.setdefault("pending_invites", [])
            rec.setdefault("sent_invites", [])
            rec.setdefault("ignored", [])
            rec.setdefault("profile_public_hex", "")
            rec.setdefault("profile_private_hex", "")
            rec.setdefault("stats_hex", "")
        return data
    except Exception as e:
        log_event(cfg, "V075-SOCIAL-STATE-ERROR", f"Lecture {path.name}: {e}; état vierge utilisé")
        return _v075_default_social_state(cfg)


def _v075_save_social_unlocked(cfg, data):
    path = v075_social_state_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def v075_register_account(cfg, username):
    name = (username or "EyeToyUser").strip()[:31] or "EyeToyUser"
    key = name.casefold()
    with V075_SOCIAL_LOCK:
        data = _v075_load_social_unlocked(cfg)
        accounts = data["accounts"]
        rec = accounts.get(key)
        if rec is None:
            used = {int(x.get("account_id", 0)) for x in accounts.values() if isinstance(x, dict)}
            candidate = max(int(data.get("next_account_id", 1)), int(cfg.get("mas_account_id", 1)))
            while candidate in used:
                candidate += 1
            rec = {
                "account_id": candidate, "name": name, "buddies": [], "pending_invites": [],
                "sent_invites": [], "ignored": [],
                "profile_public_hex": "", "profile_private_hex": "", "stats_hex": "", "last_seen": now(),
                "online": False, "last_ip": "", "application_id": 10554,
                "lobby_world_id": 0, "lobby_name": ""
            }
            accounts[key] = rec
            data["next_account_id"] = candidate + 1
            _v075_save_social_unlocked(cfg, data)
            log_event(cfg, "V075-SOCIAL-ACCOUNT-CREATE", f"AccountID={candidate}; Username={name!r}")
        else:
            rec["name"] = name
            rec["last_seen"] = now()
            _v075_save_social_unlocked(cfg, data)
        return dict(rec)


def v075_account_by_id(cfg, account_id):
    aid = int(account_id)
    with V075_SOCIAL_LOCK:
        data = _v075_load_social_unlocked(cfg)
        for rec in data.get("accounts", {}).values():
            if isinstance(rec, dict) and int(rec.get("account_id", -1)) == aid:
                return dict(rec)
    return None


def v075_account_by_name(cfg, username):
    key = (username or "").strip().casefold()
    with V075_SOCIAL_LOCK:
        rec = _v075_load_social_unlocked(cfg).get("accounts", {}).get(key)
        return dict(rec) if isinstance(rec, dict) else None


def v075_update_account(cfg, account_id, **changes):
    aid = int(account_id)
    with V075_SOCIAL_LOCK:
        data = _v075_load_social_unlocked(cfg)
        for rec in data.get("accounts", {}).values():
            if isinstance(rec, dict) and int(rec.get("account_id", -1)) == aid:
                rec.update(changes)
                rec["last_seen"] = now()
                _v075_save_social_unlocked(cfg, data)
                return dict(rec)
    return None


def v075_set_online(cfg, account_id, online, client_ip="", application_id=None, lobby_world_id=None, lobby_name=None):
    changes = {"online": bool(online), "last_ip": str(client_ip or "")}
    if application_id is not None: changes["application_id"] = int(application_id)
    if lobby_world_id is not None: changes["lobby_world_id"] = int(lobby_world_id)
    if lobby_name is not None: changes["lobby_name"] = str(lobby_name)
    return v075_update_account(cfg, account_id, **changes)


def v075_buddy_records(cfg, account_id):
    me = v075_account_by_id(cfg, account_id)
    if not me: return []
    out = []
    for aid in me.get("buddies", []):
        rec = v075_account_by_id(cfg, aid)
        if rec: out.append(rec)
    return out


def v075_invitation_records(cfg, account_id):
    me = v075_account_by_id(cfg, account_id)
    if not me: return []
    out = []
    for aid in me.get("pending_invites", []):
        rec = v075_account_by_id(cfg, aid)
        if rec: out.append(rec)
    return out


def v075_add_buddy_symmetric(cfg, account_id, target_id):
    a, b = int(account_id), int(target_id)
    if a == b: return False
    with V075_SOCIAL_LOCK:
        data = _v075_load_social_unlocked(cfg)
        by_id = {int(r.get("account_id", -1)): r for r in data.get("accounts", {}).values() if isinstance(r, dict)}
        if a not in by_id or b not in by_id: return False
        for x, y in ((a,b),(b,a)):
            lst = [int(v) for v in by_id[x].setdefault("buddies", [])]
            if y not in lst: lst.append(y)
            by_id[x]["buddies"] = sorted(set(lst))
            by_id[x]["pending_invites"] = [int(v) for v in by_id[x].get("pending_invites", []) if int(v) != y]
        _v075_save_social_unlocked(cfg, data)
        return True


def v075_remove_buddy_symmetric(cfg, account_id, target_id):
    a, b = int(account_id), int(target_id)
    with V075_SOCIAL_LOCK:
        data = _v075_load_social_unlocked(cfg)
        by_id = {int(r.get("account_id", -1)): r for r in data.get("accounts", {}).values() if isinstance(r, dict)}
        if a not in by_id: return False
        for x, y in ((a,b),(b,a)):
            if x in by_id:
                by_id[x]["buddies"] = [int(v) for v in by_id[x].get("buddies", []) if int(v) != y]
        _v075_save_social_unlocked(cfg, data)
        return True



def v076_request_friendship(cfg, account_id, target_id):
    """Persist a symmetric friendship invitation without fabricating a push packet."""
    a, b = int(account_id), int(target_id)
    if a == b:
        return False
    with V075_SOCIAL_LOCK:
        data = _v075_load_social_unlocked(cfg)
        by_id = {int(r.get("account_id", -1)): r for r in data.get("accounts", {}).values() if isinstance(r, dict)}
        if a not in by_id or b not in by_id:
            return False
        if b in [int(v) for v in by_id[a].get("buddies", [])]:
            return True
        pending = [int(v) for v in by_id[b].setdefault("pending_invites", [])]
        sent = [int(v) for v in by_id[a].setdefault("sent_invites", [])]
        if a not in pending:
            pending.append(a)
        if b not in sent:
            sent.append(b)
        by_id[b]["pending_invites"] = sorted(set(pending))
        by_id[a]["sent_invites"] = sorted(set(sent))
        _v075_save_social_unlocked(cfg, data)
        return True


def v076_accept_friendship(cfg, account_id, originator_id, symmetric=True):
    """Convert a pending invitation into buddy relation(s)."""
    me, origin = int(account_id), int(originator_id)
    with V075_SOCIAL_LOCK:
        data = _v075_load_social_unlocked(cfg)
        by_id = {int(r.get("account_id", -1)): r for r in data.get("accounts", {}).values() if isinstance(r, dict)}
        if me not in by_id or origin not in by_id:
            return False
        pending = [int(v) for v in by_id[me].get("pending_invites", [])]
        if origin not in pending:
            return False
        by_id[me]["pending_invites"] = [v for v in pending if v != origin]
        by_id[origin]["sent_invites"] = [int(v) for v in by_id[origin].get("sent_invites", []) if int(v) != me]
        ml = [int(v) for v in by_id[me].setdefault("buddies", [])]
        if origin not in ml:
            ml.append(origin)
        by_id[me]["buddies"] = sorted(set(ml))
        if symmetric:
            ol = [int(v) for v in by_id[origin].setdefault("buddies", [])]
            if me not in ol:
                ol.append(me)
            by_id[origin]["buddies"] = sorted(set(ol))
        _v075_save_social_unlocked(cfg, data)
        return True


def v076_ignore_records(cfg, account_id):
    me = v075_account_by_id(cfg, account_id)
    if not me:
        return []
    out = []
    for aid in me.get("ignored", []):
        rec = v075_account_by_id(cfg, aid)
        if rec:
            out.append(rec)
    return out


def v076_is_ignored(cfg, owner_id, other_id):
    owner = v075_account_by_id(cfg, owner_id)
    if not owner:
        return False
    return int(other_id) in [int(v) for v in owner.get("ignored", [])]


def v076_set_ignored(cfg, account_id, target_id, ignored=True):
    a, b = int(account_id), int(target_id)
    if a == b:
        return False
    with V075_SOCIAL_LOCK:
        data = _v075_load_social_unlocked(cfg)
        by_id = {int(r.get("account_id", -1)): r for r in data.get("accounts", {}).values() if isinstance(r, dict)}
        if a not in by_id or b not in by_id:
            return False
        vals = [int(v) for v in by_id[a].setdefault("ignored", [])]
        if ignored and b not in vals:
            vals.append(b)
        if not ignored:
            vals = [v for v in vals if v != b]
        by_id[a]["ignored"] = sorted(set(vals))
        _v075_save_social_unlocked(cfg, data)
        return True


def v076_delivery_allowed(cfg, origin_id, target_id):
    """Block delivery when either endpoint has explicitly ignored the other."""
    if not origin_id or not target_id:
        return True
    return not (v076_is_ignored(cfg, target_id, origin_id) or v076_is_ignored(cfg, origin_id, target_id))

def v075_store_profile(cfg, username, is_private, body):
    rec = v075_account_by_name(cfg, username) or v075_register_account(cfg, username)
    field = "profile_private_hex" if is_private else "profile_public_hex"
    clipped = bytes(body[:int(cfg.get("v075_profile_max_bytes", 1048576))])
    v075_update_account(cfg, rec["account_id"], **{field: clipped.hex()})
    return rec["account_id"], len(clipped)


def v075_load_profile(cfg, username, is_private):
    rec = v075_account_by_name(cfg, username)
    if not rec: return b""
    field = "profile_private_hex" if is_private else "profile_public_hex"
    try: return bytes.fromhex(str(rec.get(field, "")))
    except ValueError: return b""


def v075_login_state_for_ip(client_ip):
    with V044_LOGIN_STATE_LOCK:
        return dict(V044_LOGIN_STATE.get(client_ip, {}))


def v075_register_active_session(cfg, account_id, conn, rc_key, client_ip, application_id):
    if not account_id or rc_key is None: return
    with V075_ACTIVE_LOCK:
        V075_ACTIVE_SESSIONS[int(account_id)] = {
            "conn": conn, "rc_key": bytes(rc_key), "send_lock": threading.Lock(),
            "client_ip": str(client_ip), "application_id": int(application_id or 10554),
            "lobby_world_id": 0, "lobby_name": ""
        }
    profile = v064_chatroom_profile(cfg)
    v075_set_online(cfg, account_id, True, client_ip, application_id or 10554,
                    profile.get("channel_world_id", 1), profile.get("channel_name", "Default"))
    log_event(cfg, "V075-SOCIAL-ONLINE", f"AccountID={account_id}; ip={client_ip}; online=1")


def v081_set_active_room(cfg, account_id, world_id, lobby_name=""):
    """Bind an active MLS session to its current Medius channel/world."""
    if not account_id:
        return False
    with V075_ACTIVE_LOCK:
        sess = V075_ACTIVE_SESSIONS.get(int(account_id))
        if not sess:
            return False
        sess["lobby_world_id"] = int(world_id or 0)
        sess["lobby_name"] = str(lobby_name or "")
    log_event(cfg, "V081-ROOM-BIND", f"AccountID={int(account_id)}; WorldID={int(world_id or 0)}; Lobby={str(lobby_name or '')!r}")
    return True


def v081_targets_in_room(account_id, include_self=False):
    """Return active accounts bound to the sender's current WorldID."""
    aid = int(account_id or 0)
    with V075_ACTIVE_LOCK:
        sender = V075_ACTIVE_SESSIONS.get(aid)
        world_id = int((sender or {}).get("lobby_world_id", 0) or 0)
        if world_id <= 0:
            return [], world_id
        targets = [int(other_id) for other_id, sess in V075_ACTIVE_SESSIONS.items()
                   if int(sess.get("lobby_world_id", 0) or 0) == world_id
                   and (include_self or int(other_id) != aid)]
    return targets, world_id


def v081_gameworld_probe(cfg, nc, mt, plain, account_id):
    """Capture-only watcher for possible hidden Medius game-world traffic. No reply is fabricated."""
    watched = {
        (MEDIUS_CLASS_LOBBY, 0x1D): "CreateGameRequest0",
        (MEDIUS_CLASS_LOBBY, 0x23): "JoinGameRequest0",
        (MEDIUS_CLASS_LOBBY_EXT, 0x2F): "CreateGame",
        (MEDIUS_CLASS_LOBBY_EXT, 0xF3): "JoinGame",
        (MEDIUS_CLASS_LOBBY_EXT, 0xF4): "CreateGame1",
    }
    label = watched.get((int(nc), int(mt)))
    marker = b"ETChatPhotosMediusGame" in plain
    if not label and not marker:
        return None
    outdir = _v076_media_root(cfg) / "medius_gameworld_candidates"
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    label_file = re.sub(r"[^A-Za-z0-9_.-]+", "_", label or "marker")
    fp = outdir / f"{stamp}_acct{int(account_id or 0)}_c{int(nc):02X}_t{int(mt):02X}_{label_file}.bin"
    fp.write_bytes(plain)
    ascii_runs = re.findall(rb"[ -~]{4,}", plain)
    preview = " | ".join(x[:96].decode("ascii", errors="replace") for x in ascii_runs[:8])
    log_event(cfg, "V081-GAMEWORLD-WATCH",
              f"AccountID={int(account_id or 0)}; class=0x{int(nc):02X}; type=0x{int(mt):02X}; "
              f"label={label or 'marker'}; ETChatPhotosMediusGame={int(marker)}; len={len(plain)}; "
              f"ascii={preview!r}; saved={fp.relative_to(ROOT)}", plain)
    return fp


def v075_reset_online_state(cfg):
    with V075_SOCIAL_LOCK:
        data = _v075_load_social_unlocked(cfg)
        changed = False
        for rec in data.get("accounts", {}).values():
            if isinstance(rec, dict) and rec.get("online"):
                rec["online"] = False; changed = True
        if changed:
            _v075_save_social_unlocked(cfg, data)


def v075_unregister_active_session(cfg, account_id, conn):
    if not account_id: return
    removed = False
    with V075_ACTIVE_LOCK:
        cur = V075_ACTIVE_SESSIONS.get(int(account_id))
        if cur and cur.get("conn") is conn:
            V075_ACTIVE_SESSIONS.pop(int(account_id), None); removed = True
    if removed:
        v075_set_online(cfg, account_id, False)
        log_event(cfg, "V075-SOCIAL-OFFLINE", f"AccountID={account_id}; online=0")


def v075_send_to_account(cfg, account_id, medius_payload):
    with V075_ACTIVE_LOCK:
        sess = V075_ACTIVE_SESSIONS.get(int(account_id))
    if not sess: return False
    frame = scert_make_encrypted(10, medius_payload, sess["rc_key"], CTX_RC_CLIENT_SESSION)
    try:
        with sess["send_lock"]:
            sess["conn"].sendall(frame)
        return True
    except OSError as e:
        log_event(cfg, "V075-SOCIAL-SEND-ERROR", f"AccountID={account_id}: {e}")
        return False

def v044_note_service_dns(client_ip: str, host: str):
    n = normalize_dns_name(host)
    if n not in FORCED_DNS_EXACT:
        return
    with V044_SERVICE_DNS_LOCK:
        V044_SERVICE_DNS[client_ip] = (n, time.monotonic())

def v044_recent_service_dns(client_ip: str, max_age: float = 5.0):
    with V044_SERVICE_DNS_LOCK:
        item = V044_SERVICE_DNS.get(client_ip)
    if not item:
        return None
    host, ts = item
    if time.monotonic() - ts > max_age:
        return None
    return host


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
    ts = now()
    msg = f"[{ts}] [{kind}] {text}\n"
    if payload is not None:
        msg += hexdump(payload, limit=int(cfg.get("log_payload_limit", 8192))) + "\n"
    with path.open("a", encoding="utf-8", errors="replace") as f:
        f.write(msg)
    if bool(cfg.get("structured_jsonl_log", True)):
        evt = {"time": ts, "kind": kind, "text": text}
        if payload is not None:
            evt.update({
                "payload_len": len(payload),
                "payload_sha1": hashlib.sha1(payload).hexdigest(),
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "payload_prefix_hex": payload[:64].hex(),
            })
        try:
            with (log_dir / f"eyetoy_{stamp}.jsonl").open("a", encoding="utf-8") as jf:
                jf.write(json.dumps(evt, ensure_ascii=False, sort_keys=True) + "\n")
        except Exception:
            pass
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
            v044_note_service_dns(addr[0], name)
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


def make_http_response(status_line: bytes, ctype: bytes, body: bytes, method: str, extra_headers=None):
    extra = b""
    if extra_headers:
        for key, value in extra_headers:
            kb = key.encode("ascii") if isinstance(key, str) else bytes(key)
            vb = value.encode("iso-8859-1") if isinstance(value, str) else bytes(value)
            extra += kb + b": " + vb + b"\r\n"
    headers = (
        b"Content-Type: " + ctype + b"\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"Cache-Control: no-cache\r\n"
        + extra +
        b"Connection: close\r\n\r\n"
    )
    return status_line + headers + (b"" if method.upper() == "HEAD" else body)


def _v051_bool_header(value, default=False):
    # EyeToy beta ETHttpVideoConfig's boolean parser performs an exact strcmp
    # against lowercase "true".  Any other value is interpreted as false.
    if value is None:
        value = default
    if isinstance(value, bool):
        enabled = value
    elif isinstance(value, (int, float)):
        enabled = (value != 0)
    else:
        enabled = str(value).strip().lower() in ("1", "true", "yes", "on")
    return "true" if enabled else "false"


def build_vmail_config_headers(cfg):
    # V051: beta overlay reverse engineering confirms ConfigRetrieve has a no-op
    # HttpRequestRxChunk and parses the 20 settings from response headers in
    # OnHttpRequestEnd. Header names are exact/case-sensitive; boolean values must
    # be lowercase "true" to enable a feature. Body intentionally stays empty.
    host = str(cfg.get("vmail_hostname", "vmail.online.scee.com"))
    port = int(cfg.get("update_tls_port", 10443))
    scheme = str(cfg.get("vmail_scheme", "https"))
    base = f"{scheme}://{host}:{port}/mt/servlet"
    return [
        ("Mail.PostURL", str(cfg.get("vmail_mail_post_url", base + "/MailPost"))),
        ("Mail.InboxURL", str(cfg.get("vmail_mail_inbox_url", base + "/MailInbox"))),
        ("Mail.RetrieveURL", str(cfg.get("vmail_mail_retrieve_url", base + "/MailRetrieve"))),
        ("Mail.DeleteURL", str(cfg.get("vmail_mail_delete_url", base + "/MailDelete"))),
        ("Profile.RetrieveURL", str(cfg.get("vmail_profile_retrieve_url", base + "/ProfileRetrieve"))),
        ("Profile.PostURL", str(cfg.get("vmail_profile_post_url", base + "/ProfilePost"))),
        ("AdFeed.RetrieveURL", str(cfg.get("vmail_adfeed_retrieve_url", base + "/AdFeedRetrieve"))),
        ("config-version", str(cfg.get("vmail_config_version", 1))),
        ("config-code-version", str(cfg.get("vmail_config_code_version", 1))),
        ("Mail.RefreshInterval", str(cfg.get("vmail_mail_refresh_interval", 60))),
        ("Mail.MaxLength", str(cfg.get("vmail_mail_max_length", 1048576))),
        ("ChatRooms.NonRegistered.Access", _v051_bool_header(cfg.get("vmail_chatrooms_nonregistered_access", True), True)),
        ("ChatRooms.Registered.Access", _v051_bool_header(cfg.get("vmail_chatrooms_registered_access", True), True)),
        ("ChatRooms.Thumbnails.Read", _v051_bool_header(cfg.get("vmail_chatrooms_thumbnails_read", True), True)),
        ("ChatRooms.Thumbnails.Post", _v051_bool_header(cfg.get("vmail_chatrooms_thumbnails_post", True), True)),
        ("VideoMail.Inbox", _v051_bool_header(cfg.get("vmail_videomail_inbox", True), True)),
        ("VideoMail.Post", _v051_bool_header(cfg.get("vmail_videomail_post", True), True)),
        ("ScreenSaver.Access", _v051_bool_header(cfg.get("vmail_screensaver_access", True), True)),
        ("FriendshipRequest.Lock", _v051_bool_header(cfg.get("vmail_friendship_request_lock", False), False)),
        ("Product.Access", _v051_bool_header(cfg.get("vmail_product_access", True), True)),
    ]


# V060/V061 hierarchy research. The old 55-second run was later shown to be
# display time on the failure screen, not proof that the XML was accepted.
#
# Direct retail MAINGAME.MSN xrefs (load base 0x01816F80) show:
#   * ban_time is queried on the current/root XML node;
#   * heading is queried on that SAME current node;
#   * heading value is compared against literal "lang", then literal "type";
#   * when a child is activated, tag names "menu" and "chatroom" are compared;
#   * child/node attributes title/icon/type/id are queried;
#   * type values VOICE16/TEXT256 are recognized.
#
# The crucial correction versus V058/V059 is therefore that the first
# heading="lang" belongs on <chatrooms> itself, not on its first <menu> child.
# A language child menu can then become the current node and carry
# heading="type" for the next screen.
_V060_PROBE_LOCAL = threading.local()
_V060_PROBE_LOCK = threading.Lock()


# V064 keeps the HTTP hierarchy and every Medius representation of the default
# lobby in one explicit profile.  XML id, MediusWorldID and GenericField1 are
# distinct protocol fields; each profile specifies all of them without claiming
# that they must historically be equal.  Switching profile changes one complete
# compatibility hypothesis for the next cold run.
V064_CHATROOM_PROFILES = {
    "retail_holding_1000": {
        "room_title": "Holding",
        "room_id": 1000,
        "channel_name": "Holding",
        "account_login_world_id": 1000,
        "connect_world_id": 1000,
        "channel_world_id": 1000,
        "generic_field1": 1000,
        "generic_field_level": 1,
        "lobby_filter_mask_level": 1,
    },
    "medius_default_1": {
        "room_title": "Default",
        "room_id": 1,
        "channel_name": "Default",
        "account_login_world_id": 1,
        "connect_world_id": 1,
        "channel_world_id": 1,
        "generic_field1": 1,
        "generic_field_level": 1,
        "lobby_filter_mask_level": 1,
    },
    "chat_francais_1": {
        "room_title": "Chat Francais",
        "room_id": 1,
        "channel_name": "Chat Francais",
        "account_login_world_id": 1,
        "connect_world_id": 1,
        "channel_world_id": 1,
        "generic_field1": 1,
        "generic_field_level": 1,
        "lobby_filter_mask_level": 1,
    },
}


def v064_chatroom_profile(cfg):
    """Resolve and validate one end-to-end chatroom compatibility profile."""
    name = str(cfg.get("v064_chatroom_profile", "medius_default_1")).strip()
    if name not in V064_CHATROOM_PROFILES:
        allowed = ", ".join(sorted(V064_CHATROOM_PROFILES))
        raise ValueError(f"v064_chatroom_profile inconnu {name!r}; valeurs: {allowed}")
    profile = dict(V064_CHATROOM_PROFILES[name])
    configured = cfg.get("v064_chatroom_profiles", {})
    if isinstance(configured, dict) and isinstance(configured.get(name), dict):
        profile.update(configured[name])
    profile["name"] = name
    for key in ("room_id", "account_login_world_id", "connect_world_id",
                "channel_world_id", "generic_field1", "generic_field_level",
                "lobby_filter_mask_level"):
        profile[key] = int(profile[key])
    profile["room_title"] = str(profile["room_title"])
    profile["channel_name"] = str(profile["channel_name"])
    if not profile["room_title"] or not profile["channel_name"]:
        raise ValueError(f"profil {name}: titres XML et Medius requis")
    return profile

V086_DEFAULT_TEXT_ROOMS = [
    {"language": "Francais", "category": "General", "title": "General", "world_id": 1},
    {"language": "Francais", "category": "Sport", "title": "Sport", "world_id": 2},
    {"language": "English", "category": "General", "title": "General", "world_id": 3},
    {"language": "English", "category": "Sport", "title": "Sport", "world_id": 4},
]

def v086_text_rooms(cfg):
    raw = cfg.get("v086_text_rooms", V086_DEFAULT_TEXT_ROOMS)
    if not isinstance(raw, list) or not raw:
        raise ValueError("v086_text_rooms doit etre une liste non vide")
    rooms, seen = [], set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"v086_text_rooms[{index}] doit etre un objet")
        room = {
            "language": str(item.get("language", "")).strip(),
            "category": str(item.get("category", "")).strip(),
            "title": str(item.get("title", item.get("category", ""))).strip(),
            "world_id": int(item.get("world_id", 0)),
            "type": str(item.get("type", "TEXT256")).strip().upper(),
            "icon": int(item.get("icon", 0)),
        }
        if not room["language"] or not room["category"] or not room["title"]:
            raise ValueError(f"v086_text_rooms[{index}] exige language/category/title")
        if room["world_id"] <= 0 or room["world_id"] in seen:
            raise ValueError(f"v086_text_rooms[{index}] WorldID invalide ou duplique")
        if room["type"] != "TEXT256":
            raise ValueError(f"v086_text_rooms[{index}] doit rester TEXT256 pour ce test")
        seen.add(room["world_id"]); rooms.append(room)
    return rooms

def v086_room_by_world(cfg, world_id):
    if not bool(cfg.get("v086_room_tree_enabled", True)):
        return None
    target = int(world_id or 0)
    return next((dict(r) for r in v086_text_rooms(cfg) if r["world_id"] == target), None)

def _v060_xml_escape(v: str) -> str:
    return (str(v).replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;"))

def _v060_probe_modes(cfg):
    modes = cfg.get("v060_chatroom_probe_modes", [
        "root_heading_lang_menu_type_room",
        "root_heading_lang_menu_type_room_selfclose",
        "root_heading_type_direct_room_selfclose",
        "root_heading_lang_menu_type_two_rooms",
        "root_heading_lang_menu_type_dense_menu",
        "root_heading_type_menu_room",
        "root_heading_lang_minimal_menu_type",
        "root_heading_lang_menu_type_voice16",
        "root_heading_lang_menu_plain_room",
        "xml_decl_root_heading_lang_menu_type",
    ])
    if not isinstance(modes, list) or not modes:
        modes = ["root_heading_lang_menu_type_room"]
    return [str(x) for x in modes]

def build_chatroom_hierarchy_v060(cfg, mode: str) -> bytes:
    """Build legacy candidates or the selected coherent chatroom profile."""
    # menu() is the single escaping boundary for this value.
    language_title = str(cfg.get("chatroom_language_title", "English"))
    room_title = _v060_xml_escape(cfg.get("chatroom_probe_title", "Holding"))
    room_id = int(cfg.get("chatroom_probe_id", 1000))
    ban_time = int(cfg.get("chatroom_probe_ban_time", 0))
    language_index = int(cfg.get("chatroom_language_index", 2))
    vmail_inbox_size = int(cfg.get("chatroom_vmail_inbox_size", 20))
    welcome_version = int(cfg.get("chatroom_welcome_version", 1))
    welcome_text = _v060_xml_escape(
        cfg.get("chatroom_welcome_text", "Welcome to EyeToy Chat")
    )
    room_welcome_text = _v060_xml_escape(
        cfg.get("chatroom_room_welcome_text", "Welcome to EyeToy Chat")
    )
    if not 0 <= language_index <= 11:
        raise ValueError("chatroom_language_index must be in PS2 range 0..11")
    if vmail_inbox_size < 0 or welcome_version < 0:
        raise ValueError("chatroom vmail/welcome numeric values must be non-negative")

    def room(room_type="TEXT256", rid=None, title=None, selfclose=False):
        rid = room_id if rid is None else int(rid)
        title = room_title if title is None else _v060_xml_escape(title)
        attrs = f'title="{title}" icon="0" type="{room_type}" id="{rid}"'
        return f'<chatroom {attrs}/>' if selfclose else f'<chatroom {attrs}></chatroom>'

    def menu(heading=None, title=None, child="", *, minimal=False, dense=False):
        attrs=[]
        if heading is not None:
            attrs.append(f'heading="{heading}"')
        if not minimal and title is not None:
            attrs.append(f'title="{_v060_xml_escape(title)}"')
            attrs.append('icon="0"')
        if dense:
            attrs.extend([f'type="TEXT256"', f'id="{room_id}"'])
        a=(" "+" ".join(attrs)) if attrs else ""
        return f'<menu{a}>{child}</menu>'

    def root(child, heading=None, extra=""):
        attrs=[f'ban_time="{ban_time}"']
        if heading is not None:
            attrs.append(f'heading="{heading}"')
        if extra.strip(): attrs.append(extra.strip())
        return f'<chatrooms {" ".join(attrs)}>{child}</chatrooms>'

    if mode == "root_heading_lang_menu_type_room":
        xml = root(menu("type", language_title, room()), heading="lang")
    elif mode == "root_heading_lang_menu_type_room_selfclose":
        xml = root(menu("type", language_title, room(selfclose=True)), heading="lang")
    elif mode == "root_heading_type_direct_room_selfclose":
        xml = root(room(selfclose=True), heading="type")
    elif mode == "root_heading_lang_menu_type_two_rooms":
        children = room("TEXT256", 1000, "Holding", True) + room("VOICE16", 1001, "Voice Chat", True)
        xml = root(menu("type", language_title, children), heading="lang")
    elif mode == "root_heading_lang_menu_type_dense_menu":
        xml = root(menu("type", language_title, room(selfclose=True), dense=True), heading="lang")
    elif mode == "root_heading_type_menu_room":
        xml = root(menu(None, language_title, room(selfclose=True)), heading="type")
    elif mode == "root_heading_lang_minimal_menu_type":
        xml = root(menu("type", None, room(selfclose=True), minimal=True), heading="lang")
    elif mode == "root_heading_lang_menu_type_voice16":
        xml = root(menu("type", language_title, room("VOICE16", 1000, "Holding", True)), heading="lang")
    elif mode == "root_heading_lang_menu_plain_room":
        xml = root(menu(None, language_title, room(selfclose=True)), heading="lang")
    elif mode == "xml_decl_root_heading_lang_menu_type":
        xml = ('<?xml version="1.0" encoding="ISO-8859-1"?>' +
               root(menu("type", language_title, room(selfclose=True)), heading="lang"))
    # V063 targeted matrix.  These candidates intentionally change one XML
    # dimension at a time while keeping the V062 Medius behavior untouched.
    elif mode == "v063_control_probe6":
        xml = root(menu("type", None, room(selfclose=True), minimal=True), heading="lang")
    elif mode == "v063_control_plus_xml_decl":
        xml = ('<?xml version="1.0" encoding="ISO-8859-1"?>' +
               root(menu("type", None, room(selfclose=True), minimal=True), heading="lang"))
    elif mode == "v063_language_english":
        xml = root(menu("type", language_title, room(selfclose=True)), heading="lang")
    elif mode == "v063_default_room":
        xml = root(menu("type", None, room("TEXT256", room_id, "Default", True), minimal=True), heading="lang")
    elif mode == "v063_two_rooms":
        children = room("TEXT256", room_id, "Holding", True) + room("VOICE16", room_id + 1, "Voice Chat", True)
        xml = root(menu("type", None, children, minimal=True), heading="lang")
    elif mode == "v064_coherent_profile":
        profile = v064_chatroom_profile(cfg)
        child = room("TEXT256", profile["room_id"], profile["room_title"], True)
        xml = root(menu("type", None, child, minimal=True), heading="lang")
    elif mode == "v065_full_menu_profile":
        # Retail MAINGAME.MSN reads title/icon on menu entries.  V064 omitted
        # both attributes, leaving the language item with no display metadata.
        # Keep the same room/profile and self-closing room syntax so this trial
        # changes only those two statically evidenced menu attributes.
        profile = v064_chatroom_profile(cfg)
        child = room("TEXT256", profile["room_id"], profile["room_title"], True)
        xml = root(menu("type", language_title, child), heading="lang")
    elif mode == "v066_required_callback_fields":
        # Corrected retail mapping (PC = MWO3 load base + file offset) exposes
        # three mandatory callback lookups that every earlier candidate lacked:
        #   root attribute vmail_inbox_size
        #   direct child chatroom_welcome%d
        #   direct child welcome%d with a version attribute
        # The localized suffix must follow the game UI language global, not the Medius language enum.
        # V074 live-video evidence shows an English UI plus policy.1 / announcements.1,
        # therefore this build uses chatroom_language_index=1.
        # Keep the V065 menu first: the UI initializes its current menu from the
        # root's first child and the metadata nodes must not precede it.
        profile = v064_chatroom_profile(cfg)
        child = room("TEXT256", profile["room_id"], profile["room_title"], True)
        # V077: the PAL release has 11 selectable UI languages. Live captures
        # prove English asks policy/announcements suffix .1 while another PAL
        # language (French in the 2026-08-26 capture) asks suffix .2. The retail
        # callback names are also localized (chatroom_welcome%d / welcome%d).
        # Do not force one language index: expose all PAL callback nodes at once.
        if bool(cfg.get("v077_pal_multilang_callbacks", True)):
            indices = cfg.get("v077_pal_language_indices", list(range(1, 12)))
            try:
                indices = sorted({int(x) for x in indices if 1 <= int(x) <= 11})
            except Exception:
                indices = list(range(1, 12))
            if not indices:
                indices = list(range(1, 12))
        else:
            indices = [language_index]
        callback_nodes = "".join(
            f'<chatroom_welcome{idx}>{room_welcome_text}</chatroom_welcome{idx}>'
            f'<welcome{idx} version="{welcome_version}">{welcome_text}</welcome{idx}>'
            for idx in indices
        )
        xml = root(
            menu("type", language_title, child) + callback_nodes,
            heading="lang",
            extra=f'vmail_inbox_size="{vmail_inbox_size}"',
        )
    elif mode == "v086_multilingual_text_rooms":
        grouped = []
        for entry in v086_text_rooms(cfg):
            bucket = next((value for key, value in grouped if key == entry["language"]), None)
            if bucket is None:
                bucket = []; grouped.append((entry["language"], bucket))
            bucket.append(entry)
        language_nodes = []
        for language, entries in grouped:
            categories = []
            for entry in entries:
                leaf = room(entry["type"], entry["world_id"], entry["title"], True)
                categories.append(menu("type", entry["category"], leaf))
            language_nodes.append(menu("type", language, "".join(categories)))
        indices = list(range(1, 12)) if bool(cfg.get("v077_pal_multilang_callbacks", True)) else [language_index]
        callback_nodes = "".join(
            f'<chatroom_welcome{idx}>{room_welcome_text}</chatroom_welcome{idx}>'
            f'<welcome{idx} version="{welcome_version}">{welcome_text}</welcome{idx}>'
            for idx in indices
        )
        xml = root("".join(language_nodes) + callback_nodes, heading="lang",
                   extra=f'vmail_inbox_size="{vmail_inbox_size}"')
    else:
        raise ValueError(f"unknown hierarchy probe mode: {mode}")

    return xml.encode("iso-8859-1", errors="strict")


def _v060_select_probe(cfg):
    configured = str(cfg.get("v060_chatroom_probe_mode", "auto")).strip()
    modes = _v060_probe_modes(cfg)
    state_path = ROOT / str(cfg.get("v060_chatroom_probe_state_file",
                                   "logs/v060_chatroom_probe_state.json"))

    with _V060_PROBE_LOCK:
        if configured and configured.lower() != "auto":
            mode = configured
            try:
                idx = modes.index(mode)
            except ValueError:
                idx = -1
        else:
            idx = 0
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                idx = int(state.get("next_index", 0))
            except Exception:
                idx = 0
            mode = modes[idx % len(modes)]
            try:
                state_path.parent.mkdir(parents=True, exist_ok=True)
                state_path.write_text(
                    json.dumps({
                        "last_index": idx,
                        "last_mode": mode,
                        "next_index": idx + 1,
                        "mode_count": len(modes),
                        "updated": dt.datetime.now().isoformat()
                    }, indent=2),
                    encoding="utf-8"
                )
            except Exception:
                pass

        body = build_chatroom_hierarchy_v060(cfg, mode)
        info = {
            "mode": mode,
            "index": idx,
            "mode_count": len(modes),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
        if mode in ("v064_coherent_profile", "v065_full_menu_profile",
                    "v066_required_callback_fields"):
            info["profile"] = v064_chatroom_profile(cfg)
        elif mode == "v086_multilingual_text_rooms":
            info["rooms"] = v086_text_rooms(cfg)
        _V060_PROBE_LOCAL.info = info
        return body, info

def v060_last_probe_info():
    return dict(getattr(_V060_PROBE_LOCAL, "info", {}) or {})



def build_v072_adfeed_xml(cfg):
    """Build the smallest XML feed matching the retail AdFeed parser strings.

    Retail MAINGAME.MSN contains the contiguous tokens channel/image/item/title/
    description/link, AdFeed.RetrieveURL, an HTTP image cache manager, and libpng.
    This probe deliberately uses only those observed field names.  The image is
    repeated at channel and item level so the first live trace can tell us which
    location the retail parser follows without inventing a larger schema.
    """
    host = str(cfg.get("vmail_hostname", "vmail.online.scee.com"))
    port = int(cfg.get("update_tls_port", 10443))
    scheme = str(cfg.get("vmail_scheme", "https"))
    image_path = str(cfg.get("v072_adfeed_image_path", "/adfeed/eyetoy_http_test.png"))
    if not image_path.startswith("/"):
        image_path = "/" + image_path
    image_url = str(cfg.get("v072_adfeed_image_url", f"{scheme}://{host}:{port}{image_path}"))
    title = str(cfg.get("v072_adfeed_title", "EyeToy Chat HTTP image test"))
    desc = str(cfg.get("v072_adfeed_description", "V072 AdFeed PNG probe"))
    link = str(cfg.get("v072_adfeed_link", image_url))
    import html
    esc = lambda x: html.escape(str(x), quote=True)
    return (
        '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
        '<channel>\n'
        f'  <image>{esc(image_url)}</image>\n'
        '  <item>\n'
        f'    <title>{esc(title)}</title>\n'
        f'    <description>{esc(desc)}</description>\n'
        f'    <link>{esc(link)}</link>\n'
        f'    <image>{esc(image_url)}</image>\n'
        '  </item>\n'
        '</channel>\n'
    ).encode("iso-8859-1", errors="xmlcharrefreplace")


def v072_adfeed_image_bytes(cfg):
    rel = str(cfg.get("v072_adfeed_image_file", "http_root/adfeed/eyetoy_http_test.png"))
    candidate = (ROOT / rel).resolve()
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        return b""
    return candidate.read_bytes() if candidate.is_file() else b""


def _v075_http_request_parts(request: bytes):
    head, sep, body = request.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = request.partition(b"\n\n")
    headers = {}
    try:
        lines = head.decode("iso-8859-1", errors="replace").splitlines()[1:]
        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
    except Exception:
        pass
    return headers, body


def _v075_profile_request_identity(request: bytes, cfg=None):
    headers, body = _v075_http_request_parts(request)
    username = (headers.get("profileusername") or headers.get("username") or
                headers.get("profile-user-name") or headers.get("user") or "")
    if not username and cfg is not None:
        raw_id = headers.get("profileuserid") or headers.get("userid")
        try:
            rec = v075_account_by_id(cfg, int(raw_id)) if raw_id is not None else None
        except (TypeError, ValueError):
            rec = None
        if rec:
            username = str(rec.get("name", ""))
    username = username or "EyeToyUser"
    private_raw = headers.get("private", headers.get("profileprivate", "false")).strip().lower()
    is_private = private_raw in {"1", "true", "yes", "private"}
    return username[:31], is_private, body



def _v076_media_root(cfg):
    rel = str(cfg.get("v076_media_store_dir", "media_store"))
    root = (ROOT / rel).resolve()
    try:
        root.relative_to(ROOT.resolve())
    except ValueError:
        root = ROOT / "media_store"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _v076_capture_http_payload(cfg, category, path, request, body):
    if not bool(cfg.get("v076_capture_media_http", True)):
        return None
    outdir = _v076_media_root(cfg) / category
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/")) or "root"
    stem = outdir / f"{stamp}_{safe}"
    (stem.with_suffix(".request.bin")).write_bytes(request)
    if body:
        (stem.with_suffix(".body.bin")).write_bytes(body)
    return stem


def _v076_request_user(cfg, headers):
    name = (headers.get("username") or headers.get("profileusername") or "").strip()
    raw_id = headers.get("userid") or headers.get("profileuserid")
    rec = None
    try:
        rec = v075_account_by_id(cfg, int(raw_id)) if raw_id else None
    except (TypeError, ValueError):
        pass
    if not rec and name:
        rec = v075_account_by_name(cfg, name)
    if not rec and name:
        rec = v075_register_account(cfg, name)
    return rec


def _v076_vmail_index_path(cfg):
    return _v076_media_root(cfg) / "videomail" / "index.json"


def _v076_vmail_load(cfg):
    path = _v076_vmail_index_path(cfg)
    if not path.is_file():
        return {"version": 1, "next_id": 1, "messages": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data.setdefault("version", 1); data.setdefault("next_id", 1); data.setdefault("messages", [])
        return data
    except Exception:
        return {"version": 1, "next_id": 1, "messages": []}


def _v076_vmail_save(cfg, data):
    path = _v076_vmail_index_path(cfg); path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp"); tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"); os.replace(tmp, path)


def _v076_parse_recipient_ids(headers, body):
    ids = []
    for key in ("recipient", "recipientid", "recipient-id", "to", "userid"):
        val = headers.get(key)
        if val:
            for n in re.findall(r"\d+", val):
                ids.append(int(n))
    try:
        txt = body[:4096].decode("iso-8859-1", errors="ignore")
        for n in re.findall(r'<recipient\s+id=["\'](\d+)["\']', txt, flags=re.I):
            ids.append(int(n))
    except Exception:
        pass
    return sorted(set(ids))


def v076_vmail_store(cfg, request, path):
    headers, body = _v075_http_request_parts(request)
    max_len = int(cfg.get("vmail_mail_max_length", 1048576))
    body = body[:max_len]
    sender = _v076_request_user(cfg, headers)
    with V075_SOCIAL_LOCK:
        data = _v076_vmail_load(cfg)
        mid = int(data.get("next_id", 1)); data["next_id"] = mid + 1
        vmroot = _v076_media_root(cfg) / "videomail"; vmroot.mkdir(parents=True, exist_ok=True)
        fname = f"mail_{mid:08d}.bin"; (vmroot / fname).write_bytes(body)
        recipients = _v076_parse_recipient_ids(headers, body)
        meta = {
            "id": mid, "file": fname, "created": now(), "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "sender_id": int((sender or {}).get("account_id", 0)),
            "sender_name": str((sender or {}).get("name", headers.get("username", ""))),
            "recipients": recipients, "subject": headers.get("subject", ""),
            "duration": headers.get("duration", ""), "content_type": headers.get("content-type", "application/octet-stream"),
            "raw_headers": {k: v for k, v in headers.items() if k not in {"password"}},
        }
        data["messages"].append(meta); _v076_vmail_save(cfg, data)
    _v076_capture_http_payload(cfg, "videomail_capture", path, request, body)
    return meta


def _v076_vmail_requested_id(headers, target):
    for key in ("mailid", "messageid", "message-id", "id", "entry", "videoid"):
        val = headers.get(key)
        if val:
            m = re.search(r"\d+", val)
            if m: return int(m.group(0))
    q = urlsplit(target).query
    m = re.search(r"(?:^|&)(?:mailid|messageid|id)=([0-9]+)", q, flags=re.I)
    return int(m.group(1)) if m else None


def _v076_vmail_find(cfg, mid):
    if mid is None: return None
    for rec in _v076_vmail_load(cfg).get("messages", []):
        if int(rec.get("id", -1)) == int(mid): return rec
    return None


def v076_vmail_delete(cfg, mid):
    if mid is None: return False
    with V075_SOCIAL_LOCK:
        data = _v076_vmail_load(cfg); kept=[]; found=None
        for rec in data.get("messages", []):
            if int(rec.get("id", -1)) == int(mid): found=rec
            else: kept.append(rec)
        if not found: return False
        data["messages"] = kept; _v076_vmail_save(cfg, data)
        try: (_v076_media_root(cfg)/"videomail"/found.get("file","")).unlink(missing_ok=True)
        except Exception: pass
        return True


def v076_vmail_inbox_xml(cfg, account_id):
    """Experimental local inbox, enabled only by config; exact SCEE schema is not claimed."""
    msgs=[]
    if account_id:
        for m in _v076_vmail_load(cfg).get("messages", []):
            if int(account_id) in [int(x) for x in m.get("recipients", [])]: msgs.append(m)
    lines=['<?xml version="1.0" encoding="ISO-8859-1"?><inbox>']
    for m in msgs:
        esc=lambda x: str(x).replace('&','&amp;').replace('"','&quot;').replace('<','&lt;').replace('>','&gt;')
        lines.append(f'<entry id="{int(m.get("id",0))}" senderid="{int(m.get("sender_id",0))}" sendername="{esc(m.get("sender_name",""))}" subject="{esc(m.get("subject",""))}" content-length="{int(m.get("bytes",0))}" duration="{esc(m.get("duration",""))}" bounced="False"/>')
    lines.append('</inbox>')
    return (''.join(lines)+'\n').encode('iso-8859-1', errors='replace')

def http_response_for(request: bytes, cfg):
    try:
        head = request.decode("iso-8859-1", errors="replace")
        first = head.splitlines()[0]
        method, target, _ = first.split(" ", 2)
        path = urlsplit(target).path
    except Exception:
        return None, None, None

    method = method.upper()

    # V072: controlled AdFeed + PNG probe.  Accept GET/HEAD/POST for the feed
    # because the retail binary exposes request fields adFeedVersion/language,
    # but the exact historical HTTP verb has not yet been observed live.
    if path.rstrip("/").lower() == "/mt/servlet/adfeedretrieve" and method in {"GET", "HEAD", "POST"}:
        body = build_v072_adfeed_xml(cfg)
        ctype = str(cfg.get("v072_adfeed_content_type", "text/xml")).encode("ascii", errors="replace")
        response = make_http_response(b"HTTP/1.0 200 OK\r\n", ctype, body, method)
        return response, path, body

    image_path = str(cfg.get("v072_adfeed_image_path", "/adfeed/eyetoy_http_test.png"))
    if not image_path.startswith("/"):
        image_path = "/" + image_path
    if path.lower() == image_path.lower() and method in {"GET", "HEAD"}:
        body = v072_adfeed_image_bytes(cfg)
        status = b"HTTP/1.0 200 OK\r\n" if body else b"HTTP/1.0 404 Not Found\r\n"
        response = make_http_response(status, b"image/png", body, method)
        return response, path, body

    # V071: ProfilePost is the one confirmed POST endpoint.  Handle it before
    # the legacy non-GET fallback so the client receives the media type its
    # profile callback expects.  The TLS reader above separately waits for the
    # full Content-Length body before this dispatcher is called.
    if method == "POST" and path.rstrip("/").lower() == "/mt/servlet/profilepost":
        username, is_private, posted = _v075_profile_request_identity(request, cfg)
        if bool(cfg.get("v075_social_enabled", True)):
            aid, stored_len = v075_store_profile(cfg, username, is_private, posted)
            log_event(cfg, "V075-SOCIAL-PROFILE-SAVE",
                      f"AccountID={aid}; Username={username!r}; private={int(is_private)}; bytes={stored_len}; sha256={hashlib.sha256(posted).hexdigest()}")
        body = b""
        response = make_http_response(
            b"HTTP/1.0 200 OK\r\n", b"application/octet-stream", body, method
        )
        return response, path, body

    # V076: all four retail VideoMail endpoints are now captured/stored.  The
    # exact original SCEE inbox XML schema is still unknown, so serving stored
    # entries is opt-in; the proven empty <inbox/> remains the safe default.
    lowpath = path.rstrip("/").lower()
    if lowpath == "/mt/servlet/mailpost" and method == "POST":
        meta = v076_vmail_store(cfg, request, path) if bool(cfg.get("v076_videomail_store_enabled", True)) else None
        headers = [("X-EyeToy-Local-Mail-ID", str(meta["id"]))] if meta else None
        log_event(cfg, "V076-VIDEO-MAIL-POST", f"stored={bool(meta)}; id={(meta or {}).get('id',0)}; bytes={(meta or {}).get('bytes',0)}")
        body = b""
        return make_http_response(b"HTTP/1.0 200 OK\r\n", b"application/octet-stream", body, method, extra_headers=headers), path, body

    if lowpath == "/mt/servlet/mailretrieve" and method in {"GET", "HEAD", "POST"}:
        headers, reqbody = _v075_http_request_parts(request); target = request.splitlines()[0].decode("iso-8859-1",errors="replace").split(" ",2)[1]
        mid = _v076_vmail_requested_id(headers, target); meta = _v076_vmail_find(cfg, mid)
        body = b""
        if meta:
            fp = _v076_media_root(cfg)/"videomail"/meta.get("file","")
            if fp.is_file(): body = fp.read_bytes()
        _v076_capture_http_payload(cfg, "videomail_capture", path, request, reqbody)
        log_event(cfg, "V076-VIDEO-MAIL-RETRIEVE", f"id={mid}; found={bool(meta)}; bytes={len(body)}")
        status = b"HTTP/1.0 200 OK\r\n" if meta else b"HTTP/1.0 404 Not Found\r\n"
        return make_http_response(status, b"application/octet-stream", body, method), path, body

    if lowpath == "/mt/servlet/maildelete" and method in {"GET", "HEAD", "POST"}:
        headers, reqbody = _v075_http_request_parts(request); target = request.splitlines()[0].decode("iso-8859-1",errors="replace").split(" ",2)[1]
        mid = _v076_vmail_requested_id(headers, target); deleted = v076_vmail_delete(cfg, mid)
        _v076_capture_http_payload(cfg, "videomail_capture", path, request, reqbody)
        log_event(cfg, "V076-VIDEO-MAIL-DELETE", f"id={mid}; deleted={int(deleted)}")
        body=b""; return make_http_response(b"HTTP/1.0 200 OK\r\n", b"application/octet-stream", body, method), path, body

    # Capture unknown HTTP photo/thumbnail endpoints while preserving a 404.
    if bool(cfg.get("v076_photo_probe_enabled", True)) and any(tok in lowpath for tok in ("photo","thumb","thumbnail")):
        headers, reqbody = _v075_http_request_parts(request)
        stem = _v076_capture_http_payload(cfg, "photo_candidates", path, request, reqbody)
        log_event(cfg, "V076-PHOTO-ENDPOINT-PROBE", f"method={method}; path={path}; body={len(reqbody)}; saved={stem is not None}")
        body=b""; return make_http_response(b"HTTP/1.0 404 Not Found\r\n", b"application/octet-stream", body, method), path, body

    if method not in {"GET", "HEAD"}:
        body = b"EyeToy Chat Local Server V072\n"
        response = make_http_response(b"HTTP/1.0 200 OK\r\n", b"text/plain", body, method)
        return response, path, body

    # Critical endpoint: never depend on a stale file left from V007.
    if path.rstrip("/").lower() == "/qa_patches/index.xml":
        body = build_update_index(cfg)
        response = make_http_response(b"HTTP/1.0 200 OK\r\n", b"text/xml; charset=UTF-8", body, method)
        return response, path, body

    # V042: EyeToy requests language/version-indexed policy files over HTTPS
    # (observed: /policies/policy.2.txt).  Older builds only shipped policy.0.txt
    # in our local root, which caused a 404 after a fully successful TLS handshake.
    # Serve the local usage policy for any numeric policy index so we can reach
    # the next application-stage request without guessing the historical index map.
    m_policy = re.fullmatch(r"/policies/policy\.(\d+)\.txt", path, flags=re.IGNORECASE)
    if m_policy:
        candidate = HTTP_ROOT / "policies" / f"policy.{m_policy.group(1)}.txt"
        if not candidate.is_file():
            fallback = HTTP_ROOT / "policies" / "policy.0.txt"
            body = fallback.read_bytes() if fallback.is_file() else (
                b"EyeToy Chat Community Server Usage Policy\r\n"
                b"Use the service respectfully.\r\n"
            )
            response = make_http_response(b"HTTP/1.0 200 OK\r\n", b"text/plain", body, method)
            return response, path, body

    # V052: after the V051 boolean-header fix EyeToy proceeds to fetch
    # /announcements/announcements.2.txt from the update host.  The V051 server
    # returned 404, while the client kept the MLS session alive with only ECHOs.
    # Treat numeric announcement resources like policy resources: serve a local
    # matching file when present, otherwise fall back to announcements.0.txt /
    # a minimal ASCII announcement.  This intentionally changes only the HTTP
    # status/body for the newly capture-confirmed path.
    m_announcement = re.fullmatch(r"/announcements/announcements\.(\d+)\.txt", path, flags=re.IGNORECASE)
    if m_announcement:
        candidate = HTTP_ROOT / "announcements" / f"announcements.{m_announcement.group(1)}.txt"
        if candidate.is_file():
            body = candidate.read_bytes()
        else:
            fallback = HTTP_ROOT / "announcements" / "announcements.0.txt"
            body = fallback.read_bytes() if fallback.is_file() else (
                str(cfg.get("http_announcement_text", "Welcome to EyeToy Chat Europe\r\n"))
                .encode("iso-8859-1", errors="replace")
            )
        response = make_http_response(b"HTTP/1.0 200 OK\r\n", b"text/plain", body, method)
        return response, path, body

    # V058: serve one hierarchy tree candidate at a time.  Auto mode advances
    # on each hierarchy request and persists the probe index across restarts.
    if path.rstrip("/").lower() == "/chatroom_hierarchy_1_51.xml":
        body, _probe = _v060_select_probe(cfg)
        response = make_http_response(b"HTTP/1.0 200 OK\r\n", b"text/xml", body, method)
        return response, path, body

    # V051 exact ConfigRetrieve response-header format.
    # Beta overlay confirms the body callback is a no-op and the 20 settings are
    # consumed from response headers; body_len=0 is therefore intentional.
    if path.rstrip("/").lower() == "/mt/servlet/configretrievemessagetransformer":
        body = b""
        response = make_http_response(
            b"HTTP/1.0 200 OK\r\n", b"application/octet-stream", body, method,
            extra_headers=build_vmail_config_headers(cfg)
        )
        return response, path, body

    # V067: V066 is confirmed to pass the hierarchy callback gates. Retail then
    # immediately requests ProfileRetrieve. The retail GHttpVideo response
    # callback accepts HTTP 200 and explicitly validates Content-Type
    # application/octet-stream. Use an empty profile body as a controlled
    # "no stored profile yet" probe; do not guess the binary profile payload
    # until the client proves it requires one.
    if path.rstrip("/").lower() == "/mt/servlet/profileretrieve":
        username, is_private, _posted = _v075_profile_request_identity(request, cfg)
        body = v075_load_profile(cfg, username, is_private) if bool(cfg.get("v075_social_enabled", True)) else b""
        if body:
            log_event(cfg, "V075-SOCIAL-PROFILE-LOAD",
                      f"Username={username!r}; private={int(is_private)}; bytes={len(body)}; sha256={hashlib.sha256(body).hexdigest()}")
        response = make_http_response(
            b"HTTP/1.0 200 OK\r\n", b"application/octet-stream", body, method
        )
        return response, path, body

    # V070: V069 live capture proves that after buddy invitation handling the
    # retail client resolves vmail.online.scee.com and repeatedly requests
    # /mt/servlet/MailInbox. V069 returned 404, causing an immediate retry loop.
    # Use the smallest controlled empty-inbox probe first: HTTP 200, the same
    # application/octet-stream media type used by GHttpVideo, and a zero-length
    # body. The retail ISO exposes inbox entry field names, but we intentionally
    # do not invent an entry container until the client proves an empty body is
    # insufficient.
    if path.rstrip("/").lower() == "/mt/servlet/mailinbox":
        headers, reqbody = _v075_http_request_parts(request)
        rec = _v076_request_user(cfg, headers)
        if str(cfg.get("v076_videomail_inbox_mode", "empty_xml")).lower() == "local_entries_experimental":
            body = v076_vmail_inbox_xml(cfg, (rec or {}).get("account_id"))
        else:
            body = b'<?xml version="1.0" encoding="ISO-8859-1"?><inbox/>\n'
        _v076_capture_http_payload(cfg, "videomail_capture", path, request, reqbody)
        log_event(cfg, "V076-VIDEO-MAIL-INBOX", f"AccountID={(rec or {}).get('account_id',0)}; mode={cfg.get('v076_videomail_inbox_mode','empty_xml')}; bytes={len(body)}")
        response = make_http_response(
            b"HTTP/1.0 200 OK\r\n", b"text/xml", body, method
        )
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



def save_https_exchange(cfg, addr, request: bytes, response: bytes, path: str | None):
    """Persist decrypted HTTPS request/response pairs for post-TLS reverse engineering."""
    if not bool(cfg.get("capture_https_plain", True)):
        return None
    try:
        outdir = ROOT / cfg.get("log_dir", "logs") / "https_plain"
        outdir.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        safe_path = re.sub(r"[^A-Za-z0-9._-]+", "_", (path or "unknown").strip("/")) or "root"
        stem = f"https_{addr[0].replace('.', '_')}_{addr[1]}_{safe_path}_{stamp}"
        reqp = outdir / f"{stem}.request.bin"
        respp = outdir / f"{stem}.response.bin"
        reqp.write_bytes(request)
        respp.write_bytes(response)
        log_event(cfg, "V043-HTTPS-SAVE",
                  f"path={path!r}; request={reqp.relative_to(ROOT)}; response={respp.relative_to(ROOT)}; "
                  f"req_sha256={hashlib.sha256(request).hexdigest()}; resp_sha256={hashlib.sha256(response).hexdigest()}")
        return reqp, respp
    except Exception as e:
        log_event(cfg, "V043-HTTPS-SAVE-ERROR", str(e))
        return None


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
    "v086_update_2000_2049": [ROOT / "tls" / "v086_update_server_2000_2049.der"],
    "v086_vmail_2000_2049": [ROOT / "tls" / "v086_vmail_server_2000_2049.der"],
    # V085 server-only experiment. These fresh leafs are valid from 2000 to
    # 2049 and are signed by the recovered EyeToy Chat Client private key.
    # Three chain layouts test the permissive 2004 BSAFE path builder without
    # replacing the trusted root in the ISO.
    "v085_evergreen_leaf_only_update": [ROOT / "tls" / "v085_evergreen_update.der"],
    "v085_evergreen_leaf_only_vmail": [ROOT / "tls" / "v085_evergreen_vmail.der"],
    "v085_selfissued_leaf_only_update": [ROOT / "tls" / "v085_selfissued_update.der"],
    "v085_selfissued_leaf_only_vmail": [ROOT / "tls" / "v085_selfissued_vmail.der"],
    "v085_evergreen_chain_update": [ROOT / "tls" / "v085_evergreen_update.der", ROOT / "tls" / "eyetoy_chat_client_2004.der"],
    "v085_evergreen_chain_vmail": [ROOT / "tls" / "v085_evergreen_vmail.der", ROOT / "tls" / "eyetoy_chat_client_2004.der"],
    # V080 clean revival: the patched retail disc trusts this replacement Root CA.
    # Only the leaf is sent: the matching Root CA is already present in MAINGAME.MSN.
    "v080_update_2026": [ROOT / "tls" / "v080_update_server_2026.der"],
    "v080_vmail_2026": [ROOT / "tls" / "v080_vmail_server_2026.der"],
    # Retail/Light certificate embedded in MAINGAME.MSN. It is signed directly
    # by the SCEE MIS root also embedded by the client. Although its subject is
    # "EyeToy Chat Client" (not a server hostname), it is a clean trust-chain
    # probe and, unlike the historical CA probes, we also have the matching RSA
    # private key, so the handshake can continue if EyeToy accepts it.
    # V041 exploit/diagnostic probe: exact update hostname leaf signed with the
    # embedded EyeToy Chat Client private key. Chain is leaf -> EyeToy Chat Client
    # -> trusted SCEE MIS root. The intermediate has BasicConstraints CA:FALSE, so
    # a standards-compliant validator should reject it; acceptance would show the
    # legacy BSAFE path builder is permissive enough to give us a usable server cert.
    "retail_delegated_server_probe": [ROOT / "tls" / "retail_delegated_server.der", ROOT / "tls" / "eyetoy_chat_client_2004.der"],
    "retail_delegated_vmail_probe": [ROOT / "tls" / "retail_delegated_vmail.der", ROOT / "tls" / "eyetoy_chat_client_2004.der"],
    # Same original retail client cert but with the SCEE root explicitly included
    # in the TLS Certificate chain, to separate missing-chain presentation from identity.
    "retail_client_with_root_probe": [ROOT / "tls" / "eyetoy_chat_client_2004.der", ROOT / "tls" / "scee_mis_root_2002.der"],
    "retail_client_signed_probe": [ROOT / "tls" / "eyetoy_chat_client_2004.der"],
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
    # V033 research probes: byte-for-byte historical certificates with only the
    # two UTCTime validity fields changed to a window that includes 2026.
    # Their original signatures are intentionally NOT recomputed. The purpose is
    # to learn validation order: if certificate_expired changes to bad_certificate,
    # unknown_ca, decrypt_error, etc., EyeToy has moved past the date gate.
    "historical_scee_date_mutation_probe": [ROOT / "tls" / "scee_mis_root_2002_validity_mutated.der"],
    "beta_test_date_mutation_probe": [ROOT / "tls" / "beta_test_ca_43.194.211.76_validity_mutated.der"],
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

# Matching private key for the retail/Light certificate
#   subject: CN=EyeToy Chat Client, O=SCEE, OU=SCEE MIS
#   SHA1: 6fc9e2ce00b169501d90921a74a278990e8374c2
# The certificate and key are embedded/obfuscated in the retail client and were
# recovered for this compatibility diagnostic.
TLS_RETAIL_RSA_N = int(
    "b9eef8ea5a29b1cf4fbbdd9f9d2a4fd853adea222b5d6e3b957d5c6bc153307f"
    "0ad082ef6befe10de6fdd8d29c090eb8ff5ecad8745090b5a5ffbd44907b68ce"
    "1c3ce948f3a244082543db3733dff0fe82e4779e21e6a6e613e11197b137761d"
    "3a23f174c1455a22661bbf6047f131f44a42dceb87a3d305721f2bb538c1f2c7",
    16,
)
TLS_RETAIL_RSA_D = int(
    "98d55409de9f13276354fb312e510f5cb43bea8eb7b28edfaf5b6252b89096f6"
    "767f3a816ee9b8c662af1a40d43da5ba6f3f0de1aa8a66c8c97053b53e4612b8"
    "a2526ed6584c71382c1b2fb3d0ad5833eb94252e5a29d31b02ac62b0d3d5c4c7"
    "3b3c6981b8b6dc4c925c3c290ff9d4c4efd9eb10dd57507b86793487f18131f1",
    16,
)
TLS_RETAIL_RSA_K = (TLS_RETAIL_RSA_N.bit_length() + 7) // 8

# V080 RSA-1024 private key shared by the fresh update/vmail leaf certificates.
# The CA private key is intentionally NOT bundled; only this leaf key is needed at runtime.
TLS_V080_RSA_N = int(
    'b660000bae0e73d91936151dc319da0b2ce41f4931bdb08d98053e64cb05bd01'
    '2ab0e7e26d84dcb32e1f2eeeea868d40ef6fbfc53da64d1eb37a21f29f77f56f'
    '3c7953537d77e0c70e9c33d986827639eda28486662640ad369127560371e4a3'
    '11f8982380cf26c105b9091156cbb1fd599e273fc35c070fa1efeee9034eadbb',
    16,
)
TLS_V080_RSA_D = int(
    'b2bd9dedd496579633ee5c7dc1e4895e208e27d78dc792cd036c483d72f959c7'
    '55f6f21d6a272842f8761982911a74406b2ac3f1e53d23226ed6c984c82442c7'
    '2e06a2ea95e77ad4654551b15331a1134bad52f044cbe1359d380cb36ca388d8'
    '3c52817dc573d2efa1d0a8c1e011cb8c8803868af7906382f9dae67cb7e98049',
    16,
)
TLS_V080_RSA_E = 65537
TLS_V080_RSA_K = (TLS_V080_RSA_N.bit_length() + 7) // 8

TLS_V086_RSA_N = int(
    "9e7f5923062faa61a3157c8898551ffd696741a5a60f3da8d55c55c51fb60ce6"
    "77f9ae2186bed72c9c249989895ac3e425f2c3311126d08aea20c696c6e890d5e"
    "e7a20886109c71ed8445d52c40b08c933a32337de2098bca969089cfabb2654c2"
    "ecb9c2677c543fd96495f81a5548fc7a800264678103b98c6c37f95f0bcd85",
    16,
)
TLS_V086_RSA_D = int(
    "7c374e0276fcb04968e893faf177f56443511b4fd93f2491c6f5607ae709643ed"
    "35428b639c62318e11e85fe1659be2075e53638a43a8941f58fce53a87be7d5a"
    "61d90b46f646a768ed1dda97f7f8fde5b1b8afd44b5d9cfad40eb8000e94bd56"
    "f454d1f45cc048fa6c18a6e19c7d6037a708ee1059687e7d62eb76764d9b241",
    16,
)
TLS_V086_RSA_E = 65537
TLS_V086_RSA_K = (TLS_V086_RSA_N.bit_length() + 7) // 8

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
        "client_unix_time": int.from_bytes(client_random[:4], "big"),
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


def _tls_rsa_pkcs1_v15_decrypt(ciphertext: bytes, profile: str | None = None) -> bytes:
    if profile in ("v086_update_2000_2049", "v086_vmail_2000_2049"):
        n, d, k = TLS_V086_RSA_N, TLS_V086_RSA_D, TLS_V086_RSA_K
    elif profile in ("v080_update_2026", "v080_vmail_2026"):
        n, d, k = TLS_V080_RSA_N, TLS_V080_RSA_D, TLS_V080_RSA_K
    elif (profile or "").startswith("v085_") or profile in ("retail_client_signed_probe", "retail_client_with_root_probe", "retail_delegated_server_probe", "retail_delegated_vmail_probe"):
        n, d, k = TLS_RETAIL_RSA_N, TLS_RETAIL_RSA_D, TLS_RETAIL_RSA_K
    else:
        n, d, k = TLS_RSA_N, TLS_RSA_D, TLS_RSA_K
    if len(ciphertext) != k:
        # Left-pad shorter encodings; reject oversized ones.
        if len(ciphertext) > k:
            raise ValueError(f"RSA ClientKeyExchange {len(ciphertext)} octets > modulus {k}")
        ciphertext = ciphertext.rjust(k, b"\x00")
    c = int.from_bytes(ciphertext, "big")
    if c >= n:
        raise ValueError("RSA ciphertext >= modulus")
    em = pow(c, d, n).to_bytes(k, "big")
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
    requested_cfg = str(cfg.get("update_tls_cert_profile", "auto_cycle")).strip()
    forced = str(cfg.get("v034_force_tls_profile", "")).strip()
    requested = forced or requested_cfg
    cfg["_v034_requested_tls_profile"] = requested_cfg
    cfg["_v034_effective_tls_profile"] = requested
    if forced:
        cfg["_v034_force_active"] = True
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
    profile_aliases = {
        "v086_vmail_2000_2049": "v086_update_2000_2049",
        "v085_evergreen_leaf_only_vmail": "v085_evergreen_leaf_only_update",
        "v085_selfissued_leaf_only_vmail": "v085_selfissued_leaf_only_update",
        "v085_evergreen_chain_vmail": "v085_evergreen_chain_update",
    }
    state_profile = profile_aliases.get(profile, profile)
    if state_profile in state["profiles"]:
        state["profiles"][state_profile] = result
    if result == "accepted":
        state["accepted_profile"] = state_profile
    elif result == "rejected" and state.get("accepted_profile") == state_profile:
        state["accepted_profile"] = None
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

_TLS_UTC_RE = re.compile(rb"([0-9]{12}Z)")


def _tls_cert_validity_strings(der: bytes):
    """Return likely X.509 UTCTime validity fields without depending on OpenSSL."""
    vals = [m.group(1).decode("ascii", errors="replace") for m in _TLS_UTC_RE.finditer(der)]
    return vals[:2]


def _tls_client_clock(client_random: bytes):
    """Decode the legacy TLS 1.0 gmt_unix_time field used by EyeToy Chat."""
    if len(client_random) < 4:
        return None
    epoch = int.from_bytes(client_random[:4], "big")
    try:
        when = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    if not 1990 <= when.year <= 2100:
        return None
    return {"epoch": epoch, "utc": when, "iso": when.strftime("%Y-%m-%d %H:%M:%S UTC")}


def _tls_parse_utctime(value: str):
    """Parse the RFC 5280 two-digit-year UTCTime form found in the bundled certs."""
    if not re.fullmatch(r"[0-9]{12}Z", str(value)):
        return None
    year2 = int(value[:2])
    year = 2000 + year2 if year2 <= 49 else 1900 + year2
    try:
        return dt.datetime(
            year, int(value[2:4]), int(value[4:6]), int(value[6:8]),
            int(value[8:10]), int(value[10:12]), tzinfo=dt.timezone.utc
        )
    except ValueError:
        return None


def _tls_log_client_clock(cfg, client_hello, profile: str, validity):
    """V083: turn an opaque certificate_expired failure into an actionable RTC verdict."""
    clock = _tls_client_clock(client_hello.get("client_random", b""))
    if clock is None:
        log_event(cfg, "V083-CLIENT-RTC-UNKNOWN",
                  f"profile={profile}; ClientHello sans gmt_unix_time exploitable")
        return None

    leaf_window = validity[0] if validity and len(validity[0]) >= 2 else []
    not_before = _tls_parse_utctime(leaf_window[0]) if leaf_window else None
    not_after = _tls_parse_utctime(leaf_window[1]) if leaf_window else None
    inside = bool(not_before and not_after and not_before <= clock["utc"] <= not_after)
    expected_year = int(cfg.get("v083_expected_client_rtc_year", cfg.get("v082_ps2_rtc_year", 2006)))
    window_text = (
        f"{not_before.strftime('%Y-%m-%d')}/{not_after.strftime('%Y-%m-%d')}"
        if not_before and not_after else "inconnue"
    )
    log_event(
        cfg, "V083-CLIENT-RTC",
        f"profile={profile}; client_gmt_unix_time={clock['epoch']}; client_utc={clock['iso']}; "
        f"leaf_window={window_text}; status={'OK' if inside else 'HORS_PLAGE'}"
    )
    if not inside:
        log_event(
            cfg, "V083-CLIENT-RTC-FIX",
            f"CAUSE PROBABLE TROUVEE: la PS2/PCSX2 annonce {clock['utc'].year}, hors validite du certificat SCEE. "
            f"Regler l'horloge emulee/console sur {expected_year}, redemarrer le jeu, puis retester."
        )
    return {**clock, "inside_leaf_window": inside, "leaf_window": window_text}


def _tls_make_validity_mutation(src: Path, dst: Path, not_before=b"240101000000Z", not_after=b"491231235959Z"):
    """Patch only the first two 13-byte UTCTime values. Signature is left stale on purpose."""
    if not src.is_file():
        return None
    data = bytearray(src.read_bytes())
    matches = list(_TLS_UTC_RE.finditer(bytes(data)))
    if len(matches) < 2:
        raise ValueError(f"{src.name}: deux UTCTime X.509 introuvables")
    if len(not_before) != 13 or len(not_after) != 13:
        raise ValueError("les dates probe doivent faire exactement 13 octets UTCTime")
    a, b = matches[0], matches[1]
    data[a.start(1):a.end(1)] = not_before
    data[b.start(1):b.end(1)] = not_after
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)
    return bytes(data)


def _tls_prepare_v33_date_probes(cfg):
    pairs = [
        ("historical_scee_date_mutation_probe", ROOT / "tls" / "scee_mis_root_2002.der", ROOT / "tls" / "scee_mis_root_2002_validity_mutated.der"),
        ("beta_test_date_mutation_probe", ROOT / "tls" / "beta_test_ca_43.194.211.76.der", ROOT / "tls" / "beta_test_ca_43.194.211.76_validity_mutated.der"),
    ]
    for profile, src, dst in pairs:
        try:
            original = src.read_bytes() if src.is_file() else None
            mutated = _tls_make_validity_mutation(src, dst)
            if mutated is None:
                log_event(cfg, "V037-TLS-DATE-PROBE-SKIP", f"profile={profile}; source absent={src}")
                continue
            log_event(cfg, "V037-TLS-DATE-PROBE", 
                f"profile={profile}; source={src.name}; original_validity={_tls_cert_validity_strings(original)}; "
                f"mutated_validity={_tls_cert_validity_strings(mutated)}; original_sha1={hashlib.sha1(original).hexdigest()}; "
                f"mutated_sha1={hashlib.sha1(mutated).hexdigest()}; signature_recomputed=False; purpose=validation_order")
        except Exception as e:
            log_event(cfg, "V037-TLS-DATE-PROBE-ERROR", f"profile={profile}; {e}")


def _tls_alert_research_hint(alert_txt: str, profile: str | None = None):
    """Translate the next TLS alert into a useful reverse-engineering action."""
    t = alert_txt.lower()
    if "certificate_expired" in t:
        if profile and profile.endswith("_date_mutation_probe"):
            return "date_mutation_same_gate: validity fields were moved into 2024-2049 but client still returned alert 45; leaf dates alone are not sufficient explanation (chain/trust/legacy error mapping remain candidates)"
        return "date_gate_or_legacy_mapping: client parsed certificate and returned alert 45; compare against date-mutation probes before concluding it is only the leaf validity window"
    if "bad_certificate" in t:
        return "signature_or_structure_gate: date gate likely passed; stale signature/structure was rejected"
    if "unknown_ca" in t:
        return "trust_gate: certificate structure/signature acceptable enough, but issuer/root not trusted"
    if "decrypt_error" in t:
        return "crypto_gate: a handshake signature/cryptographic verification failed"
    if "unsupported_certificate" in t:
        return "x509_capability_gate: certificate type/algorithm/extensions unsupported"
    if "certificate_unknown" in t:
        return "x509_other_gate: client rejected certificate for another validation reason"
    if "handshake_failure" in t:
        return "negotiation_gate: inspect cipher/version/certificate combination"
    return "unknown_gate: preserve raw TLS record and compare with adjacent probes"


def _tls_log_date_hypothesis(cfg, profile, alert_txt, state):
    if "certificate_expired" not in alert_txt.lower() or not profile.endswith("_date_mutation_probe"):
        return
    log_event(cfg, "V037-TLS-MUTATION-RESULT",
              f"profile={profile}; alert={alert_txt}; result=mutated validity did not by itself clear TLS alert 45")
    hist = state.get("history", []) if isinstance(state, dict) else []
    seen = set()
    for item in hist:
        if not isinstance(item, dict):
            continue
        p = str(item.get("profile", ""))
        d = str(item.get("detail", "")).lower()
        if p in ("historical_scee_date_mutation_probe", "beta_test_date_mutation_probe") and "certificate_expired" in d:
            seen.add(p)
    if {"historical_scee_date_mutation_probe", "beta_test_date_mutation_probe"}.issubset(seen):
        log_event(cfg, "V037-TLS-DATE-HYPOTHESIS",
                  "both historical and beta date-mutated probes returned certificate_expired; prioritize chain/trust-anchor validation, original server leaf/private-key recovery, and possible BSAFE/Sony alert remapping over further leaf-date-only patches")


def _tls_load_cert_chain(profile):
    paths = TLS_CERT_PROFILES[profile]
    ders = []
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"certificat V036 absent: {path}")
        ders.append(path.read_bytes())
    return ders


def _tls_send_server_flight(conn, client_hello, cfg, client_ip=None):
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
    dns_host = v044_recent_service_dns(client_ip, float(cfg.get("v044_tls_dns_max_age", 5.0))) if client_ip else None
    base_profile = profile
    v085_host_profiles = {
        "v085_evergreen_leaf_only_update": {
            "eyetoychat-update.online.scee.com": "v085_evergreen_leaf_only_update",
            "vmail.online.scee.com": "v085_evergreen_leaf_only_vmail",
        },
        "v085_selfissued_leaf_only_update": {
            "eyetoychat-update.online.scee.com": "v085_selfissued_leaf_only_update",
            "vmail.online.scee.com": "v085_selfissued_leaf_only_vmail",
        },
        "v085_evergreen_chain_update": {
            "eyetoychat-update.online.scee.com": "v085_evergreen_chain_update",
            "vmail.online.scee.com": "v085_evergreen_chain_vmail",
        },
    }
    if base_profile == "v086_update_2000_2049":
        profile = "v086_vmail_2000_2049" if dns_host == "vmail.online.scee.com" else "v086_update_2000_2049"
    elif base_profile in v085_host_profiles and dns_host in v085_host_profiles[base_profile]:
        profile = v085_host_profiles[base_profile][dns_host]
    elif bool(cfg.get("v080_native_ca_enabled", True)):
        if dns_host == "vmail.online.scee.com":
            profile = "v080_vmail_2026"
        elif dns_host == "eyetoychat-update.online.scee.com":
            profile = "v080_update_2026"
    elif bool(cfg.get("v044_dynamic_tls_hostname", True)):
        if dns_host == "vmail.online.scee.com":
            profile = "retail_delegated_vmail_probe"
        elif dns_host == "eyetoychat-update.online.scee.com":
            profile = "retail_delegated_server_probe"
    if dns_host or profile != base_profile:
        log_event(cfg, "V044-TLS-HOST-SELECT", f"client={client_ip}; recent_dns={dns_host}; base_profile={base_profile}; selected_profile={profile}")
    cert_chain = _tls_load_cert_chain(profile)
    cert_bytes = b"".join(_tls_u24(len(cert)) + cert for cert in cert_chain)
    cert_fps = [hashlib.sha1(cert).hexdigest() for cert in cert_chain]
    if slot is None:
        cycle_txt = "mode_manuel"
        state_txt = "manual"
    else:
        cycle_txt = f"slot={slot}/{len(profiles)-1}; persistent_attempt={state.get('attempts', 0)}"
        state_txt = _tls_cert_state_summary(state, profiles)
    validity = [_tls_cert_validity_strings(cert) for cert in cert_chain]
    _tls_log_client_clock(cfg, client_hello, profile, validity)
    log_event(
        cfg, "V037-TLS-PROFILE-RESOLUTION",
        f"config_path={CONFIG_PATH}; requested={cfg.get('_v034_requested_tls_profile', cfg.get('update_tls_cert_profile'))}; "
        f"forced={cfg.get('v034_force_tls_profile', '') or 'none'}; effective={profile}; mode={'forced' if cfg.get('_v034_force_active') else 'config'}"
    )
    log_event(
        cfg, "UPDATE-TLS-CERT-PROFILE",
        f"profile={profile}; {cycle_txt}; chain_len={len(cert_chain)}; sha1={cert_fps}; validity={validity}; ordre={profiles}; state=[{state_txt}]; exhausted={exhausted}"
    )
    if exhausted:
        log_event(cfg, "UPDATE-TLS-ALL-CERTS-REJECTED", "Les profils generes sont deja rejetes; V036 connait les deux ancres beta (SCEE MIS et Test Cert 43.194.211.76) et les sonde separement")

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
            f"TLS version={ch['version'].hex()}; ciphers=[{offered_txt}]; compression={ch['compression']}; "
            f"hello_sha1={hashlib.sha1(ch['handshake_raw']).hexdigest()}; hello_sha256={hashlib.sha256(ch['handshake_raw']).hexdigest()}"
        )
        if ch["version"] != TLS10_VERSION:
            log_event(cfg, "UPDATE-TLS-WARN", f"ClientHello annonce {ch['version'].hex()}, V031 répond TLS1.0")

        suite, server_random, server_flight_hs, cert_profile = _tls_send_server_flight(conn, ch, cfg, addr[0])
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
                log_event(cfg, "V037-TLS-VALIDATION-GATE", f"profile={cert_profile}; alert={alert_txt}; inference={_tls_alert_research_hint(alert_txt, cert_profile)}")
                if bool(cfg.get("capture_tls_raw", True)):
                    try:
                        rawdir = ROOT / cfg.get("log_dir", "logs") / "raw_tls"
                        rawdir.mkdir(parents=True, exist_ok=True)
                        rp = rawdir / f"tls_alert_{addr[0].replace('.', '_')}_{addr[1]}_{int(time.time()*1000)}.bin"
                        rp.write_bytes(rraw)
                        log_event(cfg, "V037-TLS-RAW-SAVE", f"record TLS alert sauvegardé: {rp.relative_to(ROOT)}; sha256={hashlib.sha256(rraw).hexdigest()}")
                    except Exception as _e:
                        log_event(cfg, "V037-TLS-RAW-SAVE-ERROR", str(_e))
                v031_note_tls_failure(addr[0], cert_profile, alert_txt)
                log_event(cfg, "V037-DISCONNECT-STATE", f"TLS fatal enregistré pour client={addr[0]}; profile={cert_profile}; alert={alert_txt}; MAS sera observé avant fermeture contrôlée")
                state, profiles = _tls_mark_cert_result(cfg, cert_profile, "rejected", alert_txt)
                _v037_record_tls_verdict(cfg, cert_profile, "rejected", alert_txt)
                _tls_log_date_hypothesis(cfg, cert_profile, alert_txt, state)
                if "certificate_expired" in alert_txt.lower() and cert_profile.startswith("v085_"):
                    clock = _tls_client_clock(ch.get("client_random", b""))
                    clock_text = clock["iso"] if clock else "illisible"
                    log_event(
                        cfg,
                        "V085-EVERGREEN-RESULT",
                        f"profile={cert_profile}; client_clock={clock_text}; la feuille serveur est valide 2000-2049. "
                        "Une alerte 45 indique maintenant que le validateur controle aussi le certificat historique de la chaine, "
                        "ou reutilise ce code d alerte pour un autre echec de chemin. Tester le profil V085 suivant."
                    )
                elif "certificate_expired" in alert_txt.lower():
                    clock = _tls_client_clock(ch.get("client_random", b""))
                    expected_year = int(cfg.get("v083_expected_client_rtc_year", cfg.get("v082_ps2_rtc_year", 2006)))
                    clock_text = clock["iso"] if clock else "illisible"
                    log_event(
                        cfg, "V083-CERTIFICATE-EXPIRED-FIX",
                        f"client_clock={clock_text}; action=regler la date PS2/PCSX2 sur {expected_year}; "
                        "ce refus arrive avant ClientKeyExchange et avant l'authentification DNAS"
                    )
                log_event(cfg, "UPDATE-TLS-CERT-REJECTED", f"profile={cert_profile}; client a rejeté le certificat/handshake avant ClientKeyExchange; state=[{_tls_cert_state_summary(state, profiles)}]")
                remaining = [p for p in profiles if state['profiles'].get(p) not in ('rejected', 'trusted_probe')]
                if not remaining:
                    log_event(cfg, "UPDATE-TLS-ALL-CERTS-REJECTED", "Tous les profils TLS de V036 ont ete rejetes. La CA SCEE historique est identifiee; prochaine cible: certificat serveur historique + cle privee correspondante, ou autre materiel de signature serveur.")
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
                        if cert_profile in (
                            "historical_scee_root_probe", "beta_test_ca_probe",
                            "historical_scee_date_mutation_probe", "beta_test_date_mutation_probe"
                        ):
                            probe_names = {
                                "historical_scee_root_probe": "SCEE MIS root 2002",
                                "beta_test_ca_probe": "beta Test Cert CN=43.194.211.76",
                                "historical_scee_date_mutation_probe": "SCEE MIS root 2002 validity-mutated (stale signature)",
                                "beta_test_date_mutation_probe": "beta Test Cert validity-mutated (stale signature)",
                            }
                            probe_name = probe_names[cert_profile]
                            state, profiles = _tls_mark_cert_result(cfg, cert_profile, "trusted_probe", f"ClientKeyExchange recu avec {probe_name} presente comme certificat serveur")
                            _v037_record_tls_verdict(cfg, cert_profile, "client_key_exchange", f"ClientKeyExchange recu avec {probe_name}")
                            log_event(cfg, "V037-TLS-CLIENTKEYEXCHANGE-REACHED", f"GROSSE AVANCE: EyeToy a envoye ClientKeyExchange avec {probe_name}. Les controles anterieurs (dont la date) ont ete depasses. Arret volontaire: la cle privee historique correspondante n'est pas disponible et le probe date-mutated a volontairement une signature stale.")
                            log_event(cfg, "UPDATE-TLS-NEXT-STEP", "Conserver le RAW ClientKeyExchange et rechercher le leaf serveur historique / materiel de signature correspondant. Ne pas tenter de dechiffrer avec la cle locale update_server, qui ne correspond pas a ce modulus.")
                            return
                        if len(body) >= 2:
                            declared = struct.unpack("!H", body[:2])[0]
                            encrypted = body[2:2+declared] if declared <= len(body)-2 else body
                        else:
                            encrypted = body
                        if cert_profile in ("v086_update_2000_2049", "v086_vmail_2000_2049"):
                            expected_rsa_k = TLS_V086_RSA_K
                        elif cert_profile in ("v080_update_2026", "v080_vmail_2026"):
                            expected_rsa_k = TLS_V080_RSA_K
                        elif cert_profile.startswith("v085_") or cert_profile in ("retail_client_signed_probe", "retail_client_with_root_probe", "retail_delegated_server_probe", "retail_delegated_vmail_probe"):
                            expected_rsa_k = TLS_RETAIL_RSA_K
                        else:
                            expected_rsa_k = TLS_RSA_K
                        if len(encrypted) != expected_rsa_k and len(body) == expected_rsa_k:
                            encrypted = body
                        premaster = _tls_rsa_pkcs1_v15_decrypt(encrypted, cert_profile)
                        state, profiles = _tls_mark_cert_result(cfg, cert_profile, "accepted", "ClientKeyExchange recu")
                        _v037_record_tls_verdict(cfg, cert_profile, "accepted", "ClientKeyExchange recu")
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
                    # V071: do not stop at the header terminator for POSTs.
                    # Honour Content-Length so ProfilePost's 252-byte binary body
                    # is fully consumed before we answer and close TLS.
                    req_bytes = bytes(request)
                    sep = b"\r\n\r\n"
                    h_end = req_bytes.find(sep)
                    sep_len = 4
                    if h_end < 0:
                        sep = b"\n\n"
                        h_end = req_bytes.find(sep)
                        sep_len = 2
                    if h_end >= 0:
                        headers = req_bytes[:h_end].decode("iso-8859-1", errors="replace")
                        m_cl = re.search(r"(?im)^Content-Length\s*:\s*(\d+)\s*$", headers)
                        content_length = int(m_cl.group(1)) if m_cl else 0
                        expected_total = h_end + sep_len + content_length
                        if len(req_bytes) >= expected_total:
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
            body = b"EyeToy Chat Local TLS V037\n"
            response = make_http_response(b"HTTP/1.0 200 OK\r\n", b"text/plain", body, "GET")
            path = "<non-parse>"
        protected = server_cipher.encrypt(TLS_CONTENT_APPLICATION_DATA, TLS10_VERSION, response)
        conn.sendall(_tls_record(TLS_CONTENT_APPLICATION_DATA, protected))
        log_event(
            cfg, "UPDATE-TLS-HTTP-TX",
            f"Réponse HTTPS envoyée pour path={path!r}; http_len={len(response)}; body_len={len(body) if body is not None else 0}",
            response
        )
        if path and path.rstrip("/").lower() == "/mt/servlet/configretrievemessagetransformer":
            vh = build_vmail_config_headers(cfg)
            bool_map = {k: v for k, v in vh if k in {
                "ChatRooms.NonRegistered.Access", "ChatRooms.Registered.Access",
                "ChatRooms.Thumbnails.Read", "ChatRooms.Thumbnails.Post",
                "VideoMail.Inbox", "VideoMail.Post", "ScreenSaver.Access",
                "FriendshipRequest.Lock", "Product.Access"
            }}
            log_event(cfg, "V051-VMAIL-CONFIG-BOOL-TX",
                      f"ConfigRetrieveMessageTransformer -> HTTP 200; body_len=0; settings_as_headers={len(vh)}; booleans={bool_map}; Product.Access={dict(vh).get('Product.Access')}")
        if path and path.rstrip("/").lower() == "/mt/servlet/profileretrieve":
            status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            log_event(cfg, "V067-PROFILE-RETRIEVE-TX",
                      f"ProfileRetrieve -> {status_line}; content_type=application/octet-stream; body_len={len(body) if body is not None else 0}; probe=empty_profile")
        if path and path.rstrip("/").lower() == "/mt/servlet/profilepost":
            status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            req_b = bytes(request)
            sep_i = req_b.find(b"\r\n\r\n")
            sep_n = 4
            if sep_i < 0:
                sep_i = req_b.find(b"\n\n"); sep_n = 2
            posted = req_b[sep_i + sep_n:] if sep_i >= 0 else b""
            log_event(cfg, "V071-PROFILE-POST-TX",
                      f"ProfilePost -> {status_line}; content_type=application/octet-stream; posted_body_len={len(posted)}; posted_sha256={hashlib.sha256(posted).hexdigest()}; response_body_len={len(body) if body is not None else 0}",
                      posted if posted else None)
        if path and path.rstrip("/").lower() == "/mt/servlet/mailinbox":
            status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            log_event(cfg, "V070-MAIL-INBOX-TX",
                      f"MailInbox -> {status_line}; content_type=text/xml; body_len={len(body) if body is not None else 0}; empty_inbox_xml=1")
        if path and re.fullmatch(r"/announcements/announcements\.\d+\.txt", path, flags=re.IGNORECASE):
            status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            log_event(cfg, "V052-HTTP-ANNOUNCEMENTS-TX",
                      f"{path} -> {status_line}; body_len={len(body) if body is not None else 0}; sha256={hashlib.sha256(body or b'').hexdigest()}")
        if path and path.rstrip("/").lower() == "/chatroom_hierarchy_1_51.xml":
            status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            pi = v060_last_probe_info()
            _mode = str(pi.get('mode') or '')
            _profile = dict(pi.get("profile") or {})
            _rooms = list(pi.get("rooms") or [])
            log_event(cfg, "V066-HTTP-CHATROOM-PROFILE",
                      f"{path} -> {status_line}; probe_index={pi.get('index')}; mode={_mode}; "
                      f"mode_count={pi.get('mode_count')}; body_len={len(body) if body is not None else 0}; "
                      f"xml_decl={str(body.startswith(b'<?xml') if body else False).lower()}; "
                      f"menu_metadata={'language+category+room+title+icon' if _mode == 'v086_multilingual_text_rooms' else ('title+icon' if _mode in ('v065_full_menu_profile','v066_required_callback_fields') else 'legacy_minimal_or_matrix')}; "
                      f"callback_fields={'vmail_inbox_size+chatroom_welcome2+welcome2/version' if _mode in ('v066_required_callback_fields','v086_multilingual_text_rooms') else 'absent_or_legacy'}; "
                      f"content_type=text/xml; content_encoding=identity; "
                      f"body_sha256={hashlib.sha256(body or b'').hexdigest()}; "
                      f"response_sha256={hashlib.sha256(response).hexdigest()}; "
                      f"profile={_profile.get('name')}; room={_profile.get('room_title')!r}/{_profile.get('room_id')}; "
                      f"channel={_profile.get('channel_name')!r}/{_profile.get('channel_world_id')}; "
                      f"login_world={_profile.get('account_login_world_id')}; "
                      f"connect_world={_profile.get('connect_world_id')}; "
                      f"v086_rooms={[(r.get('language'), r.get('category'), r.get('title'), r.get('world_id')) for r in _rooms]}; "
                      f"gf1={_profile.get('generic_field1')}; gf_level={_profile.get('generic_field_level')}; "
                      f"next_expected=UI_wait_or_LobbyExt/0x12_or_0x86_or_0x1F_or_Lobby/0x25_or_AccountLogout", body)
        if path and path.rstrip("/").lower() == "/mt/servlet/adfeedretrieve":
            status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            req_b = bytes(request)
            first_line = req_b.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
            log_event(cfg, "V072-ADFEED-TX",
                      f"AdFeedRetrieve -> {status_line}; request={first_line!r}; content_type={cfg.get('v072_adfeed_content_type','text/xml')}; body_len={len(body) if body is not None else 0}; body_sha256={hashlib.sha256(body or b'').hexdigest()}", body)
        _v072_img_path = str(cfg.get("v072_adfeed_image_path", "/adfeed/eyetoy_http_test.png"))
        if not _v072_img_path.startswith("/"):
            _v072_img_path = "/" + _v072_img_path
        if path and path.lower() == _v072_img_path.lower():
            status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            log_event(cfg, "V072-ADFEED-IMAGE-TX",
                      f"{path} -> {status_line}; content_type=image/png; body_len={len(body) if body is not None else 0}; png_signature={str(bool(body and body.startswith(bytes.fromhex('89504e470d0a1a0a')))).lower()}; sha256={hashlib.sha256(body or b'').hexdigest()}")
        save_https_exchange(cfg, addr, bytes(request), response, path)
        if path and path.rstrip("/").lower() == "/qa_patches/index.xml":
            log_event(cfg, "UPDATE-TLS-INDEX", f"Catalogue HTTPS mode={cfg.get('update_mode', 'no_update')} BUILD={cfg.get('update_build', 194)}", body)

        # Graceful encrypted close_notify (warning=1, description=0).
        alert_plain = b"\x01\x00"
        alert_enc = server_cipher.encrypt(TLS_CONTENT_ALERT, TLS10_VERSION, alert_plain)
        conn.sendall(_tls_record(TLS_CONTENT_ALERT, alert_enc))
        log_event(cfg, "UPDATE-TLS-DONE",
                  "Réponse HTTPS et close_notify serveur envoyés; consommation/parsing client non confirmés")
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


# --- V043 AccountLogin / transition to MLS -----------------------------------
# Horizon RT.Models confirms MediusAccountLoginRequest = Lobby/0x07 and
# MediusAccountLoginResponse = Lobby/0x08.  The response carries the next
# NetConnectionInfo (normally MLS TCP/10078).  We deliberately keep this
# serializer isolated so later captures can adjust the wire layout without
# disturbing the already-proven SessionBegin/Version/Policy path.
MEDIUS_ACCOUNT_LOGIN_REQUEST = 0x07
MEDIUS_ACCOUNT_LOGIN_RESPONSE = 0x08
ACCOUNTNAME_MAXLEN = 32
PASSWORD_MAXLEN = 32
NET_SESSION_KEY_LEN = 17
NET_ACCESS_KEY_LEN = 17
NET_MAX_NETADDRESS_LENGTH = 16
NET_ADDRESS_LIST_COUNT = 2
NET_CONNECTION_CLIENT_SERVER_TCP = 1
NET_ADDRESS_NONE = 0
NET_ADDRESS_EXTERNAL = 1
NET_ADDRESS_NAT_SERVICE = 3
MEDIUS_ACCOUNT_MASTER = 1


def _decode_medius_string(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def parse_account_login_request(payload: bytes):
    """Parse Lobby/0x07 using the retail-era Medius layout.

    Wire layout after class/type:
      MessageID[21] + SessionKey[17] + Username[32] + Password[32]

    Password bytes are returned only so the caller can report length/hash; the
    server never writes the password itself to logs.
    """
    need = 2 + MESSAGEID_MAXLEN + NET_SESSION_KEY_LEN + ACCOUNTNAME_MAXLEN + PASSWORD_MAXLEN
    if len(payload) < need:
        raise ValueError(f"AccountLoginRequest trop court: {len(payload)} octets, attendu >= {need}")
    if payload[0] != MEDIUS_CLASS_LOBBY or payload[1] != MEDIUS_ACCOUNT_LOGIN_REQUEST:
        raise ValueError(f"pas Lobby/0x07: class={payload[0]:02X} type={payload[1]:02X}")
    off = 2
    message_id = payload[off:off+MESSAGEID_MAXLEN]; off += MESSAGEID_MAXLEN
    session_raw = payload[off:off+NET_SESSION_KEY_LEN]; off += NET_SESSION_KEY_LEN
    user_raw = payload[off:off+ACCOUNTNAME_MAXLEN]; off += ACCOUNTNAME_MAXLEN
    pass_raw = payload[off:off+PASSWORD_MAXLEN]; off += PASSWORD_MAXLEN
    return {
        "message_id": message_id,
        "session_key": _decode_medius_string(session_raw),
        "username": _decode_medius_string(user_raw),
        "password_raw": pass_raw,
        "extra": payload[off:],
    }


def make_net_address(address_type: int, address: str, port: int) -> bytes:
    # Horizon's current serializer writes NetAddressType[i32], Address[16], Port[u32].
    return (struct.pack("<i", int(address_type)) +
            medius_fixed_string(address or "", NET_MAX_NETADDRESS_LENGTH) +
            struct.pack("<I", int(port) & 0xFFFFFFFF))


def make_net_connection_info(endpoint: str, port: int, world_id: int,
                             session_key: str, access_key: str,
                             nat_endpoint: str = "", nat_port: int = 0,
                             server_key: bytes | None = None) -> bytes:
    if server_key is None:
        # Horizon builds GlobalAuthPublic from N.ToByteArrayUnsigned().Reverse(),
        # which corresponds to the 64-byte little-endian modulus on the PS2 wire.
        server_key = int(MEDIUS_RSA_N).to_bytes(64, "little", signed=False)
    if len(server_key) != 64:
        raise ValueError(f"ServerKey Medius doit faire 64 octets, reçu {len(server_key)}")
    out = bytearray()
    out += struct.pack("<i", NET_CONNECTION_CLIENT_SERVER_TCP)
    out += make_net_address(NET_ADDRESS_EXTERNAL, endpoint, port)
    if nat_endpoint and nat_port:
        out += make_net_address(NET_ADDRESS_NAT_SERVICE, nat_endpoint, nat_port)
    else:
        out += make_net_address(NET_ADDRESS_NONE, "", 0)
    out += struct.pack("<i", int(world_id))
    out += server_key
    out += medius_fixed_string(session_key, NET_SESSION_KEY_LEN)
    out += medius_fixed_string(access_key, NET_ACCESS_KEY_LEN)
    return bytes(out)


def make_account_login_response(message_id: bytes, endpoint: str, port: int,
                                session_key: str, access_key: str,
                                account_id: int = 1, account_type: int = MEDIUS_ACCOUNT_MASTER,
                                medius_world_id: int = 1, status_code: int = 0,
                                nat_endpoint: str = "", nat_port: int = 0,
                                connect_world_id: int | None = None) -> bytes:
    """Serialize Lobby/0x08 according to Horizon MediusAccountLoginResponse.

    Layout:
      class/type + MessageID[21] + pad[3] + Status[i32] + AccountID[i32] +
      AccountType[i32] + MediusWorldID[i32] + NetConnectionInfo.

    ``connect_world_id`` is explicit in V064 because the WorldID inside
    NetConnectionInfo is a separate wire field.  It defaults to the historical
    local behavior (same value as MediusWorldID) for older call sites.
    """
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError(f"MessageID doit faire {MESSAGEID_MAXLEN} octets")
    out = bytearray([MEDIUS_CLASS_LOBBY, MEDIUS_ACCOUNT_LOGIN_RESPONSE])
    out += message_id
    out += b"\x00\x00\x00"
    out += struct.pack("<iiii", int(status_code), int(account_id), int(account_type), int(medius_world_id))
    net_world_id = medius_world_id if connect_world_id is None else int(connect_world_id)
    out += make_net_connection_info(endpoint, port, net_world_id, session_key, access_key,
                                    nat_endpoint=nat_endpoint, nat_port=nat_port)
    return bytes(out)


# --- V044 documented MLS post-login messages --------------------------------
MEDIUS_SESSION_END = 0x05
MEDIUS_SESSION_END_RESPONSE = 0x06
MEDIUS_ACCOUNT_UPDATE_STATS = 0x11
MEDIUS_ACCOUNT_UPDATE_STATS_RESPONSE = 0x12
MEDIUS_ACCOUNT_LOGOUT = 0x15
MEDIUS_ACCOUNT_LOGOUT_RESPONSE = 0x16
MEDIUS_PLAYER_INFO = 0x31
MEDIUS_PLAYER_INFO_RESPONSE = 0x32
MEDIUS_CHANNEL_INFO = 0x35
MEDIUS_CHANNEL_INFO_RESPONSE = 0x36
MEDIUS_GET_ANNOUNCEMENTS = 0x4B
MEDIUS_GET_ANNOUNCEMENTS_RESPONSE = 0x4D
MEDIUS_UPDATE_USER_STATE = 0x49
MEDIUS_PLAYER_IN_CHAT_WORLD = 2
MEDIUS_CONNECTION_ETHERNET = 1
ACCOUNTSTATS_MAXLEN = 256
ANNOUNCEMENT_MAXLEN = 1000


# V058 corrected post-hierarchy target: retail code starts the hard-coded
# default channel "Holding" / world 1000 immediately after hierarchy download.
# Horizon MediusLobbyMessageIds confirms JoinChannel=0x25, response=0x26.
MEDIUS_JOIN_CHANNEL = 0x25
MEDIUS_JOIN_CHANNEL_RESPONSE = 0x26
LOBBYPASSWORD_MAXLEN = 32


def parse_join_channel_request(payload: bytes):
    """Parse Lobby/0x25 MediusJoinChannelRequest (retail-era Medius 1.x).

    Horizon layout:
      class/type + MessageID[21] + SessionKey[17] + pad[2] +
      MediusWorldID[i32] + LobbyChannelPassword[32].
    """
    need = 2 + MESSAGEID_MAXLEN + NET_SESSION_KEY_LEN + 2 + 4 + LOBBYPASSWORD_MAXLEN
    if len(payload) < need or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_JOIN_CHANNEL]):
        raise ValueError(f"JoinChannelRequest invalide len={len(payload)} attendu>={need}")
    off = 2
    message_id = payload[off:off+MESSAGEID_MAXLEN]; off += MESSAGEID_MAXLEN
    session_raw = payload[off:off+NET_SESSION_KEY_LEN]; off += NET_SESSION_KEY_LEN
    pad = payload[off:off+2]; off += 2
    world_id = struct.unpack_from("<i", payload, off)[0]; off += 4
    password_raw = payload[off:off+LOBBYPASSWORD_MAXLEN]; off += LOBBYPASSWORD_MAXLEN
    return {
        "message_id": message_id,
        "session_key": _decode_medius_string(session_raw),
        "pad": pad,
        "world_id": world_id,
        "password": _decode_medius_string(password_raw),
        "extra": payload[off:],
    }


def make_join_channel_response(message_id: bytes, endpoint: str, port: int,
                               world_id: int, session_key: str, access_key: str,
                               status_code: int = 0,
                               nat_endpoint: str = "", nat_port: int = 0) -> bytes:
    """Serialize Lobby/0x26 MediusJoinChannelResponse SUCCESS.

    Horizon success response contains MessageID, 3-byte pad, StatusCode and a
    NetConnectionInfo pointing back to the Lobby Server for the selected channel.
    """
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError(f"MessageID JoinChannel invalide len={len(message_id)}")
    return (bytes([MEDIUS_CLASS_LOBBY, MEDIUS_JOIN_CHANNEL_RESPONSE]) +
            bytes(message_id) + b"\x00\x00\x00" + struct.pack("<i", int(status_code)) +
            make_net_connection_info(endpoint, port, int(world_id), session_key, access_key,
                                     nat_endpoint=nat_endpoint, nat_port=nat_port))

# V075 social Medius messages (retail-era standard Lobby / LobbyExt layouts).
MEDIUS_FIND_PLAYER = 0x39
MEDIUS_FIND_PLAYER_RESPONSE = 0x3A
MEDIUS_CHAT_MESSAGE = 0x3B
MEDIUS_CHAT_FWD_MESSAGE = 0x3C
MEDIUS_ADD_TO_BUDDY_LIST = 0x3F
MEDIUS_ADD_TO_BUDDY_LIST_RESPONSE = 0x40
MEDIUS_REMOVE_FROM_BUDDY_LIST = 0x41
MEDIUS_REMOVE_FROM_BUDDY_LIST_RESPONSE = 0x42
MEDIUS_GENERIC_CHAT_MESSAGE = 0x23
MEDIUS_GENERIC_CHAT_FWD_MESSAGE = 0x24
MEDIUS_PLAYER_SEARCH_ACCOUNT_ID = 0
MEDIUS_PLAYER_SEARCH_ACCOUNT_NAME = 1
MEDIUS_CHAT_BROADCAST = 0
MEDIUS_CHAT_WHISPER = 1
MEDIUS_CHAT_UNIVERSE = 2
MEDIUS_CHAT_BUDDY = 4
APPNAME_MAXLEN = 32
CHATMESSAGE_MAXLEN = 64

# V076 Night research: block/ignore and opaque binary relay.
MEDIUS_GET_IGNORE_LIST = 0xC0
MEDIUS_GET_IGNORE_LIST_RESPONSE = 0xC1
MEDIUS_ADD_TO_IGNORE_LIST = 0xC2
MEDIUS_ADD_TO_IGNORE_LIST_RESPONSE = 0xC3
MEDIUS_REMOVE_FROM_IGNORE_LIST = 0xC4
MEDIUS_REMOVE_FROM_IGNORE_LIST_RESPONSE = 0xC5
MEDIUS_BINARY_MESSAGE = 0x16
MEDIUS_BINARY_FWD_MESSAGE = 0x17
MEDIUS_BINARY_BROADCAST = 0
MEDIUS_BINARY_TARGET = 1
MEDIUS_BINARY_UNIVERSE = 2
BINARYMESSAGE_MAXLEN = 400
MEDIUS_FRIEND_CONFIRM_EXT = 0x05


def v076_parse_ignore_list_request(payload: bytes):
    need=2+21+17+2
    if len(payload)<need or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_GET_IGNORE_LIST]):
        raise ValueError(f"GetIgnoreList invalide len={len(payload)}")
    return {"message_id":payload[2:23], "session_key":_decode_medius_string(payload[23:40]), "extra":payload[42:]}


def v076_make_ignore_list_response(message_id, rec=None, status_code=1, end_of_list=True):
    rec=rec or {}; online=bool(rec.get("online",False))
    out=bytearray([MEDIUS_CLASS_LOBBY,MEDIUS_GET_IGNORE_LIST_RESPONSE]); out+=message_id; out+=b"\x00\x00\x00"
    out+=struct.pack("<i",int(status_code)); out+=struct.pack("<i",int(rec.get("account_id",0)))
    out+=medius_fixed_string(str(rec.get("name","")),32); out+=struct.pack("<i",2 if online else 0)
    out+=b"\x01" if end_of_list else b"\x00"; out+=b"\x00\x00\x00"; return bytes(out)


def v076_parse_binary_message(payload: bytes):
    need=2+21+17+2+4+4+400
    if len(payload)<need or payload[:2] != bytes([MEDIUS_CLASS_LOBBY_EXT, MEDIUS_BINARY_MESSAGE]):
        raise ValueError(f"BinaryMessage invalide len={len(payload)}")
    off=2; mid=payload[off:off+21]; off+=21; session=_decode_medius_string(payload[off:off+17]); off+=17
    pad=payload[off:off+2]; off+=2; mtype=struct.unpack_from("<i",payload,off)[0]; off+=4; target=struct.unpack_from("<i",payload,off)[0]; off+=4
    return {"message_id":mid,"session_key":session,"pad":pad,"message_type":mtype,"target_id":target,"message":payload[off:off+400],"extra":payload[off+400:]}


def v076_make_binary_fwd(message_id: bytes, originator_id: int, message_type: int, message: bytes):
    out=bytearray([MEDIUS_CLASS_LOBBY_EXT,MEDIUS_BINARY_FWD_MESSAGE]); out+=message_id; out+=b"\x00\x00\x00"
    out+=struct.pack("<ii",int(originator_id),int(message_type)); msg=bytes(message[:400]); out+=msg+bytes(400-len(msg)); return bytes(out)


def v076_save_binary_probe(cfg, originator_id, target_id, message_type, message):
    outdir=_v076_media_root(cfg)/"binary_candidates"; outdir.mkdir(parents=True,exist_ok=True)
    stamp=dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    p=outdir/f"{stamp}_from{int(originator_id or 0)}_to{int(target_id or 0)}_type{int(message_type)}.bin"; p.write_bytes(message)
    return p


def v076_parse_friend_confirm_probe(payload: bytes):
    # Public Medius 1.50 layout for LobbyExt/0x05.  Capture-driven: no response
    # packet is fabricated until EyeToy proves which response ID it expects.
    need=2+21+17+2+4+4
    if len(payload)<need or payload[:2] != bytes([MEDIUS_CLASS_LOBBY_EXT,MEDIUS_FRIEND_CONFIRM_EXT]):
        raise ValueError(f"FriendConfirmation 0x05 invalide len={len(payload)}")
    return {"message_id":payload[2:23],"session_key":_decode_medius_string(payload[23:40]),
            "target_account_id":struct.unpack_from("<i",payload,42)[0],"add_type":struct.unpack_from("<i",payload,46)[0],"extra":payload[50:]}


def _v075_parse_account_target_request(payload: bytes, packet_type: int):
    need = 2 + MESSAGEID_MAXLEN + NET_SESSION_KEY_LEN + 2 + 4
    if len(payload) < need or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, packet_type]):
        raise ValueError(f"social target request 0x{packet_type:02X} invalide len={len(payload)}")
    return {"message_id": payload[2:23], "session_key": _decode_medius_string(payload[23:40]),
            "pad": payload[40:42], "account_id": struct.unpack_from("<i", payload, 42)[0], "extra": payload[46:]}


def _v075_make_status_response(message_id: bytes, packet_type: int, status_code: int = 0):
    return bytes([MEDIUS_CLASS_LOBBY, packet_type]) + message_id + b"\x00\x00\x00" + struct.pack("<i", int(status_code))


def v075_parse_find_player_request(payload: bytes):
    need = 2 + 21 + 17 + 2 + 4 + 4 + 32
    if len(payload) < need or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_FIND_PLAYER]):
        raise ValueError(f"FindPlayer invalide len={len(payload)}")
    off=2; mid=payload[off:off+21]; off+=21
    session=_decode_medius_string(payload[off:off+17]); off+=17; pad=payload[off:off+2]; off+=2
    search_type=struct.unpack_from("<i",payload,off)[0]; off+=4
    aid=struct.unpack_from("<i",payload,off)[0]; off+=4
    name=_decode_medius_string(payload[off:off+32]); off+=32
    return {"message_id":mid,"session_key":session,"pad":pad,"search_type":search_type,"account_id":aid,"name":name,"extra":payload[off:]}


def v075_make_find_player_response(message_id: bytes, rec=None, status_code=1, end_of_list=True):
    rec = rec or {}
    online = bool(rec.get("online", False))
    out=bytearray([MEDIUS_CLASS_LOBBY, MEDIUS_FIND_PLAYER_RESPONSE]); out+=message_id; out+=b"\x00\x00\x00"
    out+=struct.pack("<i",int(status_code))
    out+=struct.pack("<i",int(rec.get("application_id",10554) if rec else 0))
    out+=medius_fixed_string("EyeToy Chat",APPNAME_MAXLEN)
    out+=struct.pack("<i",1) # LobbyChatChannel
    out+=struct.pack("<i",int(rec.get("lobby_world_id",0) if online else 0))
    out+=struct.pack("<i",int(rec.get("account_id",0)))
    out+=medius_fixed_string(str(rec.get("name","")),ACCOUNTNAME_MAXLEN)
    out+=b"\x01" if end_of_list else b"\x00"; out+=b"\x00\x00\x00"
    return bytes(out)


def v075_parse_chat_message(payload: bytes, msg_class: int, packet_type: int):
    need=2+21+17+2+4+4+64
    if len(payload)<need or payload[:2] != bytes([msg_class,packet_type]):
        raise ValueError(f"ChatMessage {msg_class}/0x{packet_type:02X} invalide len={len(payload)}")
    off=2; mid=payload[off:off+21]; off+=21
    session=_decode_medius_string(payload[off:off+17]); off+=17; pad=payload[off:off+2]; off+=2
    mtype=struct.unpack_from("<i",payload,off)[0]; off+=4; target=struct.unpack_from("<i",payload,off)[0]; off+=4
    msg=_decode_medius_string(payload[off:off+64]); off+=64
    return {"message_id":mid,"session_key":session,"pad":pad,"message_type":mtype,"target_id":target,"message":msg,"extra":payload[off:]}


def v075_make_chat_fwd(msg_class: int, packet_type: int, originator_id: int, originator_name: str, message_type: int, message: str):
    out=bytearray([msg_class,packet_type]); out+=struct.pack("<I",int(time.time()) & 0xFFFFFFFF)
    out+=struct.pack("<ii",int(originator_id),int(message_type)); out+=medius_fixed_string(originator_name,32)
    out+=medius_fixed_string(message,64); return bytes(out)

# V054 expected next message after a successfully parsed chatroom hierarchy.
# Horizon/RT.Models: NetMessageTypes.MessageClassLobbyExt == 4,
# MediusLobbyExtMessageIds.SetLobbyWorldFilter == 0x12.
MEDIUS_CLASS_LOBBY_EXT = 4
MEDIUS_SET_LOBBY_WORLD_FILTER = 0x12
MEDIUS_SET_LOBBY_WORLD_FILTER_RESPONSE = 0x13
MEDIUS_SET_LOBBY_WORLD_FILTER1 = 0x86
MEDIUS_SET_LOBBY_WORLD_FILTER1_RESPONSE = 0x87
MEDIUS_GET_BUDDY_INVITATIONS = 0x08
MEDIUS_GET_BUDDY_INVITATIONS_RESPONSE = 0x09
MEDIUS_BUDDY_ADD_SYMMETRIC = 1


def parse_get_buddy_invitations_request(payload: bytes):
    """Parse LobbyExt/0x08 MediusGetBuddyInvitationsRequest.

    Captured EyeToy layout is exactly class/type + MessageID[21] = 23 bytes.
    """
    if len(payload) < 23 or payload[:2] != bytes([MEDIUS_CLASS_LOBBY_EXT, MEDIUS_GET_BUDDY_INVITATIONS]):
        raise ValueError(f"GetBuddyInvitationsRequest invalide len={len(payload)}")
    return {"message_id": payload[2:23], "extra": payload[23:]}


def make_get_buddy_invitations_response(message_id: bytes, status_code: int = 1,
                                          account_id: int = 0, account_name: str = "",
                                          add_type: int = MEDIUS_BUDDY_ADD_SYMMETRIC,
                                          end_of_list: bool = True) -> bytes:
    """Serialize LobbyExt/0x09 MediusGetBuddyInvitationsResponse.

    Public Medius implementations use NO_RESULT(1), AccountID=0, empty name,
    ADD_SYMMETRIC(1), EndOfList=true for an empty invitation list.
    Layout: class/type + MessageID[21] + pad[3] + Status[i32] + AccountID[i32]
            + AccountName[32] + AddType[i32] + EndOfList[u8] + pad[3].
    Total length: 74 bytes.
    """
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError("MessageID GetBuddyInvitations doit faire 21 octets")
    out = bytearray([MEDIUS_CLASS_LOBBY_EXT, MEDIUS_GET_BUDDY_INVITATIONS_RESPONSE])
    out += message_id
    out += b"\x00\x00\x00"
    out += struct.pack("<i", int(status_code))
    out += struct.pack("<i", int(account_id))
    out += medius_fixed_string(account_name, ACCOUNTNAME_MAXLEN)
    out += struct.pack("<i", int(add_type))
    out += b"\x01" if end_of_list else b"\x00"
    out += b"\x00\x00\x00"
    return bytes(out)


# V070: V069 capture-confirmed next social request after MailInbox starts is
# Lobby/0xD6 MediusGetBuddyList_ExtraInfo. Horizon maps the response to 0xD7.
MEDIUS_GET_BUDDY_LIST_EXTRA_INFO = 0xD6
MEDIUS_GET_BUDDY_LIST_EXTRA_INFO_RESPONSE = 0xD7


def parse_get_buddy_list_extra_info_request(payload: bytes):
    """Parse Lobby/0xD6 MediusGetBuddyList_ExtraInfoRequest.

    Captured EyeToy request is exactly class/type + MessageID[21] = 23 bytes.
    """
    if len(payload) < 23 or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_GET_BUDDY_LIST_EXTRA_INFO]):
        raise ValueError(f"GetBuddyList_ExtraInfoRequest invalide len={len(payload)}")
    return {"message_id": payload[2:23], "extra": payload[23:]}


def make_get_buddy_list_extra_info_response(message_id: bytes, status_code: int = 1,
                                               account_id: int = 0, account_name: str = "",
                                               end_of_list: bool = True,
                                               connect_status: int = 0, lobby_world_id: int = 0,
                                               game_world_id: int = 0, lobby_name: str = "",
                                               game_name: str = "") -> bytes:
    """Serialize Lobby/0xD7 empty MediusGetBuddyList_ExtraInfoResponse.

    Horizon's no-friends path uses MediusNoResult(1) + EndOfList=true.
    OnlineState is serialized as all-zero/disconnected: ConnectStatus[i32],
    LobbyWorldID[i32], GameWorldID[i32], LobbyName[64], GameName[64].
    Total packet length is 210 bytes including class/type.
    """
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError("MessageID GetBuddyList_ExtraInfo doit faire 21 octets")
    out = bytearray([MEDIUS_CLASS_LOBBY, MEDIUS_GET_BUDDY_LIST_EXTRA_INFO_RESPONSE])
    out += message_id
    out += b"\x00\x00\x00"
    out += struct.pack("<i", int(status_code))
    out += struct.pack("<i", int(account_id))
    out += medius_fixed_string(account_name, ACCOUNTNAME_MAXLEN)
    out += struct.pack("<i", int(connect_status))
    out += struct.pack("<i", int(lobby_world_id))
    out += struct.pack("<i", int(game_world_id))
    out += medius_fixed_string(lobby_name, 64)
    out += medius_fixed_string(game_name, 64)
    out += b"\x01" if end_of_list else b"\x00"
    out += b"\x00\x00\x00"
    return bytes(out)


def parse_set_lobby_world_filter_request(payload: bytes, request_type: int = MEDIUS_SET_LOBBY_WORLD_FILTER):
    """Capture/decode LobbyExt/0x12 without replying yet.

    Expected Horizon layout (50 bytes total):
      class/type + MessageID[21] + pad[3] + FilterMask1..4[u32] +
      LobbyFilterType[i32] + FilterMaskLevel[i32].
    Static EyeToy Beta code indicates its first Holding-room probe should use
    type=0, level=1, mask1=1000, mask2..4=0.
    """
    if len(payload) < 50 or payload[:2] != bytes([MEDIUS_CLASS_LOBBY_EXT, int(request_type) & 0xFF]):
        raise ValueError(f"SetLobbyWorldFilterRequest invalide len={len(payload)}")
    return {
        "message_id": payload[2:23],
        "pad": payload[23:26],
        "filter_mask1": struct.unpack_from("<I", payload, 26)[0],
        "filter_mask2": struct.unpack_from("<I", payload, 30)[0],
        "filter_mask3": struct.unpack_from("<I", payload, 34)[0],
        "filter_mask4": struct.unpack_from("<I", payload, 38)[0],
        "filter_type": struct.unpack_from("<i", payload, 42)[0],
        "filter_level": struct.unpack_from("<i", payload, 46)[0],
        "extra": payload[50:],
    }

def make_set_lobby_world_filter_response(req, status_code: int = 0, response_type: int = MEDIUS_SET_LOBBY_WORLD_FILTER_RESPONSE) -> bytes:
    """Serialize LobbyExt/0x13 and echo the accepted filter parameters.

    Horizon's MediusSetLobbyWorldFilterResponse layout is:
      class/type + MessageID[21] + pad[3] + StatusCode[i32] +
      FilterMask1..4[u32] + LobbyFilterType[i32] + FilterMaskLevel[i32].
    """
    message_id = bytes(req["message_id"])
    if len(message_id) != 21:
        raise ValueError(f"MessageID SetLobbyWorldFilter invalide len={len(message_id)}")
    return (bytes([MEDIUS_CLASS_LOBBY_EXT, int(response_type) & 0xFF]) +
            message_id + b"\x00\x00\x00" + struct.pack("<iIIIIii",
            int(status_code), int(req["filter_mask1"]), int(req["filter_mask2"]),
            int(req["filter_mask3"]), int(req["filter_mask4"]),
            int(req["filter_type"]), int(req["filter_level"])))



# V059 explicit logical default-channel model, made coherent by V064.
# Keep binding the channel to the AppId actually sent by the connected PS2.
MEDIUS_CHANNEL_LIST_EXTRA_INFO1 = 0x15         # LobbyExt request used by EyeToy Medius 1.51
MEDIUS_CHANNEL_LIST_EXTRA_INFO = 0x1F          # alternate LobbyExt request
MEDIUS_CHANNEL_LIST_EXTRA_INFO_RESPONSE = 0xED # Lobby response (Medius 1.x)
MEDIUS_NO_RESULT = 1
MEDIUS_FAIL = -966  # Horizon/RT.Common MediusCallbackStatus.MediusFail


def v059_default_channel(cfg, application_id, requested_world_id=None):
    profile = v064_chatroom_profile(cfg)
    selected = v086_room_by_world(cfg, requested_world_id)
    world_id = selected["world_id"] if selected else profile["channel_world_id"]
    channel_name = selected["title"] if selected else profile["channel_name"]
    return {
        "application_id": int(application_id or 0),
        "world_id": world_id,
        "name": channel_name,
        "max_players": int(cfg.get("v059_default_channel_max_players", 32)),
        "player_count": int(cfg.get("v059_default_channel_player_count", 0)),
        "game_world_count": int(cfg.get("v059_default_channel_game_world_count", 0)),
        "security_level": int(cfg.get("v059_default_channel_security_level", 0)),
        "generic_field1": (int(world_id) if selected else profile["generic_field1"]) & 0xFFFFFFFF,
        "generic_field2": int(cfg.get("v059_default_channel_generic_field2", 0)) & 0xFFFFFFFF,
        "generic_field3": int(cfg.get("v059_default_channel_generic_field3", 0)) & 0xFFFFFFFF,
        "generic_field4": int(cfg.get("v059_default_channel_generic_field4", 0)) & 0xFFFFFFFF,
        "generic_field_level": profile["generic_field_level"],
        "lobby_filter_mask_level": profile["lobby_filter_mask_level"],
    }


def parse_channel_list_extra_info_request(payload: bytes, request_type: int = MEDIUS_CHANNEL_LIST_EXTRA_INFO):
    """Parse LobbyExt/0x1F MediusChannelList_ExtraInfoRequest.

    Horizon layout:
      class/type + MessageID[21] + pad[1] + PageID[u16] + PageSize[u16].
    """
    need = 2 + MESSAGEID_MAXLEN + 1 + 2 + 2
    if len(payload) < need or payload[:2] != bytes([MEDIUS_CLASS_LOBBY_EXT, int(request_type) & 0xFF]):
        raise ValueError(f"ChannelList_ExtraInfoRequest invalide len={len(payload)} attendu>={need}")
    off = 2
    message_id = payload[off:off+MESSAGEID_MAXLEN]; off += MESSAGEID_MAXLEN
    pad = payload[off:off+1]; off += 1
    page_id, page_size = struct.unpack_from("<HH", payload, off); off += 4
    return {
        "message_id": message_id,
        "pad": pad,
        "page_id": page_id,
        "page_size": page_size,
        "extra": payload[off:],
    }


def make_channel_list_extra_info_response(message_id: bytes, channel: dict,
                                          status_code: int = 0,
                                          end_of_list: bool = True) -> bytes:
    """Serialize EyeToy Chat ChannelList_ExtraInfoResponse (legacy Medius <=108).

    EyeToy Chat uses the pre-Medius-1.09 SCERT layout. Horizon only inserts
    GameWorldCount[2] + pad[2] when MediusVersion > 108, so those four bytes
    MUST be omitted here. Including them shifts SecurityLevel/GenericFields/
    LobbyName/EndOfList and leaves EyeToy waiting forever before JoinChannel.
    """
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError(f"MessageID ChannelList_ExtraInfo invalide len={len(message_id)}")
    out = bytearray([MEDIUS_CLASS_LOBBY, MEDIUS_CHANNEL_LIST_EXTRA_INFO_RESPONSE])
    out += bytes(message_id)
    out += b"\x00\x00\x00"
    out += struct.pack("<i", int(status_code))
    out += struct.pack("<i", int(channel.get("world_id", 0)))
    out += struct.pack("<HH", int(channel.get("player_count", 0)) & 0xFFFF,
                       int(channel.get("max_players", 0)) & 0xFFFF)
    # V087A FIX2: EyeToy Chat is pre-Medius-1.09 / protocol <=108.
    # Do NOT serialize GameWorldCount + 2-byte pad (only valid for >108).
    out += struct.pack("<i", int(channel.get("security_level", 0)))
    out += struct.pack("<IIII",
                       int(channel.get("generic_field1", 0)) & 0xFFFFFFFF,
                       int(channel.get("generic_field2", 0)) & 0xFFFFFFFF,
                       int(channel.get("generic_field3", 0)) & 0xFFFFFFFF,
                       int(channel.get("generic_field4", 0)) & 0xFFFFFFFF)
    out += struct.pack("<i", int(channel.get("generic_field_level", 0)))
    out += medius_fixed_string(str(channel.get("name", "Holding")), 64)
    out += bytes([1 if end_of_list else 0]) + b"\x00\x00\x00"
    return bytes(out)


def v059_filter_diagnostic(channel: dict, req):
    """Return a diagnostic only; do not reject the channel on an unproven filter rule."""
    if not req:
        return "no_filter_seen"
    masks = [int(req.get(f"filter_mask{i}", 0)) & 0xFFFFFFFF for i in range(1, 5)]
    fields = [int(channel.get(f"generic_field{i}", 0)) & 0xFFFFFFFF for i in range(1, 5)]
    return (f"mask1_eq_gf1={masks[0] == fields[0]}; masks={masks}; fields={fields}; "
            f"filter_type={req.get('filter_type')}; filter_level={req.get('filter_level')}; "
            f"channel_level={channel.get('generic_field_level')}")


def v064_join_channel_decision(channel: dict, requested_world_id: int):
    """Return the configured target and reject cross-profile Join requests."""
    expected_world_id = int(channel["world_id"])
    matches = int(requested_world_id) == expected_world_id
    return expected_world_id, (0 if matches else MEDIUS_FAIL), matches


def v064_channel_list_page(channel: dict, page_id: int, page_size: int):
    """Page the single-channel registry; Medius normally starts at page 1.

    Page 0 is accepted too because some implementations tolerate that legacy
    value for their first page.
    """
    if int(page_id) in (0, 1) and int(page_size) > 0:
        return dict(channel), 0, True
    empty = dict(channel)
    empty.update({
        "world_id": 0, "name": "", "player_count": 0, "max_players": 0,
        "game_world_count": 0, "security_level": 0,
        "generic_field1": 0, "generic_field2": 0,
        "generic_field3": 0, "generic_field4": 0,
        "generic_field_level": 0,
    })
    return empty, MEDIUS_NO_RESULT, False

def parse_update_user_state(payload: bytes):
    if len(payload) < 26 or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_UPDATE_USER_STATE]):
        raise ValueError(f"UpdateUserState invalide len={len(payload)}")
    return {
        "session_key": _decode_medius_string(payload[2:19]),
        "pad": payload[19:22],
        "user_action": struct.unpack_from("<i", payload, 22)[0],
        "extra": payload[26:],
    }

def parse_player_info_request(payload: bytes):
    if len(payload) < 46 or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_PLAYER_INFO]):
        raise ValueError(f"PlayerInfoRequest invalide len={len(payload)}")
    return {
        "message_id": payload[2:23],
        "session_key": _decode_medius_string(payload[23:40]),
        "pad": payload[40:42],
        "account_id": struct.unpack_from("<i", payload, 42)[0],
        "extra": payload[46:],
    }

def make_player_info_response(message_id: bytes, account_name: str, application_id: int = 10554,
                              player_status: int = MEDIUS_PLAYER_IN_CHAT_WORLD,
                              connection_class: int = MEDIUS_CONNECTION_ETHERNET,
                              status_code: int = 0, stats: bytes | None = None) -> bytes:
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError("MessageID PlayerInfo doit faire 21 octets")
    if stats is None:
        stats = bytes(ACCOUNTSTATS_MAXLEN)
    stats = bytes(stats[:ACCOUNTSTATS_MAXLEN]).ljust(ACCOUNTSTATS_MAXLEN, b"\x00")
    out = bytearray([MEDIUS_CLASS_LOBBY, MEDIUS_PLAYER_INFO_RESPONSE])
    out += message_id
    out += b"\x00\x00\x00"
    out += struct.pack("<i", int(status_code))
    out += medius_fixed_string(account_name, ACCOUNTNAME_MAXLEN)
    out += struct.pack("<iii", int(application_id), int(player_status), int(connection_class))
    out += stats
    return bytes(out)

def parse_channel_info_request(payload: bytes):
    if len(payload) < 46 or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_CHANNEL_INFO]):
        raise ValueError(f"ChannelInfoRequest invalide len={len(payload)}")
    return {
        "message_id": payload[2:23],
        "session_key": _decode_medius_string(payload[23:40]),
        "pad": payload[40:42],
        "world_id": struct.unpack_from("<i", payload, 42)[0],
        "extra": payload[46:],
    }

def make_channel_info_response(message_id: bytes, lobby_name: str = "EyeToy Chat Europe",
                               active_players: int = 1, max_players: int = 32,
                               status_code: int = 0) -> bytes:
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError("MessageID ChannelInfo doit faire 21 octets")
    out = bytearray([MEDIUS_CLASS_LOBBY, MEDIUS_CHANNEL_INFO_RESPONSE])
    out += message_id
    out += b"\x00\x00\x00"
    out += struct.pack("<i", int(status_code))
    out += medius_fixed_string(lobby_name, 64)
    out += struct.pack("<ii", int(active_players), int(max_players))
    return bytes(out)

def parse_get_announcements_request(payload: bytes):
    """Parse Lobby/0x4B MediusGetAnnouncementsRequest.

    Horizon layout:
      class/type + MessageID[21] + SessionKey[17] + pad[2] + ApplicationID[i32]
    """
    if len(payload) < 46 or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_GET_ANNOUNCEMENTS]):
        raise ValueError(f"GetAnnouncementsRequest invalide len={len(payload)}")
    return {
        "message_id": payload[2:23],
        "session_key": _decode_medius_string(payload[23:40]),
        "pad": payload[40:42],
        "application_id": struct.unpack_from("<i", payload, 42)[0],
        "extra": payload[46:],
    }


def make_get_announcements_response(message_id: bytes, announcement: str = "",
                                    announcement_id: int = 1, end_of_list: bool = True,
                                    status_code: int = 0) -> bytes:
    """Serialize Lobby/0x4D MediusGetAnnouncementsResponse."""
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError("MessageID GetAnnouncements doit faire 21 octets")
    out = bytearray([MEDIUS_CLASS_LOBBY, MEDIUS_GET_ANNOUNCEMENTS_RESPONSE])
    out += message_id
    out += b"\x00\x00\x00"
    out += struct.pack("<i", int(status_code))
    out += struct.pack("<i", int(announcement_id))
    out += medius_fixed_string(announcement, ANNOUNCEMENT_MAXLEN)
    out += b"\x01" if end_of_list else b"\x00"
    out += b"\x00\x00\x00"
    return bytes(out)


def parse_account_update_stats_request(payload: bytes):
    """Parse Lobby/0x11 MediusAccountUpdateStatsRequest.

    Horizon retail-era layout:
      class/type + MessageID[21] + SessionKey[17] + Stats[256]
    Total expected length: 296 bytes.
    """
    need = 2 + MESSAGEID_MAXLEN + NET_SESSION_KEY_LEN + ACCOUNTSTATS_MAXLEN
    if len(payload) < need or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_ACCOUNT_UPDATE_STATS]):
        raise ValueError(f"AccountUpdateStatsRequest invalide len={len(payload)} attendu>={need}")
    off = 2
    message_id = payload[off:off+MESSAGEID_MAXLEN]; off += MESSAGEID_MAXLEN
    session_raw = payload[off:off+NET_SESSION_KEY_LEN]; off += NET_SESSION_KEY_LEN
    stats = payload[off:off+ACCOUNTSTATS_MAXLEN]; off += ACCOUNTSTATS_MAXLEN
    return {
        "message_id": message_id,
        "session_key": _decode_medius_string(session_raw),
        "stats": stats,
        "extra": payload[off:],
    }


def make_account_update_stats_response(message_id: bytes, status_code: int = 0) -> bytes:
    """Serialize Lobby/0x12 MediusAccountUpdateStatsResponse.

    Layout: class/type + MessageID[21] + pad[3] + StatusCode[i32].
    """
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError("MessageID AccountUpdateStats doit faire 21 octets")
    return (bytes([MEDIUS_CLASS_LOBBY, MEDIUS_ACCOUNT_UPDATE_STATS_RESPONSE]) +
            message_id + b"\x00\x00\x00" + struct.pack("<i", int(status_code)))


def parse_account_logout_request(payload: bytes):
    """Parse Lobby/0x15 MediusAccountLogoutRequest.

    Wire layout: class/type + MessageID[21] + SessionKey[17].
    """
    if len(payload) < 40 or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_ACCOUNT_LOGOUT]):
        raise ValueError(f"AccountLogoutRequest invalide len={len(payload)}")
    return {
        "message_id": payload[2:23],
        "session_key": _decode_medius_string(payload[23:40]),
        "extra": payload[40:],
    }


def make_account_logout_response(message_id: bytes, status_code: int = 0) -> bytes:
    """Serialize Lobby/0x16 MediusAccountLogoutResponse."""
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError("MessageID AccountLogout doit faire 21 octets")
    return (bytes([MEDIUS_CLASS_LOBBY, MEDIUS_ACCOUNT_LOGOUT_RESPONSE]) +
            message_id + b"\x00\x00\x00" + struct.pack("<i", int(status_code)))


def parse_session_end_request(payload: bytes):
    if len(payload) < 40 or payload[:2] != bytes([MEDIUS_CLASS_LOBBY, MEDIUS_SESSION_END]):
        raise ValueError(f"SessionEndRequest invalide len={len(payload)}")
    return {"message_id": payload[2:23], "session_key": _decode_medius_string(payload[23:40]), "extra": payload[40:]}

def make_session_end_response(message_id: bytes, status_code: int = 0) -> bytes:
    if len(message_id) != MESSAGEID_MAXLEN:
        raise ValueError("MessageID SessionEnd doit faire 21 octets")
    return bytes([MEDIUS_CLASS_LOBBY, MEDIUS_SESSION_END_RESPONSE]) + message_id + b"\x00\x00\x00" + struct.pack("<i", int(status_code))

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


def save_post_policy_capture(cfg, addr, frame: bytes, plain: bytes | None, rt_id: int, nc=None, mt=None):
    """Save post-0x48 traffic separately so the next EyeToy stage is easy to diff."""
    if not bool(cfg.get("capture_post_policy_raw", True)):
        return None
    try:
        rawdir = ROOT / cfg.get("log_dir", "logs") / "post_policy"
        rawdir.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        stem = f"post48_{addr[0].replace('.', '_')}_{addr[1]}_rt{rt_id}"
        if nc is not None and mt is not None:
            stem += f"_c{int(nc):02X}_t{int(mt):02X}"
        fp = rawdir / f"{stem}_{stamp}.scert.bin"
        fp.write_bytes(frame)
        pp = None
        if plain is not None:
            pp = rawdir / f"{stem}_{stamp}.plain.bin"
            pp.write_bytes(plain)
        log_event(cfg, "V037-POST-POLICY-SAVE",
                  f"rt_id={rt_id}; class={nc}; type={mt}; scert={fp.relative_to(ROOT)}; "
                  f"scert_sha256={hashlib.sha256(frame).hexdigest()}; "
                  f"plain_sha256={hashlib.sha256(plain).hexdigest() if plain is not None else 'none'}")
        return fp, pp
    except Exception as e:
        log_event(cfg, "V037-POST-POLICY-SAVE-ERROR", str(e))
        return None

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

                            if info & INFO_NEWS:
                                n_payload = make_universe_news_response(req["message_id"], news, end_of_list=True)
                                n_frame = scert_make_encrypted(10, n_payload, rc_key, CTX_RC_CLIENT_SESSION)
                                conn.sendall(n_frame)
                                log_event(cfg, "MUIS-NEWS-TX", f"UniverseNewsResponse envoyé; News={news!r}; EndOfList=1", n_payload)
                                log_event(cfg, "MUIS-NEWS-TX-SCERT", "RT_MSG_SERVER_APP chiffré envoyé (UniverseNewsResponse)", n_frame)

                            u_payload = make_universe_variable_information_response(
                                req["message_id"], info, endpoint, next_port, uname, udesc,
                                universe_id=int(cfg.get("universe_id", 1)),
                                status=int(cfg.get("universe_status", 0)),
                                user_count=int(cfg.get("universe_user_count", 0)),
                                max_users=int(cfg.get("universe_max_users", 64)),
                                end_of_list=True)
                            u_frame = scert_make_encrypted(10, u_payload, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(u_frame)
                            log_event(cfg, "MUIS-UNIVERSE-TX",
                                      f"UniverseVariableInformationResponse -> {endpoint}:{next_port}; name={uname!r}; InfoFilter=0x{info:08X}; Status={int(cfg.get('universe_status', 0))}; Users={int(cfg.get('universe_user_count', 0))}/{int(cfg.get('universe_max_users', 64))}; EndOfList=1",
                                      u_payload)
                            log_event(cfg, "MUIS-UNIVERSE-TX-SCERT", "RT_MSG_SERVER_APP chiffré envoyé (UniverseVariableInformationResponse)", u_frame)


                            

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
    "packed_284",
    "pad_before_287",
    "tail_pad_287",
    "horizon_290",
    "v021_290",
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
    """Parse EyeToy Lobby/0xA3 and compare it with Horizon's Medius layout."""
    minimum = 2 + MESSAGEID_MAXLEN + 8
    if len(payload) < minimum:
        raise ValueError(f"class1/0xA3 trop court: {len(payload)} octets (minimum {minimum})")
    if payload[0] != MEDIUS_A3_PROBE_CLASS or payload[1] != MEDIUS_A3_PROBE_REQUEST:
        raise ValueError(f"pas class1/0xA3: class={payload[0]:02X} type={payload[1]:02X}")

    message_id = payload[2:2+MESSAGEID_MAXLEN]
    opaque = payload[2+MESSAGEID_MAXLEN:-8]
    character_encoding, language = struct.unpack_from("<II", payload, len(payload)-8)

    result = {
        "message_id": message_id,
        "opaque": opaque,
        "character_encoding": character_encoding,
        "language": language,
        "horizon_layout_available": False,
        "horizon_session_key_raw": b"",
        "horizon_session_key": "",
        "horizon_padding": b"",
        "horizon_character_encoding": None,
        "horizon_language": None,
        "extra": b"",
    }

    expected = 2 + MESSAGEID_MAXLEN + SESSIONKEY_MAXLEN + 2 + 4 + 4
    if len(payload) >= expected:
        off = 2 + MESSAGEID_MAXLEN
        key_raw = payload[off:off+SESSIONKEY_MAXLEN]; off += SESSIONKEY_MAXLEN
        pad = payload[off:off+2]; off += 2
        h_enc = struct.unpack_from("<i", payload, off)[0]; off += 4
        h_lang = struct.unpack_from("<i", payload, off)[0]; off += 4
        result.update({
            "horizon_layout_available": True,
            "horizon_session_key_raw": key_raw,
            "horizon_session_key": key_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace"),
            "horizon_padding": pad,
            "horizon_character_encoding": h_enc,
            "horizon_language": h_lang,
            "extra": payload[off:],
        })
    return result


def parse_policy_request(payload: bytes):
    """Parse EyeToy Lobby/0x47 and compare it with Horizon's Medius layout."""
    minimum = 2 + MESSAGEID_MAXLEN + 4
    if len(payload) < minimum:
        raise ValueError(f"class1/0x47 Policy trop court: {len(payload)} octets (minimum {minimum})")
    if payload[0] != MEDIUS_POLICY_CLASS or payload[1] != MEDIUS_POLICY_REQUEST:
        raise ValueError(f"pas class1/0x47 Policy: class={payload[0]:02X} type={payload[1]:02X}")

    message_id = payload[2:2+MESSAGEID_MAXLEN]
    policy_type = struct.unpack_from("<i", payload, len(payload)-4)[0]
    opaque = payload[2+MESSAGEID_MAXLEN:-4]

    result = {
        "message_id": message_id,
        "opaque": opaque,
        "policy_type": policy_type,
        "horizon_layout_available": False,
        "horizon_session_key_raw": b"",
        "horizon_session_key": "",
        "horizon_padding": b"",
        "horizon_policy_type": None,
        "extra": b"",
    }

    expected = 2 + MESSAGEID_MAXLEN + SESSIONKEY_MAXLEN + 2 + 4
    if len(payload) >= expected:
        off = 2 + MESSAGEID_MAXLEN
        key_raw = payload[off:off+SESSIONKEY_MAXLEN]; off += SESSIONKEY_MAXLEN
        pad = payload[off:off+2]; off += 2
        h_policy = struct.unpack_from("<i", payload, off)[0]; off += 4
        result.update({
            "horizon_layout_available": True,
            "horizon_session_key_raw": key_raw,
            "horizon_session_key": key_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace"),
            "horizon_padding": pad,
            "horizon_policy_type": h_policy,
            "extra": payload[off:],
        })
    return result


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
    if mode in ("horizon_290", "v021_290"):
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
    log_event(cfg, "MAS-CONNECT", f"Connexion TCP MAS acceptée depuis {addr[0]}:{addr[1]} -> {port}; handshake + SessionBegin + VersionServer + post-version probes + Policy V036")
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
    policy_answered_time = None
    post_policy_app_count = 0
    post_policy_non_echo_count = 0
    account_login_answered = False
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
                        log_event(cfg, "V037-MAS-AFTER-TLS-FAIL", f"echo_after_fail={v031_tls_fail_echoes}; age={age:.1f}s; alert={fail.get('alert')}; profile={fail.get('profile')}; MAS toujours vivant; rc_sha1={hashlib.sha1(rc_key).hexdigest() if rc_key else 'none'}")
                        min_echoes = max(1, int(cfg.get("v031_disconnect_after_echoes", 3)))
                        grace = max(0.0, float(cfg.get("v031_disconnect_grace_seconds", 25.0)))
                        mode = str(cfg.get("v031_disconnect_test_mode", "socket_close")).strip().lower()
                        if v031_tls_fail_echoes >= min_echoes and age >= grace and mode == "socket_close":
                            v031_consume_tls_failure(addr[0])
                            log_event(cfg, "V037-MAS-CONTROLLED-CLOSE", f"TEST socket_close: {v031_tls_fail_echoes} ECHO après échec TLS, age={age:.1f}s. Fermeture TCP MAS volontaire pour vérifier si EyeToy quitte l'écran de déconnexion.")
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
                                f"blob_len={req['blob_len']}; blob_all_zero={zero_blob}; extra={len(req['extra'])}; "
                                f"confidence=experimental_layout; semantics=unknown",
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
                            expected_key = str(cfg.get("mas_session_key", "ETC0000000000001"))
                            horizon_key_match = (req.get("horizon_session_key") == expected_key)
                            log_event(
                                cfg, "MAS-A3-REQ",
                                f"0xA3 SetLocalizationParams comparison #{a3_req_count}: "
                                f"CharacterEncoding={req['character_encoding']}; Language={req['language']}; "
                                f"HorizonSessionKey={req.get('horizon_session_key')!r}; "
                                f"horizon_key_match={horizon_key_match}; "
                                f"HorizonPad={req.get('horizon_padding', b'').hex(' ').upper()}; "
                                f"HorizonEncoding={req.get('horizon_character_encoding')}; "
                                f"HorizonLanguage={req.get('horizon_language')}; "
                                f"opaque_len={len(req['opaque'])}; extra={len(req.get('extra', b''))}",
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
                                    f"Réponse 0x{response_type:02X} de compatibilité envoyée; "
                                    f"mode={mode}; StatusCode=0; len={len(response_plain)}; "
                                    f"layout_A4_exact_non_confirme",
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
                            expected_key = str(cfg.get("mas_session_key", "ETC0000000000001"))
                            horizon_key_match = (req.get("horizon_session_key") == expected_key)
                            log_event(
                                cfg, "MAS-POLICY-REQ",
                                f"MediusGetPolicyRequest 0x47 #{policy_req_count}: "
                                f"MessageID=[{req['message_id'].hex(' ').upper()}]; "
                                f"HorizonSessionKey={req.get('horizon_session_key')!r}; "
                                f"horizon_key_match={horizon_key_match}; "
                                f"HorizonPad={req.get('horizon_padding', b'').hex(' ').upper()}; "
                                f"Policy={req['policy_type']} ({policy_name}); "
                                f"HorizonPolicy={req.get('horizon_policy_type')}; "
                                f"opaque_len={len(req['opaque'])}; extra={len(req.get('extra', b''))}",
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
                                if bool(cfg.get("protocol_lock_proven_layouts", True)) and policy_connection_mode == "pad_before_287" and len(response_plain) != 287:
                                    raise AssertionError(f"0x48 protocol lock violated: expected 287 bytes, got {len(response_plain)}")
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
                                log_event(cfg, "MAS-POLICY-TX-SCERT", "RT_MSG_SERVER_APP chiffré envoyé (MediusGetPolicyResponse 0x48 V036)", response_frame)
                                policy_answered = True
                                policy_answered_time = time.time()
                                log_event(cfg, "V037-PROTOCOL-LOCK", "0x48 accepted-layout lock active: pad_before_287 / 287-byte response; post-policy deep capture armed")
                            else:
                                log_event(cfg, "MAS-POLICY-SKIP", "Réponse Policy 0x47/0x48 désactivée dans config.json")
                        except Exception as e:
                            log_event(cfg, "MAS-POLICY-ERROR", f"Impossible d'analyser/répondre au MediusGetPolicyRequest 0x47: {e}", plain)
                        continue

                    # V043: documented MediusAccountLoginRequest/Response transition.
                    # EyeToy reaches this only after the policy/TLS stage.  Successful
                    # login redirects the client to the dedicated MLS capture listener.
                    if (nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_ACCOUNT_LOGIN_REQUEST
                            and bool(cfg.get("mas_account_login_enabled", True))):
                        try:
                            req = parse_account_login_request(plain)
                            session_key = req["session_key"] or str(cfg.get("mas_session_key", "ETC0000000000001"))
                            username = req["username"]
                            pass_effective = req["password_raw"].split(b"\x00", 1)[0]
                            mls_endpoint = cfg.get("_runtime_advertise_ip") or local_ipv4()
                            mls_port = int(cfg.get("mls_exact_port", 10078))
                            nat_endpoint = str(cfg.get("nat_endpoint", "auto") or "auto")
                            if nat_endpoint.strip().lower() == "auto":
                                nat_endpoint = mls_endpoint
                            nat_port = int(cfg.get("nat_port", 10070))
                            access_key = str(cfg.get("mas_access_key", "ETCACCESS0000001"))
                            if bool(cfg.get("v075_social_enabled", True)):
                                social_rec = v075_register_account(cfg, username)
                                account_id = int(social_rec["account_id"])
                            else:
                                account_id = int(cfg.get("mas_account_id", 1))
                            profile = v064_chatroom_profile(cfg)
                            login_world_id = profile["account_login_world_id"]
                            connect_world_id = profile["connect_world_id"]
                            log_event(
                                cfg, "MAS-ACCOUNT-LOGIN-REQ",
                                f"MediusAccountLoginRequest 0x07: MessageID=[{req['message_id'].hex(' ').upper()}]; "
                                f"SessionKey={session_key!r}; Username={username!r}; "
                                f"PasswordLen={len(pass_effective)}; PasswordSHA1={hashlib.sha1(pass_effective).hexdigest()}; "
                                f"extra={len(req['extra'])}", plain
                            )
                            response_plain = make_account_login_response(
                                req["message_id"], mls_endpoint, mls_port, session_key, access_key,
                                account_id=account_id, account_type=MEDIUS_ACCOUNT_MASTER,
                                medius_world_id=login_world_id, status_code=0,
                                nat_endpoint=nat_endpoint, nat_port=nat_port,
                                connect_world_id=connect_world_id
                            )
                            response_frame = scert_make_encrypted(10, response_plain, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(response_frame)
                            account_login_answered = True
                            log_event(
                                cfg, "MAS-ACCOUNT-LOGIN-TX",
                                f"MediusAccountLoginResponse 0x08 SUCCESS envoyé; AccountID={account_id}; "
                                f"AccountType=Master(1); MediusWorldID={login_world_id}; "
                                f"ConnectInfo.WorldID={connect_world_id}; "
                                f"profile={profile['name']}; Channel={profile['channel_name']!r}; "
                                f"ConnectInfo={mls_endpoint}:{mls_port}; NAT={nat_endpoint}:{nat_port}; "
                                f"SessionKey={session_key!r}; AccessKey={access_key!r}; len={len(response_plain)}",
                                response_plain
                            )
                            log_event(cfg, "MAS-ACCOUNT-LOGIN-TX-SCERT",
                                      "RT_MSG_SERVER_APP chiffré envoyé (MediusAccountLoginResponse 0x08)", response_frame)
                            with V044_LOGIN_STATE_LOCK:
                                V044_LOGIN_STATE[addr[0]] = {
                                    "username": req["username"], "account_id": account_id,
                                    "session_key": req["session_key"], "access_key": access_key,
                                    "application_id": application_id,
                                    "account_login_world_id": login_world_id,
                                    "connect_world_id": connect_world_id,
                                    "channel_world_id": profile["channel_world_id"],
                                    "chatroom_profile": profile["name"],
                                }
                            if bool(cfg.get("v075_social_enabled", True)):
                                v075_update_account(cfg, account_id, last_ip=addr[0], application_id=int(application_id or 10554))
                            log_event(cfg, "V044-LOGIN-STATE",
                                      f"state MLS mémorisé pour {addr[0]}: AccountID={account_id}; Username={req['username']!r}; AppId={application_id}")
                            log_event(cfg, "V043-NEXT-STAGE",
                                      f"Account login accepted; attente d'une connexion MLS vers {mls_endpoint}:{mls_port}")
                            save_post_policy_capture(cfg, addr, response_frame, response_plain, 10,
                                                     MEDIUS_CLASS_LOBBY, MEDIUS_ACCOUNT_LOGIN_RESPONSE)
                        except Exception as e:
                            log_event(cfg, "MAS-ACCOUNT-LOGIN-ERROR", f"Impossible de répondre au 0x07: {e}", plain)
                        continue

                    if not first_app_seen:
                        first_app_seen = True
                        log_event(cfg, "MAS-NEXT", f"Premier message Medius MAS inattendu: class={nc} type={mt}", plain)
                    elif policy_answered:
                        post_policy_app_count += 1
                        age = max(0.0, time.time() - (policy_answered_time or time.time()))
                        log_event(cfg, "MAS-NEXT", f"NOUVEAU message Medius capturé après MediusGetPolicyResponse 0x48 V036: class={nc} type={mt}; post48_app_index={post_policy_app_count}; age={age:.3f}s", plain)
                        save_post_policy_capture(cfg, addr, frame, plain, rt_id, nc, mt)
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
                    if policy_answered:
                        post_policy_non_echo_count += 1
                        age = max(0.0, time.time() - (policy_answered_time or time.time()))
                        log_event(cfg, "V037-POST-POLICY-SCERT", f"index={post_policy_non_echo_count}; age={age:.3f}s; {name}; id={rt_id}; decrypt_ok={ok}", frame)
                        save_post_policy_capture(cfg, addr, frame, plain, rt_id)
                    if ok:
                        log_event(cfg, "MAS-NEXT", f"Message SCERT suivant capturé: {name} (id={rt_id})")
                    else:
                        log_event(cfg, "MAS-NEXT", f"Message SCERT suivant reçu mais non déchiffré: {name} ctx={ctx}")
    except Exception as e:
        log_event(cfg, "ERROR", f"MAS V037 {addr}: {e}")
    finally:
        if buffer:
            log_event(cfg, "MAS-TAIL", f"Données SCERT incomplètes restantes: {len(buffer)} octets", buffer)
        try:
            conn.close()
        except OSError:
            pass

def handle_mls_v043(conn, addr, cfg):
    """Minimal dedicated Medius Lobby Server listener for the stage after 0x08.

    It completes the same legacy PS2 SCERT crypto/connect handshake, echoes keep-
    alives, and captures every decrypted Medius application message.  No guessed
    lobby application replies are emitted yet: the first retail request becomes
    the next protocol target instead of being hidden by a fabricated response.
    """
    conn.settimeout(4.0)
    port = int(cfg.get("mls_exact_port", 10078))
    log_event(cfg, "MLS-CONNECT", f"Connexion TCP MLS acceptée depuis {addr[0]}:{addr[1]} -> {port}; capture post-login V043")
    buffer = b""
    rc_key = None
    peer_sent = False
    connect_accepted = False
    application_id = None
    v059_lobby_filter = None
    # MLS is a persistent lobby connection.  Treat this as an inactivity
    # timeout and refresh it whenever the console sends bytes; the former
    # absolute 300-second lifetime cut a healthy session while ECHOs continued.
    capture_timeout = float(cfg.get("mls_capture_timeout", 300.0))
    deadline = time.time() + capture_timeout
    disconnect_reason = "handler_completed"
    frame_count = 0
    v075_account_id = None
    try:
        while time.time() < deadline:
            frames, buffer = scert_extract_frames(buffer)
            if not frames:
                try:
                    data = conn.recv(8192)
                except socket.timeout:
                    continue
                if not data:
                    disconnect_reason = "peer_closed"
                    break
                deadline = time.time() + capture_timeout
                buffer += data
                log_event(cfg, "MLS-RX", f"{len(data)} octets reçus depuis {addr[0]}:{addr[1]}", data)
                frames, buffer = scert_extract_frames(buffer)

            for frame in frames:
                frame_count += 1
                rt_id, encrypted, ctx, h, plain, ok = scert_decode_frame(frame, rc_key)
                name = RT_NAMES.get(rt_id, f"RT_MSG_{rt_id}")
                log_event(cfg, "MLS-FRAME", f"#{frame_count} {name} id={rt_id} encrypted={encrypted} ctx={ctx} len={struct.unpack_from('<H', frame, 1)[0]} decrypt_ok={ok}", frame)
                if plain is not None:
                    log_event(cfg, "MLS-PLAIN", f"#{frame_count} {name} plaintext {len(plain)} octets", plain)

                if rt_id == 18 and encrypted and ok and plain is not None and not peer_sent:
                    client_modulus = int.from_bytes(plain, "little", signed=False)
                    log_scert_rsa_identity(cfg, "MLS", client_modulus, "RT_MSG_CLIENT_CRYPTKEY_PUBLIC modulus")
                    rc_key = os.urandom(64)
                    cipher, rhash = rsa_auth_encrypt_for_client(rc_key, client_modulus)
                    reply = bytes([0x80 | 19]) + struct.pack("<H", 64) + rhash + cipher
                    conn.sendall(reply)
                    peer_sent = True
                    log_scert_crypto_state(cfg, "MLS", "after_rsa_peer_key", rc_key, plain=plain, frame=reply)
                    log_event(cfg, "MLS-TX", "RT_MSG_SERVER_CRYPTKEY_PEER envoyé (id=19, RSA_AUTH)", reply)
                    continue

                if rt_id == 0 and peer_sent and ok and plain is not None and not connect_accepted:
                    try:
                        world_id, unk0, application_id, client_key, extra = parse_client_connect_tcp_old(plain)
                        log_event(cfg, "MLS-CONNECT-PARSED",
                                  f"CLIENT_CONNECT_TCP old-layout: TargetWorldId={world_id} (0x{world_id:08X}), "
                                  f"UNK0=0x{unk0:02X}, AppId={application_id}, key64={len(client_key)}, extra={len(extra)}", plain)
                        ch = v059_default_channel(cfg, application_id)
                        log_event(cfg, "V059-DEFAULT-CHANNEL-REGISTER",
                                  f"logical channel registered for CLIENT AppId={application_id}: "
                                  f"Name={ch['name']!r}; WorldID={ch['world_id']}; Type=Lobby; "
                                  f"MaxPlayers={ch['max_players']}; Security={ch['security_level']}; "
                                  f"GF1={ch['generic_field1']}; GF2={ch['generic_field2']}; "
                                  f"GF3={ch['generic_field3']}; GF4={ch['generic_field4']}; "
                                  f"GFLevel={ch['generic_field_level']}; LobbyFilterMaskLevel={ch.get('lobby_filter_mask_level', 1)}; appid_mode=client_reported")
                    except Exception as e:
                        log_event(cfg, "MLS-CONNECT-PARSE-FAIL", str(e), plain)
                    ip = cfg.get("_runtime_advertise_ip") or local_ipv4()
                    accept_plain, accept_frame = make_server_connect_accept_tcp_old(ip, rc_key, player_id=1, player_count=1)
                    conn.sendall(accept_frame)
                    complete_plain, complete_frame = make_server_connect_complete(rc_key, arg1=1)
                    conn.sendall(complete_frame)
                    connect_accepted = True
                    if bool(cfg.get("v075_social_enabled", True)):
                        st = v075_login_state_for_ip(addr[0])
                        v075_account_id = int(st.get("account_id", 0) or 0)
                        if v075_account_id:
                            v075_register_active_session(cfg, v075_account_id, conn, rc_key, addr[0], application_id)
                    log_event(cfg, "MLS-TX", f"SERVER_CONNECT_ACCEPT_TCP + CONNECT_COMPLETE envoyés; AppId={application_id}", accept_frame + complete_frame)
                    log_event(cfg, "V043-MLS-STAGE", "SCERT MLS connecté; attente du premier message Medius lobby post-login")
                    continue

                if rt_id == 33 and connect_accepted and ok:
                    complete_plain, complete_frame = make_server_connect_complete(rc_key, arg1=1)
                    conn.sendall(complete_frame)
                    log_event(cfg, "MLS-TX", "CLIENT_CONNECT_READY_TCP reçu -> SERVER_CONNECT_COMPLETE renvoyé", complete_frame)
                    continue

                if rt_id == 5 and connect_accepted and ok and plain is not None:
                    echo = scert_make_encrypted(5, plain, rc_key, CTX_RC_CLIENT_SESSION)
                    conn.sendall(echo)
                    log_event(cfg, "MLS-ECHO", "RT_MSG_CLIENT_ECHO reçu et renvoyé", echo)
                    continue

                if rt_id == 11 and connect_accepted and ok and plain is not None:
                    nc = plain[0] if len(plain) >= 1 else None
                    mt = plain[1] if len(plain) >= 2 else None
                    if bool(cfg.get("v081_gameworld_watch_enabled", True)) and nc is not None and mt is not None:
                        try:
                            v081_gameworld_probe(cfg, nc, mt, plain, v075_account_id)
                        except Exception as e:
                            log_event(cfg, "V081-GAMEWORLD-WATCH-ERROR", f"class=0x{nc:02X}; type=0x{mt:02X}; {e}", plain)
                    save_muis_plain(cfg, "mls_app", addr, plain)
                    log_event(cfg, "MLS-APP",
                              f"PREMIER/PROCHAIN message Medius lobby capturé: class={nc}; type={mt}; "
                              f"AppId={application_id}; len={len(plain)}", plain)
                    try:
                        rawdir = ROOT / cfg.get("log_dir", "logs") / "post_login_mls"
                        rawdir.mkdir(parents=True, exist_ok=True)
                        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                        fp = rawdir / f"mls_c{int(nc):02X}_t{int(mt):02X}_{addr[0].replace('.', '_')}_{stamp}.bin"
                        fp.write_bytes(plain)
                        log_event(cfg, "V043-MLS-SAVE", f"payload MLS sauvegardé: {fp.relative_to(ROOT)}; sha256={hashlib.sha256(plain).hexdigest()}")
                    except Exception as e:
                        log_event(cfg, "V043-MLS-SAVE-ERROR", str(e))

                    # V058 primary target: after a successfully accepted hierarchy the retail
                    # client should start its hard-coded default channel Holding / world 1000.
                    # That transition is Lobby/0x25 MediusJoinChannel, not LobbyExt/0x12.
                    if (nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_JOIN_CHANNEL
                            and bool(cfg.get("v059_join_channel_enabled", cfg.get("v058_join_channel_enabled", True)))):
                        try:
                            req = parse_join_channel_request(plain)
                            with V044_LOGIN_STATE_LOCK:
                                st = dict(V044_LOGIN_STATE.get(addr[0], {}))
                            session_key = req["session_key"] or st.get("session_key") or str(cfg.get("mas_session_key", "ETC0000000000001"))
                            access_key = st.get("access_key") or str(cfg.get("mas_access_key", "ETCACCESS0000001"))
                            endpoint = cfg.get("_runtime_advertise_ip") or local_ipv4()
                            port = int(cfg.get("mls_exact_port", 10078))
                            nat_endpoint = str(cfg.get("nat_endpoint", "auto") or "auto")
                            if nat_endpoint.strip().lower() == "auto":
                                nat_endpoint = endpoint
                            nat_port = int(cfg.get("nat_port", 10070))
                            channel = v059_default_channel(cfg, application_id, req["world_id"])
                            expected_world = int(channel["world_id"])
                            default_name = str(channel["name"])
                            response_world, status_code, world_match = v064_join_channel_decision(
                                channel, req["world_id"]
                            )
                            log_event(cfg, "V059-MLS-JOIN-CHANNEL-REQ",
                                      f"Lobby/0x25 JoinChannel reçu; WorldID={req['world_id']}; "
                                      f"expected_default={default_name!r}/{expected_world}; bound_AppId={channel['application_id']}; "
                                      f"world_match={world_match}; decision={'SUCCESS' if world_match else 'MediusFail'}; "
                                      f"SessionKey={session_key!r}; Password={req['password']!r}; "
                                      f"pad={req['pad'].hex()}; extra={len(req['extra'])}; "
                                      f"{v059_filter_diagnostic(channel, v059_lobby_filter)}", plain)
                            resp = make_join_channel_response(
                                req["message_id"], endpoint, port, response_world,
                                session_key, access_key, status_code=status_code,
                                nat_endpoint=nat_endpoint, nat_port=nat_port
                            )
                            frame_out = scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(frame_out)
                            if world_match and v075_account_id and bool(cfg.get("v075_social_enabled", True)):
                                v075_update_account(cfg, v075_account_id, online=True,
                                                    lobby_world_id=int(response_world), lobby_name=default_name)
                                v081_set_active_room(cfg, v075_account_id, int(response_world), default_name)
                            log_event(cfg, "V059-MLS-JOIN-CHANNEL-TX",
                                      f"Lobby/0x26 JoinChannelResponse {'SUCCESS' if world_match else 'FAIL'} envoyé; "
                                      f"RequestedWorldID={req['world_id']}; ResponseWorldID={response_world}; Status={status_code}; "
                                      f"ConnectInfo={endpoint}:{port}; NAT={nat_endpoint}:{nat_port}; "
                                      f"len={len(resp)}; next_expected=reconnect_or_next_MLS_stage", resp)
                        except Exception as e:
                            log_event(cfg, "V059-MLS-JOIN-CHANNEL-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY_EXT and mt == MEDIUS_GET_BUDDY_INVITATIONS:
                        try:
                            req = parse_get_buddy_invitations_request(plain)
                            invites = v075_invitation_records(cfg, v075_account_id) if v075_account_id else []
                            if invites:
                                for i, inv in enumerate(invites):
                                    resp = make_get_buddy_invitations_response(req["message_id"], 0, inv["account_id"], inv["name"],
                                                                              MEDIUS_BUDDY_ADD_SYMMETRIC, i == len(invites)-1)
                                    conn.sendall(scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION))
                                desc=f"SUCCESS count={len(invites)}"
                            else:
                                resp = make_get_buddy_invitations_response(req["message_id"])
                                conn.sendall(scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)); desc="NO_RESULT"
                            log_event(cfg, "V075-SOCIAL-BUDDY-INVITES", f"AccountID={v075_account_id}; {desc}", plain)
                        except Exception as e:
                            log_event(cfg, "V075-SOCIAL-BUDDY-INVITES-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_GET_IGNORE_LIST:
                        try:
                            req=v076_parse_ignore_list_request(plain); rows=v076_ignore_records(cfg,v075_account_id) if v075_account_id else []
                            if rows:
                                for i,rec in enumerate(rows):
                                    resp=v076_make_ignore_list_response(req["message_id"],rec,0,i==len(rows)-1)
                                    conn.sendall(scert_make_encrypted(10,resp,rc_key,CTX_RC_CLIENT_SESSION))
                                desc=f"SUCCESS count={len(rows)}"
                            else:
                                resp=v076_make_ignore_list_response(req["message_id"]); conn.sendall(scert_make_encrypted(10,resp,rc_key,CTX_RC_CLIENT_SESSION)); desc="NO_RESULT"
                            log_event(cfg,"V076-BLOCK-LIST",f"AccountID={v075_account_id}; {desc}",plain)
                        except Exception as e: log_event(cfg,"V076-BLOCK-LIST-ERROR",str(e),plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt in (MEDIUS_ADD_TO_IGNORE_LIST, MEDIUS_REMOVE_FROM_IGNORE_LIST):
                        try:
                            req=_v075_parse_account_target_request(plain,mt); adding=(mt==MEDIUS_ADD_TO_IGNORE_LIST)
                            okop=bool(v075_account_id) and v076_set_ignored(cfg,v075_account_id,req["account_id"],adding)
                            rtype=MEDIUS_ADD_TO_IGNORE_LIST_RESPONSE if adding else MEDIUS_REMOVE_FROM_IGNORE_LIST_RESPONSE
                            resp=_v075_make_status_response(req["message_id"],rtype,0 if okop else -966)
                            conn.sendall(scert_make_encrypted(10,resp,rc_key,CTX_RC_CLIENT_SESSION))
                            log_event(cfg,"V076-BLOCK-ADD" if adding else "V076-BLOCK-REMOVE",f"from={v075_account_id}; target={req['account_id']}; success={int(okop)}",plain)
                        except Exception as e: log_event(cfg,"V076-BLOCK-CHANGE-ERROR",str(e),plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY_EXT and mt == MEDIUS_BINARY_MESSAGE:
                        try:
                            req=v076_parse_binary_message(plain); probe=v076_save_binary_probe(cfg,v075_account_id,req["target_id"],req["message_type"],req["message"])
                            fwd=v076_make_binary_fwd(req["message_id"],v075_account_id or 0,req["message_type"],req["message"])
                            route_world=0
                            if req["message_type"] == MEDIUS_BINARY_TARGET:
                                targets=[req["target_id"]]
                                route_scope="target"
                            elif req["message_type"] == MEDIUS_BINARY_BROADCAST:
                                targets, route_world = v081_targets_in_room(v075_account_id)
                                route_scope="channel"
                            elif req["message_type"] == MEDIUS_BINARY_UNIVERSE:
                                with V075_ACTIVE_LOCK: targets=list(V075_ACTIVE_SESSIONS.keys())
                                route_scope="universe"
                            else:
                                targets=[]
                                route_scope="unknown"
                            sent=blocked=0
                            for target in targets:
                                if int(target)==int(v075_account_id or -1) and req["message_type"]!=MEDIUS_BINARY_TARGET: continue
                                if not v076_delivery_allowed(cfg,v075_account_id,target): blocked+=1; continue
                                if v075_send_to_account(cfg,target,fwd): sent+=1
                            marker = b"ETChatPhotosMediusGame" in req["message"]
                            log_event(cfg,"V081-BINARY-RX",f"from={v075_account_id}; type={req['message_type']}; target={req['target_id']}; scope={route_scope}; WorldID={route_world}; relayed={sent}; blocked={blocked}; marker_ETChatPhotosMediusGame={int(marker)}; saved={probe.relative_to(ROOT)}",plain)
                        except Exception as e: log_event(cfg,"V076-BINARY-ERROR",str(e),plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY_EXT and mt == MEDIUS_FRIEND_CONFIRM_EXT:
                        try:
                            req=v076_parse_friend_confirm_probe(plain)
                            accepted=False
                            if bool(cfg.get("v076_friend_confirmation_apply_without_reply", False)) and v075_account_id:
                                # AddType 1 is AddSymmetric; target field names differ between public implementations,
                                # so this is deliberately opt-in until a live EyeToy packet is captured.
                                accepted=v076_accept_friendship(cfg,v075_account_id,req["target_account_id"],req["add_type"]==1)
                            log_event(cfg,"V076-FRIEND-CONFIRM-PROBE",f"AccountID={v075_account_id}; target={req['target_account_id']}; add_type={req['add_type']}; applied={int(accepted)}; no_reply=1",plain)
                        except Exception as e: log_event(cfg,"V076-FRIEND-CONFIRM-ERROR",str(e),plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_GET_BUDDY_LIST_EXTRA_INFO:
                        try:
                            req = parse_get_buddy_list_extra_info_request(plain)
                            buddies = v075_buddy_records(cfg, v075_account_id) if v075_account_id else []
                            if not buddies:
                                resp = make_get_buddy_list_extra_info_response(req["message_id"])
                                conn.sendall(scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)); desc="NO_RESULT"
                            else:
                                for i, buddy in enumerate(buddies):
                                    online=bool(buddy.get("online",False))
                                    resp=make_get_buddy_list_extra_info_response(
                                        req["message_id"], 0, buddy["account_id"], buddy["name"], i==len(buddies)-1,
                                        2 if online else 0, int(buddy.get("lobby_world_id",0) if online else 0), 0,
                                        str(buddy.get("lobby_name","") if online else ""), "")
                                    conn.sendall(scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION))
                                desc=f"SUCCESS count={len(buddies)}"
                            log_event(cfg, "V075-SOCIAL-BUDDY-LIST", f"AccountID={v075_account_id}; {desc}", plain)
                        except Exception as e:
                            log_event(cfg, "V075-SOCIAL-BUDDY-LIST-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_FIND_PLAYER:
                        try:
                            req=v075_parse_find_player_request(plain)
                            rec=(v075_account_by_id(cfg,req["account_id"]) if req["search_type"]==MEDIUS_PLAYER_SEARCH_ACCOUNT_ID
                                 else v075_account_by_name(cfg,req["name"]))
                            resp=v075_make_find_player_response(req["message_id"],rec,0 if rec else 1,True)
                            conn.sendall(scert_make_encrypted(10,resp,rc_key,CTX_RC_CLIENT_SESSION))
                            log_event(cfg,"V075-SOCIAL-FIND",f"from={v075_account_id}; type={req['search_type']}; id={req['account_id']}; name={req['name']!r}; found={bool(rec)}",plain)
                        except Exception as e: log_event(cfg,"V075-SOCIAL-FIND-ERROR",str(e),plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt in (MEDIUS_ADD_TO_BUDDY_LIST, MEDIUS_REMOVE_FROM_BUDDY_LIST):
                        try:
                            req=_v075_parse_account_target_request(plain,mt)
                            if mt==MEDIUS_ADD_TO_BUDDY_LIST:
                                mode=str(cfg.get("v076_friendship_mode","symmetric_legacy")).lower()
                                if mode in ("request","request_capture"):
                                    okop=bool(v075_account_id) and v076_request_friendship(cfg,v075_account_id,req["account_id"])
                                    op="REQUEST"
                                else:
                                    okop=bool(v075_account_id) and v075_add_buddy_symmetric(cfg,v075_account_id,req["account_id"])
                                    op="ADD"
                                rtype=MEDIUS_ADD_TO_BUDDY_LIST_RESPONSE
                            else:
                                okop=bool(v075_account_id) and v075_remove_buddy_symmetric(cfg,v075_account_id,req["account_id"])
                                rtype=MEDIUS_REMOVE_FROM_BUDDY_LIST_RESPONSE; op="REMOVE"
                            resp=_v075_make_status_response(req["message_id"],rtype,0 if okop else -966)
                            conn.sendall(scert_make_encrypted(10,resp,rc_key,CTX_RC_CLIENT_SESSION))
                            log_event(cfg,"V075-SOCIAL-BUDDY-"+op,f"from={v075_account_id}; target={req['account_id']}; success={int(okop)}",plain)
                        except Exception as e: log_event(cfg,"V075-SOCIAL-BUDDY-CHANGE-ERROR",str(e),plain)
                        continue

                    if ((nc==MEDIUS_CLASS_LOBBY and mt==MEDIUS_CHAT_MESSAGE) or
                        (nc==MEDIUS_CLASS_LOBBY_EXT and mt==MEDIUS_GENERIC_CHAT_MESSAGE)):
                        try:
                            req=v075_parse_chat_message(plain,nc,mt)
                            me=v075_account_by_id(cfg,v075_account_id) if v075_account_id else None
                            origin_name=(me or {}).get("name","EyeToyUser")
                            fwd_class=MEDIUS_CLASS_LOBBY if nc==MEDIUS_CLASS_LOBBY else MEDIUS_CLASS_LOBBY_EXT
                            fwd_type=MEDIUS_CHAT_FWD_MESSAGE if nc==MEDIUS_CLASS_LOBBY else MEDIUS_GENERIC_CHAT_FWD_MESSAGE
                            fwd=v075_make_chat_fwd(fwd_class,fwd_type,v075_account_id or 0,origin_name,req["message_type"],req["message"])
                            targets=[]; route_world=0
                            if req["message_type"] in (MEDIUS_CHAT_WHISPER,MEDIUS_CHAT_BUDDY):
                                targets=[req["target_id"]]; route_scope="target"
                            elif req["message_type"] == MEDIUS_CHAT_UNIVERSE:
                                with V075_ACTIVE_LOCK: targets=list(V075_ACTIVE_SESSIONS.keys())
                                route_scope="universe"
                            else:
                                targets, route_world = v081_targets_in_room(v075_account_id)
                                route_scope="channel"
                            sent=blocked=0
                            for target in targets:
                                if not v076_delivery_allowed(cfg,v075_account_id,target): blocked+=1; continue
                                if v075_send_to_account(cfg,target,fwd): sent+=1
                            log_event(cfg,"V081-SOCIAL-CHAT-RX",f"from={v075_account_id}; type={req['message_type']}; target={req['target_id']}; scope={route_scope}; WorldID={route_world}; text={req['message']!r}; relayed={sent}; blocked={blocked}",plain)
                        except Exception as e: log_event(cfg,"V075-SOCIAL-CHAT-ERROR",str(e),plain)
                        continue

                    # V058: retain SetLobbyWorldFilter support if the client chooses that path
                    # immediately with the documented 0x13 success layout.  Echo every
                    # filter field from the real client request rather than guessing.
                    if nc == MEDIUS_CLASS_LOBBY_EXT and mt in (MEDIUS_SET_LOBBY_WORLD_FILTER, MEDIUS_SET_LOBBY_WORLD_FILTER1):
                        try:
                            req = parse_set_lobby_world_filter_request(plain, mt)
                            v059_lobby_filter = dict(req)
                            channel = v059_default_channel(cfg, application_id)
                            log_event(cfg, "V059-MLS-SET-LOBBY-FILTER-REQ",
                                      f"LobbyExt/0x{mt:02X} SetLobbyWorldFilter{'1' if mt == MEDIUS_SET_LOBBY_WORLD_FILTER1 else ''} reçu; "
                                      f"mask1={req['filter_mask1']}; mask2={req['filter_mask2']}; "
                                      f"mask3={req['filter_mask3']}; mask4={req['filter_mask4']}; "
                                      f"type={req['filter_type']}; level={req['filter_level']}; "
                                      f"pad={req['pad'].hex()}; extra={len(req['extra'])}", plain)
                            response_type = (MEDIUS_SET_LOBBY_WORLD_FILTER1_RESPONSE if mt == MEDIUS_SET_LOBBY_WORLD_FILTER1 else MEDIUS_SET_LOBBY_WORLD_FILTER_RESPONSE)
                            resp = make_set_lobby_world_filter_response(req, status_code=0, response_type=response_type)
                            frame_out = scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(frame_out)
                            log_event(cfg, "V059-MLS-SET-LOBBY-FILTER-TX",
                                      f"LobbyExt/0x{response_type:02X} SUCCESS envoyé; len={len(resp)}; "
                                      f"mask1={req['filter_mask1']}; type={req['filter_type']}; "
                                      f"level={req['filter_level']}; next_expected=capture_next_MLS_message", resp)
                        except Exception as e:
                            log_event(cfg, "V059-MLS-SET-LOBBY-FILTER-ERROR", str(e), plain)
                        continue

                    # V064 fix: ChannelList_ExtraInfo belongs to the post-login
                    # Lobby Server connection.  The old block lived in MAS, where
                    # EyeToy never sends this discovery request.
                    if (nc == MEDIUS_CLASS_LOBBY_EXT and mt in (MEDIUS_CHANNEL_LIST_EXTRA_INFO1, MEDIUS_CHANNEL_LIST_EXTRA_INFO)
                            and bool(cfg.get("v059_channel_list_extra_info_enabled", True))):
                        try:
                            req = parse_channel_list_extra_info_request(plain, mt)
                            channel = v059_default_channel(cfg, application_id)
                            diag = v059_filter_diagnostic(channel, v059_lobby_filter)
                            page_channel, page_status, has_result = v064_channel_list_page(
                                channel, req["page_id"], req["page_size"]
                            )
                            log_event(cfg, "V064-MLS-CHANNEL-LIST-EXTRA-REQ",
                                      f"LobbyExt/0x{mt:02X} ChannelList_ExtraInfo reçu; PageID={req['page_id']}; "
                                      f"PageSize={req['page_size']}; client_AppId={application_id}; "
                                      f"has_result={has_result}; status={page_status}; "
                                      f"current_filter={diag}; pad={req['pad'].hex()}; extra={len(req['extra'])}", plain)
                            resp = make_channel_list_extra_info_response(
                                req["message_id"], page_channel,
                                status_code=page_status, end_of_list=True
                            )
                            frame_out = scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(frame_out)
                            log_event(cfg, "V064-MLS-CHANNEL-LIST-EXTRA-TX",
                                      f"Lobby/0xED ChannelList_ExtraInfoResponse envoyé; has_result={has_result}; "
                                      f"Name={page_channel['name']!r}; WorldID={page_channel['world_id']}; "
                                      f"AppId(binding)={channel['application_id']}; Status={page_status}; "
                                      f"Players={page_channel['player_count']}/{page_channel['max_players']}; "
                                      f"GF1={page_channel['generic_field1']}; GF2={page_channel['generic_field2']}; "
                                      f"GF3={page_channel['generic_field3']}; GF4={page_channel['generic_field4']}; "
                                      f"GFLevel={page_channel['generic_field_level']}; len={len(resp)}", resp)
                        except Exception as e:
                            log_event(cfg, "V064-MLS-CHANNEL-LIST-EXTRA-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_VERSION_SERVER_REQUEST:
                        try:
                            req = parse_version_server_request(plain)
                            version_string = str(cfg.get("mls_version_string", "Medius Lobby Server Version 1.51.0001"))
                            resp = make_version_server_response(req["message_id"], version_string)
                            frame_out = scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(frame_out)
                            log_event(cfg, "V046-MLS-VERSION-REQ",
                                      f"VersionServer 0x86: SessionKey={req['session_key']!r}; extra={len(req['extra'])}", plain)
                            log_event(cfg, "V046-MLS-VERSION-TX",
                                      f"VersionServerResponse 0x87 envoyé; version={version_string!r}; len={len(resp)}", resp)
                        except Exception as e:
                            log_event(cfg, "V046-MLS-VERSION-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_CHANNEL_INFO:
                        try:
                            req = parse_channel_info_request(plain)
                            channel = v059_default_channel(cfg, application_id, req["world_id"])
                            lobby_name = channel["name"]
                            active_players = int(cfg.get("mls_active_player_count", 1))
                            max_players = int(cfg.get("mls_max_players", 32))
                            resp = make_channel_info_response(req["message_id"], lobby_name,
                                                              active_players=active_players,
                                                              max_players=max_players)
                            frame_out = scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(frame_out)
                            log_event(cfg, "V047-MLS-CHANNEL-INFO-REQ",
                                      f"ChannelInfo 0x35: WorldID={req['world_id']}; "
                                      f"selected_world={channel['world_id']}; "
                                      f"world_match={req['world_id'] == channel['world_id']}; "
                                      f"SessionKey={req['session_key']!r}; pad={req['pad'].hex()}", plain)
                            log_event(cfg, "V047-MLS-CHANNEL-INFO-TX",
                                      f"ChannelInfoResponse 0x36 SUCCESS envoyé; LobbyName={lobby_name!r}; Active={active_players}; Max={max_players}; len={len(resp)}", resp)
                        except Exception as e:
                            log_event(cfg, "V047-MLS-CHANNEL-INFO-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_GET_ANNOUNCEMENTS:
                        try:
                            req = parse_get_announcements_request(plain)
                            announcement = str(cfg.get("mls_announcement_text", "Welcome to EyeToy Chat Europe"))
                            announcement_id = int(cfg.get("mls_announcement_id", 1))
                            resp = make_get_announcements_response(
                                req["message_id"], announcement,
                                announcement_id=announcement_id,
                                end_of_list=True, status_code=0
                            )
                            frame_out = scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(frame_out)
                            log_event(cfg, "V048-MLS-ANNOUNCEMENTS-REQ",
                                      f"GetAnnouncements 0x4B: AppId={req['application_id']}; SessionKey={req['session_key']!r}; pad={req['pad'].hex()}", plain)
                            log_event(cfg, "V048-MLS-ANNOUNCEMENTS-TX",
                                      f"GetAnnouncementsResponse 0x4D SUCCESS envoyé; AnnouncementID={announcement_id}; EndOfList=1; text_len={len(announcement.encode('utf-8', errors='replace'))}; len={len(resp)}", resp)
                        except Exception as e:
                            log_event(cfg, "V048-MLS-ANNOUNCEMENTS-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_UPDATE_USER_STATE:
                        try:
                            u = parse_update_user_state(plain)
                            action_names = {0: "KeepAlive", 1: "JoinedChatWorld", 2: "LeftGameWorld"}
                            if v075_account_id and bool(cfg.get("v075_social_enabled", True)):
                                profile=v064_chatroom_profile(cfg)
                                current=v075_account_by_id(cfg, v075_account_id) or {}
                                current_world=int(current.get("lobby_world_id", 0) or profile.get("channel_world_id",1))
                                selected=v086_room_by_world(cfg, current_world)
                                current_name=(selected or {}).get("title") or current.get("lobby_name") or profile.get("channel_name","Default")
                                v075_update_account(cfg,v075_account_id,online=True,
                                                    lobby_world_id=current_world,
                                                    lobby_name=current_name)
                                v081_set_active_room(cfg, v075_account_id, current_world, current_name)
                            log_event(cfg, "V044-MLS-UPDATE-USER-STATE",
                                      f"SessionKey={u['session_key']!r}; UserAction={u['user_action']} ({action_names.get(u['user_action'],'unknown')}); pad={u['pad'].hex()}")
                        except Exception as e:
                            log_event(cfg, "V044-MLS-UPDATE-USER-STATE-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_PLAYER_INFO:
                        try:
                            req = parse_player_info_request(plain)
                            with V044_LOGIN_STATE_LOCK:
                                st = dict(V044_LOGIN_STATE.get(addr[0], {}))
                            social_target = v075_account_by_id(cfg, req["account_id"]) if bool(cfg.get("v075_social_enabled", True)) else None
                            account_name = (social_target or {}).get("name", st.get("username", "EyeToyUser"))
                            app_id = int((social_target or {}).get("application_id", st.get("application_id", application_id or 10554)))
                            player_status = 2 if (social_target or {}).get("online", True) else 0
                            try:
                                social_stats = bytes.fromhex(str((social_target or {}).get("stats_hex", ""))) or None
                            except ValueError:
                                social_stats = None
                            resp = make_player_info_response(req["message_id"], account_name, application_id=app_id,
                                                             player_status=player_status, stats=social_stats)
                            frame_out = scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(frame_out)
                            log_event(cfg, "V044-MLS-PLAYER-INFO-REQ",
                                      f"AccountID={req['account_id']}; SessionKey={req['session_key']!r}; pad={req['pad'].hex()}", plain)
                            log_event(cfg, "V044-MLS-PLAYER-INFO-TX",
                                      f"PlayerInfoResponse 0x32 SUCCESS envoyé; AccountName={account_name!r}; AppId={app_id}; PlayerStatus=InChatWorld(2); ConnectionClass=Ethernet(1); len={len(resp)}", resp)
                        except Exception as e:
                            log_event(cfg, "V044-MLS-PLAYER-INFO-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_ACCOUNT_UPDATE_STATS:
                        try:
                            req = parse_account_update_stats_request(plain)
                            resp = make_account_update_stats_response(req["message_id"], 0)
                            frame_out = scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(frame_out)
                            if v075_account_id and bool(cfg.get("v075_social_enabled", True)):
                                v075_update_account(cfg, v075_account_id, stats_hex=req["stats"].hex())
                            stats_prefix = req["stats"][:32].split(b"\x00", 1)[0].decode("ascii", errors="replace")
                            log_event(cfg, "V068-MLS-ACCOUNT-UPDATE-STATS-REQ",
                                      f"AccountUpdateStats 0x11: SessionKey={req['session_key']!r}; "
                                      f"stats_len={len(req['stats'])}; stats_sha256={hashlib.sha256(req['stats']).hexdigest()}; "
                                      f"ascii_prefix={stats_prefix!r}; extra={len(req['extra'])}", plain)
                            log_event(cfg, "V068-MLS-ACCOUNT-UPDATE-STATS-TX",
                                      f"AccountUpdateStatsResponse 0x12 SUCCESS envoyé; MessageID={_decode_medius_string(req['message_id'])!r}; len={len(resp)}", resp)
                        except Exception as e:
                            log_event(cfg, "V068-MLS-ACCOUNT-UPDATE-STATS-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_ACCOUNT_LOGOUT:
                        try:
                            req = parse_account_logout_request(plain)
                            resp = make_account_logout_response(req["message_id"], 0)
                            frame_out = scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(frame_out)
                            if v075_account_id and bool(cfg.get("v075_social_enabled", True)):
                                v075_set_online(cfg, v075_account_id, False)
                            log_event(cfg, "V049-MLS-ACCOUNT-LOGOUT-REQ",
                                      f"AccountLogout 0x15: SessionKey={req['session_key']!r}; extra={len(req['extra'])}", plain)
                            log_event(cfg, "V049-MLS-ACCOUNT-LOGOUT-TX",
                                      f"AccountLogoutResponse 0x16 SUCCESS envoyé; len={len(resp)}", resp)
                        except Exception as e:
                            log_event(cfg, "V049-MLS-ACCOUNT-LOGOUT-ERROR", str(e), plain)
                        continue

                    if nc == MEDIUS_CLASS_LOBBY and mt == MEDIUS_SESSION_END:
                        try:
                            req = parse_session_end_request(plain)
                            resp = make_session_end_response(req["message_id"], 0)
                            frame_out = scert_make_encrypted(10, resp, rc_key, CTX_RC_CLIENT_SESSION)
                            conn.sendall(frame_out)
                            log_event(cfg, "V044-MLS-SESSION-END-TX",
                                      f"SessionEndResponse 0x06 SUCCESS envoyé; SessionKey={req['session_key']!r}; len={len(resp)}", resp)
                        except Exception as e:
                            log_event(cfg, "V044-MLS-SESSION-END-ERROR", str(e), plain)
                        continue

                    continue

                if peer_sent and rt_id not in (18, 0, 33, 5, 11):
                    log_event(cfg, "MLS-NEXT", f"Message SCERT non géré: {name} id={rt_id}; decrypt_ok={ok}", frame)
        if disconnect_reason == "handler_completed" and time.time() >= deadline:
            disconnect_reason = "idle_timeout"
            log_event(cfg, "MLS-IDLE-TIMEOUT",
                      f"Fermeture après {capture_timeout:.1f}s sans aucune donnée de {addr[0]}:{addr[1]}")
    except Exception as e:
        disconnect_reason = f"error:{type(e).__name__}"
        log_event(cfg, "ERROR", f"MLS V043 {addr}: {e}")
    finally:
        if bool(cfg.get("v075_social_enabled", True)):
            v075_unregister_active_session(cfg, v075_account_id, conn)
        if buffer:
            log_event(cfg, "MLS-TAIL", f"Données SCERT incomplètes restantes: {len(buffer)} octets", buffer)
        try:
            conn.close()
        except OSError:
            pass
        log_event(cfg, "MLS-DISCONNECT",
                  f"Connexion MLS fermée; client={addr[0]}:{addr[1]}; reason={disconnect_reason}; "
                  f"frames={frame_count}; idle_timeout={capture_timeout:.1f}s")


class MLSListener(threading.Thread):
    def __init__(self, cfg):
        super().__init__(name="MLS-Dedicated")
        self.cfg = cfg
        self.port = int(cfg.get("mls_exact_port", 10078))
        self.daemon = True

    def run(self):
        bind_ip = self.cfg.get("bind_ip", "0.0.0.0")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((bind_ip, self.port))
            s.listen(16)
        except OSError as e:
            log_event(self.cfg, "ERROR", f"MLS TCP {self.port} impossible: {e}")
            return
        log_event(self.cfg, "MLS-LISTEN", f"listener MLS dédié actif sur {bind_ip}:{self.port} (V043)")
        while True:
            try:
                conn, addr = s.accept()
            except OSError as e:
                log_event(self.cfg, "ERROR", f"MLS accept: {e}")
                time.sleep(1)
                continue
            threading.Thread(target=handle_mls_v043, args=(conn, addr, self.cfg),
                             name=f"MLS-{addr[0]}:{addr[1]}", daemon=True).start()


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
        log_event(self.cfg, "MAS-LISTEN", f"listener MAS dédié actif sur {bind_ip}:{self.port} (V037)")
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
        if self.port == int(self.cfg.get("http_port", -1)) or self.port in set(map(int, self.cfg.get("http_plain_ports", []))):
            bind_ip = self.cfg.get("http_bind_ip", self.cfg.get("bind_ip", "0.0.0.0"))
        else:
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


def v045_make_nat_probe_response(addr_ip: str, addr_port: int) -> bytes:
    """Medius NAT probe reply: external IPv4 (4 bytes) + UDP port (u16 BE)."""
    return socket.inet_aton(addr_ip) + struct.pack(">H", int(addr_port) & 0xFFFF)


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
                # V045: implement the small Medius NAT reflector used on UDP/10070.
                # Horizon's NAT service replies to 4-byte probes (except subtype 0xD4)
                # with the sender's observed IPv4 address followed by its UDP port.
                nat_port = int(self.cfg.get("nat_port", 10070))
                if (bool(self.cfg.get("v045_nat_probe_reply", True)) and self.port == nat_port
                        and len(data) == 4 and data[3] != 0xD4):
                    try:
                        reply = v045_make_nat_probe_response(addr[0], addr[1])
                        s.sendto(reply, addr)
                        log_event(self.cfg, "V045-NAT-TX",
                                  f"reply -> {addr[0]}:{addr[1]}; observed={addr[0]}:{addr[1]}; len={len(reply)}", reply)
                    except Exception as e:
                        log_event(self.cfg, "V045-NAT-ERROR", f"{addr}: {e}")
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
        "index.txt": "EyeToy Chat Community Server V086 - DNAS21 Timeless Rooms\n",
        "chatroom_hierarchy_1_51.xml": "<chatrooms ban_time=\"0\" heading=\"lang\" vmail_inbox_size=\"20\"><menu heading=\"type\" title=\"English\" icon=\"0\"><chatroom title=\"Default\" icon=\"0\" type=\"TEXT256\" id=\"1\"/></menu><chatroom_welcome1>Welcome to EyeToy Chat</chatroom_welcome1><welcome1 version=\"1\">Welcome to EyeToy Chat</welcome1><chatroom_welcome2>Welcome to EyeToy Chat</chatroom_welcome2><welcome2 version=\"1\">Welcome to EyeToy Chat</welcome2><chatroom_welcome3>Welcome to EyeToy Chat</chatroom_welcome3><welcome3 version=\"1\">Welcome to EyeToy Chat</welcome3><chatroom_welcome4>Welcome to EyeToy Chat</chatroom_welcome4><welcome4 version=\"1\">Welcome to EyeToy Chat</welcome4><chatroom_welcome5>Welcome to EyeToy Chat</chatroom_welcome5><welcome5 version=\"1\">Welcome to EyeToy Chat</welcome5><chatroom_welcome6>Welcome to EyeToy Chat</chatroom_welcome6><welcome6 version=\"1\">Welcome to EyeToy Chat</welcome6><chatroom_welcome7>Welcome to EyeToy Chat</chatroom_welcome7><welcome7 version=\"1\">Welcome to EyeToy Chat</welcome7><chatroom_welcome8>Welcome to EyeToy Chat</chatroom_welcome8><welcome8 version=\"1\">Welcome to EyeToy Chat</welcome8><chatroom_welcome9>Welcome to EyeToy Chat</chatroom_welcome9><welcome9 version=\"1\">Welcome to EyeToy Chat</welcome9><chatroom_welcome10>Welcome to EyeToy Chat</chatroom_welcome10><welcome10 version=\"1\">Welcome to EyeToy Chat</welcome10><chatroom_welcome11>Welcome to EyeToy Chat</chatroom_welcome11><welcome11 version=\"1\">Welcome to EyeToy Chat</welcome11></chatrooms>",
        "announcements/announcements.0.txt": "Welcome to EyeToy Chat Europe\r\n",
        "announcements/announcements.2.txt": "Welcome to EyeToy Chat Europe\r\n",
        "policies/policy.0.txt": "EyeToy Chat local server test policy\n",
        "policies/policy.2.txt": "EyeToy Chat Community Server Usage Policy\r\n\r\nUse the service respectfully.\r\nDo not send abusive, illegal, explicit, or disruptive content.\r\nBy continuing, you agree to follow the community server rules.\r\n"
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

    # The HTTP dispatcher serves a dynamic hierarchy.  Keep the on-disk copy in
    # sync so manual inspection never shows a stale, different experiment.
    hierarchy = HTTP_ROOT / "chatroom_hierarchy_1_51.xml"
    inspection_mode = str(cfg.get("v060_chatroom_probe_mode", "v066_required_callback_fields")).strip()
    if not inspection_mode or inspection_mode.lower() == "auto":
        inspection_mode = _v060_probe_modes(cfg)[0]
    hierarchy.write_bytes(build_chatroom_hierarchy_v060(cfg, inspection_mode))


def selftest(cfg, advertise_ip):
    cfg = dict(cfg)
    cfg["v075_social_state_file"] = "_selftest_social_state.json"
    _self_state = v075_social_state_path(cfg)
    try:
        if _self_state.exists(): _self_state.unlink()
    except OSError:
        pass
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
    req_policy = b"GET /policies/policy.2.txt HTTP/1.0\r\nHost: eyetoychat-update.online.scee.com\r\n\r\n"
    http_p, path_p, body_p = http_response_for(req_policy, cfg)
    assert path_p == "/policies/policy.2.txt" and b"HTTP/1.0 200 OK" in http_p and body_p
    # V065: validate both complete profiles with the retail-read menu metadata.
    # Every consumer must use the
    # selected values without reintroducing hard-coded WorldID/title drift.
    import xml.etree.ElementTree as _ET
    for _profile_name in V064_CHATROOM_PROFILES:
        _pcfg = dict(cfg)
        _pcfg["v064_chatroom_profile"] = _profile_name
        _profile = v064_chatroom_profile(_pcfg)
        _body = build_chatroom_hierarchy_v060(_pcfg, "v065_full_menu_profile")
        assert _body and not _body.startswith(b"<?xml")
        _root = _ET.fromstring(_body.decode("iso-8859-1"))
        _menu = _root.find("./menu")
        _room = _menu.find("./chatroom") if _menu is not None else None
        assert _root.tag == "chatrooms" and _root.attrib == {"ban_time": "0", "heading": "lang"}
        assert _menu is not None and _menu.attrib == {
            "heading": "type",
            "title": str(_pcfg.get("chatroom_language_title", "English")),
            "icon": "0",
        }
        assert _room is not None
        assert _room.attrib.get("title") == _profile["room_title"]
        assert _room.attrib.get("id") == str(_profile["room_id"])
        assert _room.attrib.get("type") == "TEXT256"
        _channel = v059_default_channel(_pcfg, 424242)
        assert _channel["world_id"] == _profile["channel_world_id"]
        assert _channel["name"] == _profile["channel_name"]
        assert _channel["generic_field1"] == _profile["generic_field1"]
        _login_mid = bytes(range(MESSAGEID_MAXLEN))
        _login = make_account_login_response(
            _login_mid, advertise_ip, int(cfg.get("mls_exact_port", 10078)),
            "ETC0000000000001", "ETCACCESS0000001",
            medius_world_id=_profile["account_login_world_id"], nat_endpoint=advertise_ip,
            nat_port=int(cfg.get("nat_port", 10070)),
            connect_world_id=_profile["connect_world_id"]
        )
        assert struct.unpack_from("<i", _login, 38)[0] == _profile["account_login_world_id"]
        assert struct.unpack_from("<i", _login, 42 + 4 + (24 * 2))[0] == _profile["connect_world_id"]

    _escape_cfg = dict(cfg)
    _escape_cfg["chatroom_language_title"] = "A & B"
    _escape_root = _ET.fromstring(
        build_chatroom_hierarchy_v060(_escape_cfg, "v065_full_menu_profile")
        .decode("iso-8859-1")
    )
    assert _escape_root.find("./menu").attrib["title"] == "A & B"

    # Prove that V064 models distinct wire concepts rather than accidentally
    # relying on the equal numbers used by the two built-in hypotheses.
    _dcfg = dict(cfg)
    _dcfg["v064_chatroom_profile"] = "medius_default_1"
    _dcfg["v064_chatroom_profiles"] = {
        "medius_default_1": {
            "room_title": "XML only", "room_id": 700,
            "channel_name": "Medius only",
            "account_login_world_id": 11, "connect_world_id": 22,
            "channel_world_id": 33, "generic_field1": 44,
            "generic_field_level": 1, "lobby_filter_mask_level": 1,
        }
    }
    _distinct = v064_chatroom_profile(_dcfg)
    assert len({_distinct["room_id"], _distinct["account_login_world_id"],
                _distinct["connect_world_id"], _distinct["channel_world_id"],
                _distinct["generic_field1"]}) == 5
    _dbody = build_chatroom_hierarchy_v060(_dcfg, "v065_full_menu_profile")
    _droom = _ET.fromstring(_dbody.decode("iso-8859-1")).find("./menu/chatroom")
    assert _droom is not None and _droom.attrib["id"] == "700" and _droom.attrib["title"] == "XML only"
    _dchannel = v059_default_channel(_dcfg, 10554)
    assert _dchannel["world_id"] == 33 and _dchannel["generic_field1"] == 44
    _dlogin = make_account_login_response(
        bytes(range(MESSAGEID_MAXLEN)), advertise_ip, int(cfg.get("mls_exact_port", 10078)),
        "ETC0000000000001", "ETCACCESS0000001", medius_world_id=11,
        nat_endpoint=advertise_ip, nat_port=int(cfg.get("nat_port", 10070)),
        connect_world_id=22
    )
    assert struct.unpack_from("<i", _dlogin, 38)[0] == 11
    assert struct.unpack_from("<i", _dlogin, 42 + 4 + (24 * 2))[0] == 22
    safe_print("[SELFTEST] V065 XML/menu/login/connect/channel/GF1 remain independent fields: OK")
    test_cfg = dict(cfg)
    test_cfg["v060_chatroom_probe_mode"] = "v065_full_menu_profile"
    hreq = (b"GET /chatroom_hierarchy_1_51.xml HTTP/1.0\r\n"
            b"HOST: eyetoychat-update.online.scee.com\r\n\r\n")
    hresp, hpath, hbody = http_response_for(hreq, test_cfg)
    assert hpath == "/chatroom_hierarchy_1_51.xml"
    assert hresp.startswith(b"HTTP/1.0 200 OK\r\n")
    hroot = _ET.fromstring(hbody.decode("iso-8859-1"))
    assert hroot.tag == "chatrooms"
    hmenus = hroot.findall("./menu")
    assert len(hmenus) == 1
    htype = hmenus[0]
    hroom = htype.find("./chatroom")
    assert hroom is not None
    assert hroot.attrib.get("ban_time") == "0"
    assert hroot.attrib.get("heading") == "lang"
    assert htype.attrib.get("heading") == "type"
    assert htype.attrib.get("title") == str(test_cfg.get("chatroom_language_title", "English"))
    assert htype.attrib.get("icon") == "0"
    active_profile = v064_chatroom_profile(test_cfg)
    assert hroom.attrib.get("title") == active_profile["room_title"]
    assert hroom.attrib.get("type") == "TEXT256"
    assert hroom.attrib.get("id") == str(active_profile["room_id"])
    safe_print("[SELFTEST] V065 full retail menu metadata + coherent profiles + no XML declaration: OK")
    # V066: the retail HTTP completion callback requires three extra metadata
    # gates before it invokes the main chatroom/menu parser.  These were absent
    # from every V060-V065 candidate.
    _v66cfg = dict(cfg)
    _v66cfg["v060_chatroom_probe_mode"] = "v066_required_callback_fields"
    _v66body = build_chatroom_hierarchy_v060(_v66cfg, "v066_required_callback_fields")
    _v66root = _ET.fromstring(_v66body.decode("iso-8859-1"))
    assert _v66root.attrib.get("vmail_inbox_size") == str(int(_v66cfg.get("chatroom_vmail_inbox_size", 20)))
    _lang_idx = int(_v66cfg.get("chatroom_language_index", 2))
    _crw = _v66root.find(f"./chatroom_welcome{_lang_idx}")
    _wel = _v66root.find(f"./welcome{_lang_idx}")
    assert _crw is not None and (_crw.text or "") == str(_v66cfg.get("chatroom_room_welcome_text", "Welcome to EyeToy Chat"))
    assert _wel is not None and _wel.attrib.get("version") == str(int(_v66cfg.get("chatroom_welcome_version", 1)))
    assert (_wel.text or "") == str(_v66cfg.get("chatroom_welcome_text", "Welcome to EyeToy Chat"))
    assert _v66root.find("./menu/chatroom") is not None
    safe_print("[SELFTEST] V066 mandatory hierarchy callback fields: OK")
    # V077: every PAL UI language must find its localized callback nodes.
    _v77cfg = dict(cfg)
    _v77cfg["v077_pal_multilang_callbacks"] = True
    _v77body = build_chatroom_hierarchy_v060(_v77cfg, "v066_required_callback_fields")
    _v77root = _ET.fromstring(_v77body.decode("iso-8859-1"))
    for _idx in range(1, 12):
        assert _v77root.find(f"./chatroom_welcome{_idx}") is not None
        _w = _v77root.find(f"./welcome{_idx}")
        assert _w is not None and _w.attrib.get("version") == str(int(_v77cfg.get("chatroom_welcome_version", 1)))
    # Numeric policy/announcement resources are served for every locale index
    # through the existing fallback logic, even if no dedicated file exists.
    for _idx in range(1, 12):
        _p = f"GET /policies/policy.{_idx}.txt HTTP/1.0\r\nHost: eyetoychat-update.online.scee.com\r\n\r\n".encode("ascii")
        _a = f"GET /announcements/announcements.{_idx}.txt HTTP/1.0\r\nHost: eyetoychat-update.online.scee.com\r\n\r\n".encode("ascii")
        _ph, _pp, _pb = http_response_for(_p, _v77cfg)
        _ah, _ap, _ab = http_response_for(_a, _v77cfg)
        assert _ph.startswith(b"HTTP/1.0 200 OK") and _pb
        assert _ah.startswith(b"HTTP/1.0 200 OK") and _ab
    safe_print("[SELFTEST] V077 PAL multilang callbacks + policy/announcements 1..11: OK")

    _v86body = build_chatroom_hierarchy_v060(cfg, "v086_multilingual_text_rooms")
    _v86root = _ET.fromstring(_v86body.decode("iso-8859-1"))
    assert _v86root.attrib.get("heading") == "lang"
    _v86langs = _v86root.findall("./menu")
    assert [node.attrib.get("title") for node in _v86langs] == ["Francais", "English"]
    _v86leaves = []
    for _language in _v86langs:
        _categories = _language.findall("./menu")
        assert [node.attrib.get("title") for node in _categories] == ["General", "Sport"]
        for _category in _categories:
            _leaf = _category.find("./chatroom")
            assert _leaf is not None and _leaf.attrib.get("type") == "TEXT256"
            _v86leaves.append(_leaf)
    assert [int(node.attrib["id"]) for node in _v86leaves] == [1, 2, 3, 4]
    for _world in range(1, 5):
        _selected = v059_default_channel(cfg, 10554, _world)
        assert _selected["world_id"] == _world
        _target, _status, _matched = v064_join_channel_decision(_selected, _world)
        assert _matched and _status == 0 and _target == _world
    safe_print("[SELFTEST] V086 Francais/English -> General/Sport -> TEXT256 WorldID 1..4: OK")

    # V067: capture-confirmed next request after V066. Retail expects a normal
    # HTTP success and application/octet-stream for ProfileRetrieve.
    _pr_req = (
        b"GET /mt/servlet/ProfileRetrieve HTTP/1.0\r\n"
        b"profileVersion: 2\r\n"
        b"userid: 1\r\n"
        b"profileUserID: 1\r\n"
        b"private: 0\r\n"
        b"HOST: vmail.online.scee.com\r\n\r\n"
    )
    _pr_resp, _pr_path, _pr_body = http_response_for(_pr_req, cfg)
    assert _pr_path == "/mt/servlet/ProfileRetrieve"
    assert _pr_resp.startswith(b"HTTP/1.0 200 OK\r\n")
    assert b"Content-Type: application/octet-stream\r\n" in _pr_resp
    assert b"Content-Length: 0\r\n" in _pr_resp
    assert _pr_body == b""
    safe_print("[SELFTEST] V067 ProfileRetrieve -> HTTP 200 application/octet-stream, empty profile probe: OK")

    # V068: V067 capture-confirmed next MLS request after both public/private
    # ProfileRetrieve probes is Lobby/0x11 AccountUpdateStats, exactly 296 bytes.
    _aus_mid = medius_fixed_string("122", MESSAGEID_MAXLEN)
    _aus_key = medius_fixed_string("ETC0000000000001", NET_SESSION_KEY_LEN)
    _aus_stats = b"1,0,1,0,0\x00" + bytes(ACCOUNTSTATS_MAXLEN - len(b"1,0,1,0,0\x00"))
    _aus_req_raw = bytes([MEDIUS_CLASS_LOBBY, MEDIUS_ACCOUNT_UPDATE_STATS]) + _aus_mid + _aus_key + _aus_stats
    assert len(_aus_req_raw) == 296
    _aus_req = parse_account_update_stats_request(_aus_req_raw)
    assert _aus_req["session_key"] == "ETC0000000000001"
    assert len(_aus_req["stats"]) == 256 and _aus_req["stats"].startswith(b"1,0,1,0,0\x00")
    assert not _aus_req["extra"]
    _aus_resp = make_account_update_stats_response(_aus_req["message_id"], 0)
    assert len(_aus_resp) == 30
    assert _aus_resp[:2] == bytes([MEDIUS_CLASS_LOBBY, MEDIUS_ACCOUNT_UPDATE_STATS_RESPONSE])
    assert _aus_resp[2:23] == _aus_mid
    assert struct.unpack_from("<i", _aus_resp, 26)[0] == 0
    safe_print("[SELFTEST] V068 Lobby/0x11 AccountUpdateStats -> 0x12 SUCCESS: OK")

    # V069: V068 capture-confirmed next request is LobbyExt/0x08 GetBuddyInvitations.
    _bi_mid = medius_fixed_string("29", MESSAGEID_MAXLEN)
    _bi_req_raw = bytes([MEDIUS_CLASS_LOBBY_EXT, MEDIUS_GET_BUDDY_INVITATIONS]) + _bi_mid
    assert len(_bi_req_raw) == 23
    _bi_req = parse_get_buddy_invitations_request(_bi_req_raw)
    assert _bi_req["message_id"] == _bi_mid and not _bi_req["extra"]
    _bi_resp = make_get_buddy_invitations_response(_bi_mid)
    assert len(_bi_resp) == 74
    assert _bi_resp[:2] == bytes([MEDIUS_CLASS_LOBBY_EXT, MEDIUS_GET_BUDDY_INVITATIONS_RESPONSE])
    assert _bi_resp[2:23] == _bi_mid
    assert struct.unpack_from("<i", _bi_resp, 26)[0] == 1  # MediusNoResult
    assert struct.unpack_from("<i", _bi_resp, 30)[0] == 0  # AccountID
    assert _bi_resp[34:66] == bytes(32)
    assert struct.unpack_from("<i", _bi_resp, 66)[0] == 1  # ADD_SYMMETRIC
    assert _bi_resp[70] == 1  # EndOfList
    safe_print("[SELFTEST] V069 LobbyExt/0x08 GetBuddyInvitations -> 0x09 NO_RESULT EndOfList: OK")

    # V070 live-proven empty inbox XML: client polls it periodically instead of looping immediately.
    _mi_req_raw = (
        b"GET /mt/servlet/MailInbox HTTP/1.0\r\n"
        b"version: 1\r\nuserid: 1\r\nusername: test\r\npassword: test\r\n"
        b"Content-Type: application/octet-stream\r\nHOST: vmail.online.scee.com\r\n\r\n"
    )
    _mi_resp, _mi_path, _mi_body = http_response_for(_mi_req_raw, cfg)
    assert _mi_path == "/mt/servlet/MailInbox"
    assert _mi_resp.startswith(b"HTTP/1.0 200 OK\r\n")
    assert b"Content-Type: text/xml\r\n" in _mi_resp
    assert _mi_body.endswith(b"<inbox/>\n")
    safe_print("[SELFTEST] V070 MailInbox -> HTTP 200 text/xml empty inbox: OK")

    # V071: ProfilePost must get a clean success response after its binary body is read.
    _pp_req_raw = (
        b"POST /mt/servlet/ProfilePost HTTP/1.0\r\n"
        b"profileVersion: 2\r\nuserid: 1\r\nusername: test\r\npassword: test\r\nprivate: 1\r\n"
        b"Content-Type: application/octet-stream\r\nHOST: vmail.online.scee.com\r\n"
        b"Content-Length: 252\r\n\r\n" + bytes(252)
    )
    _pp_resp, _pp_path, _pp_body = http_response_for(_pp_req_raw, cfg)
    assert _pp_path == "/mt/servlet/ProfilePost"
    assert _pp_resp.startswith(b"HTTP/1.0 200 OK\r\n")
    assert b"Content-Type: application/octet-stream\r\n" in _pp_resp
    assert b"Content-Length: 0\r\n" in _pp_resp
    assert _pp_body == b""
    _pp_get = (b"GET /mt/servlet/ProfileRetrieve HTTP/1.0\r\n"
               b"profileVersion: 2\r\nusername: test\r\nprivate: 1\r\n"
               b"HOST: vmail.online.scee.com\r\n\r\n")
    _pp_get_resp, _pp_get_path, _pp_get_body = http_response_for(_pp_get, cfg)
    assert _pp_get_path == "/mt/servlet/ProfileRetrieve" and len(_pp_get_body) == 252
    assert b"Content-Length: 252\r\n" in _pp_get_resp
    safe_print("[SELFTEST] V075 ProfilePost/ProfileRetrieve persistent binary round-trip: OK")

    assert int(cfg.get("universe_status", -1)) == 2
    safe_print("[SELFTEST] V073 MUIS Universe Status=2 restore: OK")

    # V070 MLS: captured Lobby/0xD6 GetBuddyList_ExtraInfo, 23-byte request.
    _bl_mid = medius_fixed_string("17", MESSAGEID_MAXLEN)
    _bl_req_raw = bytes([MEDIUS_CLASS_LOBBY, MEDIUS_GET_BUDDY_LIST_EXTRA_INFO]) + _bl_mid
    assert len(_bl_req_raw) == 23
    _bl_req = parse_get_buddy_list_extra_info_request(_bl_req_raw)
    assert _bl_req["message_id"] == _bl_mid and not _bl_req["extra"]
    _bl_resp = make_get_buddy_list_extra_info_response(_bl_mid)
    assert len(_bl_resp) == 210
    assert _bl_resp[:2] == bytes([MEDIUS_CLASS_LOBBY, MEDIUS_GET_BUDDY_LIST_EXTRA_INFO_RESPONSE])
    assert _bl_resp[2:23] == _bl_mid
    assert struct.unpack_from("<i", _bl_resp, 26)[0] == 1  # MediusNoResult
    assert struct.unpack_from("<i", _bl_resp, 30)[0] == 0  # AccountID
    assert _bl_resp[34:66] == bytes(32)
    assert _bl_resp[66:206] == bytes(140)  # empty/disconnected OnlineState
    assert _bl_resp[206] == 1
    safe_print("[SELFTEST] V070 Lobby/0xD6 GetBuddyList_ExtraInfo -> 0xD7 NO_RESULT EndOfList: OK")

    # V075 persistent social foundation: stable accounts, search, buddy add/remove,
    # online presence serialization, profile round-trip and both text-chat wire forms.
    _alice = v075_register_account(cfg, "Alice")
    _bob = v075_register_account(cfg, "Bob")
    assert _alice["account_id"] != _bob["account_id"]
    assert v075_register_account(cfg, "ALICE")["account_id"] == _alice["account_id"]
    _find_mid = medius_fixed_string("find1", MESSAGEID_MAXLEN)
    _find_req = (bytes([MEDIUS_CLASS_LOBBY, MEDIUS_FIND_PLAYER]) + _find_mid +
                 medius_fixed_string("ETC0000000000001", NET_SESSION_KEY_LEN) + b"\x00\x00" +
                 struct.pack("<ii", MEDIUS_PLAYER_SEARCH_ACCOUNT_NAME, 0) + medius_fixed_string("Bob", 32))
    _find = v075_parse_find_player_request(_find_req)
    assert _find["name"] == "Bob" and _find["search_type"] == MEDIUS_PLAYER_SEARCH_ACCOUNT_NAME
    _find_resp = v075_make_find_player_response(_find_mid, v075_account_by_name(cfg, "bob"), 0, True)
    assert _find_resp[:2] == bytes([MEDIUS_CLASS_LOBBY, MEDIUS_FIND_PLAYER_RESPONSE])
    assert struct.unpack_from("<i", _find_resp, 74)[0] == _bob["account_id"]
    assert v075_add_buddy_symmetric(cfg, _alice["account_id"], _bob["account_id"])
    assert _bob["account_id"] in [r["account_id"] for r in v075_buddy_records(cfg, _alice["account_id"])]
    v075_set_online(cfg, _bob["account_id"], True, "127.0.0.1", 10554, 1, "Default")
    _buddy_online = make_get_buddy_list_extra_info_response(
        _bl_mid, 0, _bob["account_id"], "Bob", True, 2, 1, 0, "Default", "")
    assert struct.unpack_from("<i", _buddy_online, 66)[0] == 2
    assert struct.unpack_from("<i", _buddy_online, 70)[0] == 1
    assert v075_remove_buddy_symmetric(cfg, _alice["account_id"], _bob["account_id"])
    assert not v075_buddy_records(cfg, _alice["account_id"])
    _profile_blob = b"PROFILE-V075-ROUNDTRIP"
    v075_store_profile(cfg, "Alice", False, _profile_blob)
    assert v075_load_profile(cfg, "alice", False) == _profile_blob
    _chat_mid = medius_fixed_string("chat1", MESSAGEID_MAXLEN)
    for _chat_class, _chat_type, _fwd_type in ((MEDIUS_CLASS_LOBBY, MEDIUS_CHAT_MESSAGE, MEDIUS_CHAT_FWD_MESSAGE),
                                               (MEDIUS_CLASS_LOBBY_EXT, MEDIUS_GENERIC_CHAT_MESSAGE, MEDIUS_GENERIC_CHAT_FWD_MESSAGE)):
        _chat_req = (bytes([_chat_class, _chat_type]) + _chat_mid +
                     medius_fixed_string("ETC0000000000001", NET_SESSION_KEY_LEN) + b"\x00\x00" +
                     struct.pack("<ii", MEDIUS_CHAT_BUDDY, _bob["account_id"]) + medius_fixed_string("hello", 64))
        _chat = v075_parse_chat_message(_chat_req, _chat_class, _chat_type)
        assert _chat["message"] == "hello" and _chat["target_id"] == _bob["account_id"]
        _fwd = v075_make_chat_fwd(_chat_class, _fwd_type, _alice["account_id"], "Alice", _chat["message_type"], _chat["message"])
        assert _fwd[:2] == bytes([_chat_class, _fwd_type]) and len(_fwd) == 110
    safe_print("[SELFTEST] V075 Social Foundation -> accounts/find/buddy/presence/profile/chat: OK")

    # V076 Night Research Integration: ignore/block, binary relay, friendship request state and VideoMail store.
    assert v076_set_ignored(cfg,_alice["account_id"],_bob["account_id"],True)
    assert v076_is_ignored(cfg,_alice["account_id"],_bob["account_id"])
    _ig_mid=medius_fixed_string("ignore1",MESSAGEID_MAXLEN)
    _ig_resp=v076_make_ignore_list_response(_ig_mid,_bob,0,True)
    assert len(_ig_resp)==74 and _ig_resp[:2]==bytes([MEDIUS_CLASS_LOBBY,MEDIUS_GET_IGNORE_LIST_RESPONSE])
    assert v076_set_ignored(cfg,_alice["account_id"],_bob["account_id"],False)
    assert not v076_is_ignored(cfg,_alice["account_id"],_bob["account_id"])
    assert v076_request_friendship(cfg,_alice["account_id"],_bob["account_id"])
    assert _alice["account_id"] in [r["account_id"] for r in v075_invitation_records(cfg,_bob["account_id"])]
    assert v076_accept_friendship(cfg,_bob["account_id"],_alice["account_id"],True)
    _bin_mid=medius_fixed_string("bin1",MESSAGEID_MAXLEN); _msg=b"ETChatPhotosMediusGame"+bytes(400-len(b"ETChatPhotosMediusGame"))
    _bin_req=(bytes([MEDIUS_CLASS_LOBBY_EXT,MEDIUS_BINARY_MESSAGE])+_bin_mid+medius_fixed_string("ETC0000000000001",17)+b"\x00\x00"+struct.pack("<ii",MEDIUS_BINARY_TARGET,_bob["account_id"])+_msg)
    _parsed=v076_parse_binary_message(_bin_req); assert _parsed["message"].startswith(b"ETChatPhotosMediusGame")
    _bf=v076_make_binary_fwd(_bin_mid,_alice["account_id"],MEDIUS_BINARY_TARGET,_parsed["message"])
    assert len(_bf)==434 and _bf[:2]==bytes([MEDIUS_CLASS_LOBBY_EXT,MEDIUS_BINARY_FWD_MESSAGE])
    _vm_req=(b"POST /mt/servlet/MailPost HTTP/1.0\r\nusername: Alice\r\nuserid: "+str(_alice["account_id"]).encode()+b"\r\nrecipient: "+str(_bob["account_id"]).encode()+b"\r\nsubject: test\r\nduration: 3\r\nContent-Type: application/octet-stream\r\nContent-Length: 8\r\n\r\nVIDEOMSG")
    _vm_resp,_vm_path,_vm_body=http_response_for(_vm_req,cfg); assert _vm_path=="/mt/servlet/MailPost" and _vm_resp.startswith(b"HTTP/1.0 200 OK")
    safe_print("[SELFTEST] V076 Night Research -> block/request/binary/VideoMail capture: OK")

    # V058: retain 0x12/0x13 compatibility, but JoinChannel 0x25 is now the primary target
    # serializer before any live PS2 traffic is touched.
    probe_mid = bytes(range(21))
    for request_type, response_type in (
            (MEDIUS_SET_LOBBY_WORLD_FILTER, MEDIUS_SET_LOBBY_WORLD_FILTER_RESPONSE),
            (MEDIUS_SET_LOBBY_WORLD_FILTER1, MEDIUS_SET_LOBBY_WORLD_FILTER1_RESPONSE)):
        probe_filter = (bytes([MEDIUS_CLASS_LOBBY_EXT, request_type]) + probe_mid + b"\x00\x00\x00" +
                        struct.pack("<IIIIii", active_profile["generic_field1"], 0, 0, 0, 0,
                                    active_profile["lobby_filter_mask_level"]))
        pf = parse_set_lobby_world_filter_request(probe_filter, request_type)
        assert len(probe_filter) == 50 and pf["filter_mask1"] == active_profile["generic_field1"]
        filter_resp = make_set_lobby_world_filter_response(
            pf, status_code=0, response_type=response_type
        )
        assert len(filter_resp) == 54
        assert filter_resp[:2] == bytes([MEDIUS_CLASS_LOBBY_EXT, response_type])
        assert filter_resp[2:23] == probe_mid and struct.unpack_from("<i", filter_resp, 26)[0] == 0
    safe_print("[SELFTEST] V064 LobbyExt 0x12/0x86 -> 0x13/0x87 filter serializers: OK")


    # V058: documented Lobby/0x25 JoinChannel -> 0x26 with NetConnectionInfo.
    join_mid = bytes((0x41 + i) & 0xff for i in range(MESSAGEID_MAXLEN))
    join_session = "ETC0000000000001"
    join_req = (bytes([MEDIUS_CLASS_LOBBY, MEDIUS_JOIN_CHANNEL]) + join_mid +
                medius_fixed_string(join_session, NET_SESSION_KEY_LEN) + b"\x00\x00" +
                struct.pack("<i", active_profile["channel_world_id"]) + medius_fixed_string("", LOBBYPASSWORD_MAXLEN))
    jr = parse_join_channel_request(join_req)
    assert len(join_req) == 78 and jr["world_id"] == active_profile["channel_world_id"] and jr["session_key"] == join_session
    join_resp = make_join_channel_response(join_mid, advertise_ip, int(cfg.get("mls_exact_port", 10078)),
                                           active_profile["channel_world_id"], join_session, "ETCACCESS0000001",
                                           nat_endpoint=advertise_ip, nat_port=int(cfg.get("nat_port", 10070)))
    assert join_resp[:2] == bytes([MEDIUS_CLASS_LOBBY, MEDIUS_JOIN_CHANNEL_RESPONSE])
    assert join_resp[2:23] == join_mid and struct.unpack_from("<i", join_resp, 26)[0] == 0
    # NetConnectionInfo begins at byte 30; type is ClientServerTCP and world id
    # follows two fixed NetAddress entries.
    assert struct.unpack_from("<i", join_resp, 30)[0] == NET_CONNECTION_CLIENT_SERVER_TCP
    assert struct.unpack_from("<i", join_resp, 30 + 4 + (24 * 2))[0] == active_profile["channel_world_id"]
    _target, _status, _match = v064_join_channel_decision(
        v059_default_channel(cfg, 424242), active_profile["channel_world_id"]
    )
    assert _match and _status == 0 and _target == active_profile["channel_world_id"]
    _wrong_world = active_profile["channel_world_id"] + 999
    _target, _status, _match = v064_join_channel_decision(
        v059_default_channel(cfg, 424242), _wrong_world
    )
    assert not _match and _status == MEDIUS_FAIL and _target == active_profile["channel_world_id"]
    safe_print("[SELFTEST] V064 JoinChannel request/response uses the active profile WorldID: OK")
    # V059: explicit default channel bound to the actual connected AppId and
    # ChannelList_ExtraInfo response carrying GenericField values.
    ch59 = v059_default_channel(cfg, 424242)
    assert ch59["application_id"] == 424242
    assert ch59["world_id"] == active_profile["channel_world_id"] and ch59["name"] == active_profile["channel_name"]
    cl_mid = medius_fixed_string("59", MESSAGEID_MAXLEN)
    cl_req = bytes([MEDIUS_CLASS_LOBBY_EXT, MEDIUS_CHANNEL_LIST_EXTRA_INFO]) + cl_mid + b"\x00" + struct.pack("<HH", 0, 10)
    clr = parse_channel_list_extra_info_request(cl_req)
    assert len(cl_req) == 28 and clr["page_id"] == 0 and clr["page_size"] == 10
    cl_resp = make_channel_list_extra_info_response(clr["message_id"], ch59, 0, True)
    assert len(cl_resp) == 130 and cl_resp[:2] == bytes([MEDIUS_CLASS_LOBBY, MEDIUS_CHANNEL_LIST_EXTRA_INFO_RESPONSE])
    assert struct.unpack_from("<i", cl_resp, 30)[0] == active_profile["channel_world_id"]
    assert struct.unpack_from("<I", cl_resp, 42)[0] == ch59["generic_field1"]
    assert cl_resp[-4] == 1
    _page0, _page0_status, _page0_has_result = v064_channel_list_page(ch59, 0, 10)
    assert _page0_has_result and _page0_status == 0 and _page0["world_id"] == ch59["world_id"]
    _page1, _page1_status, _page1_has_result = v064_channel_list_page(ch59, 1, 10)
    assert _page1_has_result and _page1_status == 0 and _page1["world_id"] == ch59["world_id"]
    _page2, _page2_status, _page2_has_result = v064_channel_list_page(ch59, 2, 10)
    assert not _page2_has_result and _page2_status == MEDIUS_NO_RESULT
    _page2_resp = make_channel_list_extra_info_response(clr["message_id"], _page2, _page2_status, True)
    assert struct.unpack_from("<i", _page2_resp, 26)[0] == MEDIUS_NO_RESULT
    assert struct.unpack_from("<i", _page2_resp, 30)[0] == 0
    _cl1_req = bytes([MEDIUS_CLASS_LOBBY_EXT, MEDIUS_CHANNEL_LIST_EXTRA_INFO1]) + cl_req[2:]
    _cl1 = parse_channel_list_extra_info_request(_cl1_req, MEDIUS_CHANNEL_LIST_EXTRA_INFO1)
    assert _cl1["page_id"] == clr["page_id"] and _cl1["page_size"] == clr["page_size"]
    safe_print("[SELFTEST] V075 ChannelList_ExtraInfo EyeToy 0x15 + alternate 0x1F -> 0xED: OK")

    # V052: exact HTTPS request captured from V051 after Product.Access=true.
    req_ann_http = (b"GET /announcements/announcements.2.txt HTTP/1.0\r\n"
                    b"Content-Type: application/octet-stream\r\n"
                    b"HOST: eyetoychat-update.online.scee.com\r\n"
                    b"Accept: */*;q=0.01\r\n"
                    b"Accept-Encoding: \r\n"
                    b"Accept-Charset: iso-8859-1;q=0.01\r\n"
                    b"User-Agent: SCEE HTTP Downloader 1.0\r\n\r\n")
    http_a, path_a, body_a = http_response_for(req_ann_http, cfg)
    assert path_a == "/announcements/announcements.2.txt"
    assert http_a.startswith(b"HTTP/1.0 200 OK\r\n") and body_a
    safe_print("[SELFTEST] V052 exact /announcements/announcements.2.txt -> HTTP 200: OK")
    safe_print("[SELFTEST] UPDATE XML -> <patches BUILD=\"194\"/>")
    safe_print("[SELFTEST] EyeToy DNS local -> " + advertise_ip)
    safe_print("[SELFTEST] DNAS = passthrough DNS communautaire; V086 conserve le HTTPS retail sur TCP/10443")
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
    ap, af = make_server_connect_accept_tcp_old("192.0.2.75", rc_key)
    cp, cf = make_server_connect_complete(rc_key)
    assert len(ap) == 23 and len(af) == 30 and ap[:7] == bytes.fromhex("01 08 10 00 00 01 00")
    assert ap[7:] == b"192.0.2.75".ljust(16, b"\x00")
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
    assert areq["character_encoding"] == 2 and areq["language"] == 8
    assert areq["horizon_layout_available"]
    assert areq["horizon_padding"] == b"\x00\x00"
    assert areq["horizon_character_encoding"] == 2
    assert areq["horizon_language"] == 8
    atype = int(cfg.get("mas_a3_response_type", MEDIUS_A3_PROBE_RESPONSE_DEFAULT))
    amode = str(cfg.get("mas_a3_response_mode", "mid_pad_status"))
    aresp = make_probe_status_response(1, atype, areq["message_id"], 0, amode)
    assert aresp[:2] == bytes([1, atype & 0xFF])
    af = scert_make_encrypted(10, aresp, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(af, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == aresp
    safe_print(f"[SELFTEST] V039 0xA3 Horizon comparison + compat 0x{atype:02X}: OK")

    captured_policy = bytes.fromhex(
        "01473600820100000000000000000000000045544330003030303030303030303031002d82010000000000000000"
    )
    preq = parse_policy_request(captured_policy)
    assert len(captured_policy) == 46
    assert len(preq["message_id"]) == MESSAGEID_MAXLEN
    assert len(preq["opaque"]) == 19
    assert preq["policy_type"] == 0
    assert preq["horizon_layout_available"]
    assert preq["horizon_padding"] == b"\x00\x00"
    assert preq["horizon_policy_type"] == 0
    policy_text, _ = load_policy_text(cfg, preq["policy_type"])
    expected_lengths = {
        "packed_284": 284,
        "pad_before_287": 287,
        "tail_pad_287": 287,
        "horizon_290": 290,
        "v021_290": 290,
    }
    for pmode in POLICY_RESPONSE_MODES:
        presp = make_policy_response(preq["message_id"], policy_text, 0, True, pmode)
        assert len(presp) == expected_lengths[pmode]
        pf = scert_make_encrypted(10, presp, rc_key, CTX_RC_CLIENT_SESSION)
        rid, enc, ctx, hh, pp, ok = scert_decode_frame(pf, rc_key)
        assert rid == 10 and enc and ctx == 3 and ok and pp == presp
    safe_print("[SELFTEST] V039 Policy 0x48 EyeToy 287 + Horizon 290 serializers: OK")

    # V043 documented AccountLoginRequest/Response + NetConnectionInfo transition.
    login_mid = bytes.fromhex("36 00 82 01") + b"\x00" * 17
    login_req = (bytes([MEDIUS_CLASS_LOBBY, MEDIUS_ACCOUNT_LOGIN_REQUEST]) + login_mid +
                 medius_fixed_string("ETC0000000000001", NET_SESSION_KEY_LEN) +
                 medius_fixed_string("testuser", ACCOUNTNAME_MAXLEN) +
                 medius_fixed_string("testpass", PASSWORD_MAXLEN))
    lreq = parse_account_login_request(login_req)
    assert lreq["session_key"] == "ETC0000000000001" and lreq["username"] == "testuser"
    lresp = make_account_login_response(
        lreq["message_id"], advertise_ip, int(cfg.get("mls_exact_port", 10078)),
        lreq["session_key"], str(cfg.get("mas_access_key", "ETCACCESS0000001")),
        account_id=int(cfg.get("mas_account_id", 1)),
        medius_world_id=active_profile["account_login_world_id"],
        nat_endpoint=advertise_ip, nat_port=int(cfg.get("nat_port", 10070)),
        connect_world_id=active_profile["connect_world_id"]
    )
    assert lresp[:2] == bytes([1, 8]) and lresp[2:23] == login_mid
    assert struct.unpack_from("<i", lresp, 26)[0] == 0
    assert struct.unpack_from("<i", lresp, 30)[0] == int(cfg.get("mas_account_id", 1))
    # 196 bytes is Horizon's pre-1.09 serialized layout: class/type + 21 + pad3 +
    # 4x i32 + NetConnectionInfo(154).
    assert len(lresp) == 196, len(lresp)
    lf = scert_make_encrypted(10, lresp, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(lf, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == lresp
    safe_print(f"[SELFTEST] V043 AccountLogin 0x07/0x08 -> MLS {advertise_ip}:{int(cfg.get('mls_exact_port',10078))}; len={len(lresp)}: OK")

    # V044 real post-login MLS captures from EyeToy Chat.
    cap_state = bytes.fromhex("01 49 45 54 43 30 30 30 30 30 30 30 30 30 30 30 30 31 00 5E 82 01 01 00 00 00")
    us = parse_update_user_state(cap_state)
    assert us["session_key"] == "ETC0000000000001" and us["user_action"] == 1
    cap_pi = bytes.fromhex("01 31 38 00 AA 00 00 00 00 00 00 00 00 00 00 00 00 00 EC 1E 82 01 00 45 54 43 30 30 30 30 30 30 30 30 30 30 30 30 31 00 00 00 01 00 00 00")
    pi = parse_player_info_request(cap_pi)
    assert pi["session_key"] == "ETC0000000000001" and pi["account_id"] == 1
    pir = make_player_info_response(pi["message_id"], "EyeToyUser", application_id=10554)
    assert len(pir) == 330 and pir[:2] == bytes([1, 0x32])
    pf = scert_make_encrypted(10, pir, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(pf, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == pir
    cap_end = bytes.fromhex("01 05 39 00 A7 01 00 00 00 00 00 00 00 00 00 00 00 00 70 B4 A7 01 00 45 54 43 30 30 30 30 30 30 30 30 30 30 30 30 31 00")
    se = parse_session_end_request(cap_end)
    ser = make_session_end_response(se["message_id"], 0)
    assert len(ser) == 30 and ser[:2] == bytes([1, 0x06])
    assert (ROOT / "tls" / "retail_delegated_vmail.der").is_file()
    safe_print("[SELFTEST] V044 MLS 0x49 UpdateUserState + 0x31/0x32 PlayerInfo + 0x05/0x06 SessionEnd: OK")
    safe_print("[SELFTEST] V044 vmail delegated TLS certificate present: OK")

    # V046: real post-PlayerInfo MLS VersionServer request captured from EyeToy.
    cap_mls_ver = bytes.fromhex("01 86 39 00 82 01 00 00 00 00 00 00 00 00 00 00 00 00 45 54 43 30 00 45 54 43 30 30 30 30 30 30 30 30 30 30 30 30 31 00")
    mv = parse_version_server_request(cap_mls_ver)
    assert mv["session_key"] == "ETC0000000000001"
    mvr = make_version_server_response(mv["message_id"], str(cfg.get("mls_version_string", "Medius Lobby Server Version 1.51.0001")))
    assert len(mvr) == 79 and mvr[:2] == bytes([1, 0x87]) and mvr[2:23] == mv["message_id"]
    mf = scert_make_encrypted(10, mvr, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(mf, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == mvr
    safe_print("[SELFTEST] V046 MLS 0x86 réel -> 0x87 Lobby Server Version: OK")

    ch_req = bytes.fromhex("01353130000100000000000000000000000045544330004554433030303030303030303030303100000001000000")
    ch = parse_channel_info_request(ch_req)
    assert ch["world_id"] == 1 and ch["session_key"] == "ETC0000000000001"
    ch_resp = make_channel_info_response(ch["message_id"], active_profile["channel_name"], 1, 32)
    assert ch_resp[:2] == bytes([1, 0x36]) and len(ch_resp) == 102
    safe_print("[SELFTEST] V064 MLS 0x35 réel -> 0x36 ChannelInfoResponse active profile: OK")

    # V048: real post-ChannelInfo GetAnnouncements request captured from EyeToy V047.
    ann_req = bytes.fromhex("014b3231000100000000000000000000000049cf000000455443303030303030303030303030310000003a290000")
    ar = parse_get_announcements_request(ann_req)
    assert ar["session_key"] == "ETC0000000000001"
    assert ar["application_id"] == 10554
    assert ar["pad"] == b"\x00\x00"
    atxt = str(cfg.get("mls_announcement_text", "Welcome to EyeToy Chat Europe"))
    aid = int(cfg.get("mls_announcement_id", 1))
    aresp = make_get_announcements_response(ar["message_id"], atxt, announcement_id=aid, end_of_list=True, status_code=0)
    assert aresp[:2] == bytes([1, 0x4D]) and aresp[2:23] == ar["message_id"]
    assert len(aresp) == 1038, len(aresp)
    assert struct.unpack_from("<i", aresp, 26)[0] == 0
    assert struct.unpack_from("<i", aresp, 30)[0] == aid
    assert aresp[-4:] == b"\x01\x00\x00\x00"
    af = scert_make_encrypted(10, aresp, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(af, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == aresp
    safe_print("[SELFTEST] V048 MLS 0x4B réel -> 0x4D GetAnnouncementsResponse: OK")

    # V049: real post-announcement AccountLogout request captured from EyeToy V048.
    logout_req = bytes.fromhex("01153132000000000000000000000000000000000000004554433030303030303030303030303100")
    lr = parse_account_logout_request(logout_req)
    assert lr["session_key"] == "ETC0000000000001"
    assert lr["extra"] == b""
    lresp = make_account_logout_response(lr["message_id"], 0)
    assert lresp[:2] == bytes([1, 0x16]) and lresp[2:23] == lr["message_id"]
    assert len(lresp) == 30 and struct.unpack_from("<i", lresp, 26)[0] == 0
    lf = scert_make_encrypted(10, lresp, rc_key, CTX_RC_CLIENT_SESSION)
    rid, enc, ctx, hh, pp, ok = scert_decode_frame(lf, rc_key)
    assert rid == 10 and enc and ctx == 3 and ok and pp == lresp
    safe_print("[SELFTEST] V049 MLS 0x15 réel -> 0x16 AccountLogoutResponse: OK")

    vmail_req = (b"GET /mt/servlet/ConfigRetrieveMessageTransformer HTTP/1.0\r\n"
                 b"HOST: vmail.online.scee.com\r\n\r\n")
    vmail_resp, vmail_path, vmail_body = http_response_for(vmail_req, cfg)
    assert vmail_path == "/mt/servlet/ConfigRetrieveMessageTransformer"
    assert vmail_resp.startswith(b"HTTP/1.0 200 OK") and vmail_body == b""
    vh = build_vmail_config_headers(cfg)
    assert len(vh) == 20
    for k, v in vh:
        assert k.encode("ascii") + b": " + v.encode("iso-8859-1") + b"\r\n" in vmail_resp
    bool_expected = {
        "ChatRooms.NonRegistered.Access": "true",
        "ChatRooms.Registered.Access": "true",
        "ChatRooms.Thumbnails.Read": "true",
        "ChatRooms.Thumbnails.Post": "true",
        "VideoMail.Inbox": "true",
        "VideoMail.Post": "true",
        "ScreenSaver.Access": "true",
        "FriendshipRequest.Lock": "false",
        "Product.Access": "true",
    }
    vh_map = dict(vh)
    for k, expected in bool_expected.items():
        assert vh_map[k] == expected, (k, vh_map[k], expected)
        assert (k.encode("ascii") + b": " + expected.encode("ascii") + b"\r\n") in vmail_resp
    assert b"Product.Access: 1\r\n" not in vmail_resp
    safe_print("[SELFTEST] V051 vmail ConfigRetrieve -> exact 20 headers + lowercase true/false booleans, Product.Access=true: OK")

    # V072 AdFeed parser/image-cache probe.
    _af_req = (b"GET /mt/servlet/AdFeedRetrieve HTTP/1.0\r\n"
               b"HOST: vmail.online.scee.com\r\n\r\n")
    _af_resp, _af_path, _af_body = http_response_for(_af_req, cfg)
    assert _af_path == "/mt/servlet/AdFeedRetrieve"
    assert _af_resp.startswith(b"HTTP/1.0 200 OK")
    assert b"<channel>" in _af_body and b"<image>" in _af_body and b"<item>" in _af_body
    assert b"<title>" in _af_body and b"<description>" in _af_body and b"<link>" in _af_body
    _img_path = str(cfg.get("v072_adfeed_image_path", "/adfeed/eyetoy_http_test.png"))
    _img_req = (f"GET {_img_path} HTTP/1.0\r\nHOST: vmail.online.scee.com\r\n\r\n").encode("ascii")
    _img_resp, _img_got_path, _img_body = http_response_for(_img_req, cfg)
    assert _img_got_path == _img_path and _img_resp.startswith(b"HTTP/1.0 200 OK")
    assert b"Content-Type: image/png\r\n" in _img_resp
    assert _img_body.startswith(bytes.fromhex("89504e470d0a1a0a"))
    safe_print("[SELFTEST] V072 AdFeed XML -> PNG HTTP image probe: OK")

    # V045 Medius NAT/UDP 10070 reply used by EyeToy after MUIS universe selection.
    nr = v045_make_nat_probe_response("192.0.2.75", 6969)
    assert nr == bytes.fromhex("C0 00 02 4B 1B 39")
    safe_print("[SELFTEST] V045 NAT probe reply 192.0.2.75:6969 -> c0a8014b1b39: OK")

    # V087 has two intentionally separate update branches.
    assert cfg.get("v087_branch") in ("full_http", "dnas21_research")
    assert cfg.get("v080_native_ca_enabled") is False
    assert cfg.get("v080_iso_patch_required") is False
    assert _tls_cert_validity_strings((ROOT / "tls" / "v086_update_server_2000_2049.der").read_bytes()) == [
        "000101000000Z", "491231235959Z"
    ]
    assert cfg.get("v083_client_rtc_diagnostic") is True
    assert cfg.get("v086_dnas21_mode4_required") is True
    if cfg.get("v087_branch") == "full_http":
        assert cfg.get("update_tls_enabled") is False
        assert int(cfg.get("http_port", 18080)) in cfg.get("http_plain_ports", [])
        assert cfg.get("v086_iso_trust_patch_required") is False
        assert cfg.get("vmail_scheme") == "http"
        assert str(cfg.get("v072_adfeed_link", "")).startswith("http://")
        safe_print("[SELFTEST] Public FULL HTTP -> Apache :10443 -> local plain HTTP :18080: OK")
    else:
        assert cfg.get("update_tls_cert_profile") == "retail_delegated_server_probe"
    assert cfg.get("v086_tls_valid_from_year") == 2000
    assert cfg.get("v086_tls_valid_until_year") == 2049
    assert len((ROOT / "tls" / "v086_timeless_root_2000_2049.pem").read_bytes()) == 0x522
    assert TLS_V086_RSA_K == 128
    safe_print("[SELFTEST] V086 room tree and TLS diagnostic material retained: OK")

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
    _clock = _tls_client_clock(ch["client_random"])
    assert ch["client_unix_time"] == 0x6A838182
    assert _clock and _clock["iso"] == "2026-08-17 21:47:46 UTC"
    assert _tls_parse_utctime("040812000000Z") == dt.datetime(2004, 8, 12, tzinfo=dt.timezone.utc)
    assert _tls_parse_utctime("100812000000Z") == dt.datetime(2010, 8, 12, tzinfo=dt.timezone.utc)
    safe_print("[SELFTEST] V083 ClientHello RTC decode + X.509 window guard: OK")
    assert TLS_CERT_DER_PATH.is_file() and len(TLS_CERT_DER_PATH.read_bytes()) > 400
    assert (ROOT / "tls" / "v080_scee_mis_root_2026.pem").is_file()
    assert len((ROOT / "tls" / "v080_scee_mis_root_2026.pem").read_bytes()) == 0x522
    assert len((ROOT / "tls" / "v080_scee_mis_root_2026.der").read_bytes()) == 930
    assert TLS_V080_RSA_K == 128
    for _pname, _paths in TLS_CERT_PROFILES.items():
        assert _paths and all(_p.is_file() and len(_p.read_bytes()) > 300 for _p in _paths), _pname
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
    safe_print("[SELFTEST] V039 TLS1.0 + profile diagnostics + cert probes + PRF + RC4/HMAC: OK")
    try:
        if _self_state.exists(): _self_state.unlink()
    except OSError:
        pass
    safe_print("[SELFTEST] OK")
    return 0



def v038_log_time_diagnostics(cfg):
    """V038: log only local/server time facts. Does not alter the certificate."""
    import time as _time
    import datetime as _dt
    now_local = _dt.datetime.now().astimezone()
    now_utc = _dt.datetime.now(_dt.timezone.utc)
    log_event(cfg, "V039-TIME-DIAG",
              f"server_local={now_local.isoformat()}; server_utc={now_utc.isoformat()}; "
              f"time_time={_time.time():.3f}; tzname={_time.tzname}; "
              f"tls_profile={cfg.get('update_tls_cert_profile')}; "
              f"v034_force={cfg.get('v034_force_tls_profile')}; "
              f"v035_force={cfg.get('v035_force_tls_profile')}")

def main():
    parser = argparse.ArgumentParser(description="EyeToy Chat PS2 Community Server V083 DNAS Patch 21 Guard")
    parser.add_argument("--ip", help="IPv4 LAN à renvoyer par le DNS (défaut: auto)")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--tls-profile", help="override TLS certificate profile for this run")
    parser.add_argument("--chatroom-profile", choices=sorted(V064_CHATROOM_PROFILES),
                        help="profil cohérent salon/WorldID pour cette exécution")
    parser.add_argument("--reset-tls-matrix", action="store_true", help="reset persistent TLS profile results and V037 matrix logs")
    args = parser.parse_args()

    cfg = load_config()
    if args.chatroom_profile:
        cfg["v064_chatroom_profile"] = args.chatroom_profile
    if args.reset_tls_matrix:
        _v037_reset_tls_matrix(cfg)
    v035_print_tls_matrix_config(cfg)
    if bool(cfg.get("v075_social_enabled", True)):
        v075_reset_online_state(cfg)
    if args.tls_profile:
        cfg["v034_force_tls_profile"] = args.tls_profile
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
    active_profile = v064_chatroom_profile(cfg)
    log_event(cfg, "VERSION",
              f"EyeToyChat Server {VERSION}; branch={cfg.get('v087_branch')}; profile={active_profile['name']}")
    log_protocol_knowledge(cfg)
    log_event(
        cfg, "V036-CONFIG",
        f"config_path={CONFIG_PATH}; exists={CONFIG_PATH.is_file()}; "
        f"requested_tls_profile={cfg.get('update_tls_cert_profile')}; "
        f"force_tls_profile={cfg.get('v034_force_tls_profile')}; "
        f"profile_list={cfg.get('update_tls_cert_profiles')}"
    )
    _tls_prepare_v33_date_probes(cfg)
    log_scert_rsa_identity(cfg, "SCERT", MEDIUS_RSA_N, "server RSA_AUTH key (GLOBAL MEDIUS KEY)")
    _tls_log_persistent_state(cfg)
    try:
        _v86_root = ROOT / "tls" / "v086_timeless_root_2000_2049.pem"
        _v86_leaf = ROOT / "tls" / "v086_update_server_2000_2049.der"
        log_event(cfg, "V086-TIMELESS-TRUST", f"root_pem_len={len(_v86_root.read_bytes()) if _v86_root.is_file() else -1}; update_leaf_sha1={hashlib.sha1(_v86_leaf.read_bytes()).hexdigest() if _v86_leaf.is_file() else 'missing'}; validity=2000-2049; ISO_patch_required={bool(cfg.get('v086_iso_trust_patch_required', True))}")
    except Exception as _e:
        log_event(cfg, "V086-TIMELESS-TRUST-ERROR", str(_e))
    try:
        _v80_root = ROOT / "tls" / "v080_scee_mis_root_2026.pem"
        _v80_leaf = ROOT / "tls" / "v080_update_server_2026.der"
        log_event(cfg, "V080-NATIVE-TLS-CA", f"enabled={bool(cfg.get('v080_native_ca_enabled', False))}; root_pem_len={len(_v80_root.read_bytes()) if _v80_root.is_file() else -1}; update_leaf_sha1={hashlib.sha1(_v80_leaf.read_bytes()).hexdigest() if _v80_leaf.is_file() else 'missing'}; ISO_patch_required={bool(cfg.get('v080_iso_patch_required', False))}")
    except Exception as _e:
        log_event(cfg, "V080-NATIVE-TLS-CA-ERROR", str(_e))
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
    safe_print(" EyeToy: Chat PS2 - Community Server 0.3.0-beta1")
    safe_print(f" IP annoncée pour Medius/NAT : {advertise_ip}")
    safe_print(" Services EyeToy : Apache2 public :10443 -> HTTP local")
    for x in ("eyetoychat-master.online.scee.com", "eyetoychat-update.online.scee.com", "vmail.online.scee.com"):
        safe_print(f"   {x} -> {advertise_ip}")
    safe_print(f" HTTP local : {cfg.get('http_bind_ip', '127.0.0.1')}:{int(cfg.get('http_port', 18080))}")
    safe_print(f" Update : /qa_patches/index.xml -> BUILD={cfg.get('update_build', 194)} ({cfg.get('update_mode', 'no_update')})")
    safe_print(" Update V087A FIX2 : HTTP clair + ChannelList legacy Medius 108")
    safe_print(" Patch ISO : utiliser 01_FULL_PATCH_HTTP_V087A.bat sur un ISO deja DNAS21 MODE 4")
    safe_print(" Date PS2/PCSX2 : toute date, dont 2026")
    safe_print(f" Update HTTP : TCP/{int(cfg.get('update_tls_port', 10443))} sans TLS")
    safe_print(" Policy 0x48 : pad_before_287 / 287 octets verrouillé (capture-confirmé)")
    safe_print(" Post-0x48 : capture RAW dédiée activée pour identifier la prochaine étape EyeToy")
    safe_print(f" MUIS Universe : {cfg.get('universe_name', 'EyeToy Chat Europe')} -> {advertise_ip}:{int(cfg.get('universe_next_port', 10075))}")
    safe_print(f" Profil chatroom : {active_profile['name']} -> XML {active_profile['room_title']!r}/{active_profile['room_id']} + menu title/icon + callback metadata, canal {active_profile['channel_name']!r}/WorldID {active_profile['channel_world_id']}, login={active_profile['account_login_world_id']}, connect={active_profile['connect_world_id']}, GF1={active_profile['generic_field1']}")
    safe_print(" Salons V086 : Francais/English > General/Sport > TEXT256 WorldID 1..4")
    safe_print(f" MAS : SCERT crypto/connect actif sur TCP/{int(cfg.get('mas_exact_port', cfg.get('universe_next_port', 10075)))}; AccountLogin renvoie le WorldID du profil")
    safe_print(f" MLS : listener dédié TCP/{int(cfg.get('mls_exact_port', 10078))}; timeout d'inactivité={float(cfg.get('mls_capture_timeout', 300.0)):.0f}s; social V083=salons isoles + BinaryMessage cible/canal/univers + GameWorld capture")
    safe_print(f" VideoMail : stockage/capture HTTP actif={bool(cfg.get('v076_videomail_store_enabled', True))}; inbox_mode={cfg.get('v076_videomail_inbox_mode','empty_xml')}; media={cfg.get('v076_media_store_dir','media_store')}")
    safe_print(" DNAS : direct vers le serveur communautaire")
    safe_print("   gate1.eu.dnas.playstation.org -> réponse du DNS communautaire")
    safe_print("   DNS DNAS upstream : " + ", ".join(cfg.get("dnas_dns_upstreams", ["45.7.228.197"])))
    safe_print(" Public deployment : TLS disabled; Apache2 may proxy plain HTTP :10443")
    safe_print(" Résultats : logs/tls_x509_matrix_v037.tsv et .jsonl")
    safe_print("=" * 68)

    threads = []
    if bool(cfg.get("dns_enabled", True)):
        threads.extend([DNSServer(cfg, advertise_ip), DNSTCPServer(cfg, advertise_ip)])
    threads.append(NetstatWatcher(cfg))
    mas_port = int(cfg.get("mas_exact_port", cfg.get("universe_next_port", 10075)))
    mls_port = int(cfg.get("mls_exact_port", 10078))
    threads.append(MASListener(cfg))
    threads.append(MLSListener(cfg))
    for p in sorted(set(map(int, cfg.get("tcp_probe_ports", [])))):
        if p in (mas_port, mls_port):
            continue
        threads.append(TCPProbe(cfg, p))
    for p in sorted(set(map(int, cfg.get("udp_probe_ports", [])))):
        threads.append(UDPProbe(cfg, p))
    for t in threads:
        t.start()

    if bool(cfg.get("dns_enabled", True)):
        safe_print("\nServeur lancé. DNS primaire/secondaire :", advertise_ip)
    else:
        safe_print("\nServeur lancé. DNS fourni par BIND9 sur le VPS.")
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


# V036 research metadata (EyeToy Chat Light)
V036_CHAT_LIGHT_RESEARCH = {
    "ssl_library": "RSA BSAFE SSL-C",
    "protocol_seen": "TLSv1",
    "checks_seen_in_client": [
        "certificate not_before/not_after",
        "expiration check",
        "Server CA match",
        "commonName to hostname match",
        "X509 verification",
    ],
    "endpoints": [
        "eyetoychat-master.online.scee.com",
        "eyetoychat-update.online.scee.com",
        "vmail.online.scee.com",
        "43.194.211.76",
    ],
    "patch_path": "/qa_patches_demo/index.xml",
}
