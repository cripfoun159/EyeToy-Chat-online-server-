#!/usr/bin/env python3
"""EyeToy Chat V033 - trust material scanner (stdlib only).

Scans an EyeToy Chat ISO image or an extracted game directory for:
- hostnames / SSL / CA-related strings;
- PEM certificates;
- DER-like X.509 certificate candidates containing RSA/X.509 OIDs.

This does not claim a candidate is the certificate EyeToy trusts. It only
produces a small evidence bundle to inspect after TLS alert 46.
"""
from __future__ import annotations
import argparse, base64, hashlib, os, re, sys
from pathlib import Path

RSA_OID = bytes.fromhex('06092a864886f70d010101')      # rsaEncryption
SHA1_RSA_OID = bytes.fromhex('06092a864886f70d010105') # sha1WithRSAEncryption
PEM_BEGIN = b'-----BEGIN CERTIFICATE-----'
PEM_END = b'-----END CERTIFICATE-----'
SCEE_ROOT_SHA1 = '114a7be0a9f99d28d88f726e90b84cbc289c5861'
SCEE_ROOT_SHA256 = 'a5a51101510370e956beb301a61d3873078a6070c67750640ad2b437fb4fb358'
BETA_TEST_CA_SHA1 = 'a8d5716647fd04c99ae4e04e02fa0c01338ca0e9'
BETA_TEST_CA_SHA256 = 'c83c705e08c786f2d17f2ab5d82358350b6b30c7f7311690d7d711c483030630'
KEYWORDS = [
    b'eyetoychat-update.online.scee.com', b'eyetoychat-master.online.scee.com',
    b'online.scee.com', b'https://', b'https', b'ssl', b'tls', b'certificate',
    b'cert', b'root ca', b'root', b'verisign', b'thawte', b'entrust',
    b'baltimore', b'geotrust', b'sony', b'scee', b'playstation', b'rsa', b'x509',
    b'eyetoychat-beta.online.scee.com', b'hardware-master-muis.online.scee.com',
    b'hw2003-prod-muis.rt.au.playstation.com', b'43.194.211.76', b'217.18.18.118',
    b'private key', b'rsa private key', b'begin private key', b'begin rsa private key',
    b'scert', b'sce-rt', b'medius', b'cryptkey', b'rsa_auth', b'sessionbegin', b'sessionkey', b'validity', b'notbefore', b'notafter',
]
SCAN_EXTS = {'.elf','.irx','.bin','.dat','.img','.cnf','.xml','.crt','.cer','.der','.pem','.prx','.iso'}

GLOBAL_MEDIUS_N = int("10315955513017997681600210131013411322695824559688299373570246338038100843097466504032586443986679280716603540690692615875074465586629501752500179100369237")
GLOBAL_MEDIUS_MOD_BE = GLOBAL_MEDIUS_N.to_bytes(64, 'big')
GLOBAL_MEDIUS_MOD_LE = GLOBAL_MEDIUS_MOD_BE[::-1]
KNOWN_MEDIUS_BINARY = {
    'GLOBAL_MEDIUS_MODULUS_BE': GLOBAL_MEDIUS_MOD_BE,
    'GLOBAL_MEDIUS_MODULUS_LE': GLOBAL_MEDIUS_MOD_LE,
}

def sha(b: bytes):
    return hashlib.sha1(b).hexdigest(), hashlib.sha256(b).hexdigest()

def printable_context(data: bytes, pos: int, radius=96):
    a=max(0,pos-radius); z=min(len(data),pos+radius)
    chunk=data[a:z]
    text=''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
    return a, text

def parse_der_total(data: bytes, off: int):
    if off >= len(data) or data[off] != 0x30 or off+2 > len(data):
        return None
    first=data[off+1]
    if first < 0x80:
        n=first; h=2
    else:
        k=first & 0x7f
        if k < 1 or k > 4 or off+2+k > len(data): return None
        n=int.from_bytes(data[off+2:off+2+k], 'big'); h=2+k
    total=h+n
    if total < 128 or total > 65536 or off+total > len(data): return None
    return total

def der_candidates(data: bytes):
    seen=set(); out=[]
    # Anchor around rsaEncryption occurrences and walk backwards for enclosing SEQUENCEs.
    for oid in (RSA_OID, SHA1_RSA_OID):
        start=0
        while True:
            pos=data.find(oid,start)
            if pos < 0: break
            lo=max(0,pos-4096)
            for off in range(pos-1,lo-1,-1):
                if data[off] != 0x30: continue
                total=parse_der_total(data,off)
                if not total: continue
                end=off+total
                if off < pos < end and total >= 256:
                    blob=data[off:end]
                    # X.509 certs normally contain rsa/sha1 OIDs and multiple ASN.1 sequences.
                    if (RSA_OID in blob or SHA1_RSA_OID in blob) and blob.count(b'\x30') >= 4:
                        h=hashlib.sha256(blob).digest()
                        if h not in seen:
                            seen.add(h); out.append((off,blob))
                    break
            start=pos+1
    return out


def pem_certificates(data: bytes):
    out=[]; pos=0
    while True:
        a=data.find(PEM_BEGIN,pos)
        if a < 0: break
        z=data.find(PEM_END,a)
        if z < 0: break
        z += len(PEM_END)
        pem=data[a:z]
        body=b''.join(line.strip() for line in pem.splitlines()[1:-1])
        try:
            der=base64.b64decode(body, validate=True)
        except Exception:
            der=b''
        out.append((a,pem,der))
        pos=z
    return out

def iter_inputs(path: Path):
    if path.is_file():
        yield path
        return
    for p in path.rglob('*'):
        if not p.is_file(): continue
        # Scan all reasonably sized files, prioritising binary/game-ish extensions.
        try: size=p.stat().st_size
        except OSError: continue
        if size == 0: continue
        if p.suffix.lower() in SCAN_EXTS or size <= 64*1024*1024:
            yield p

def main():
    ap=argparse.ArgumentParser(description='EyeToy Chat V033 - scan ISO/folder for TLS CA/certificate/private-key clues')
    ap.add_argument('source', help='Path to SCES-52154 ISO or extracted game folder')
    ap.add_argument('--out', default='trust_scan_output', help='Output folder')
    ap.add_argument('--max-file-mb', type=int, default=4096, help='Skip individual files above this size (default 4096 MB)')
    args=ap.parse_args()
    src=Path(args.source).expanduser().resolve(); out=Path(args.out).expanduser().resolve()
    if not src.exists():
        print(f'ERROR: source not found: {src}', file=sys.stderr); return 2
    out.mkdir(parents=True,exist_ok=True); canddir=out/'der_candidates'; canddir.mkdir(exist_ok=True); pemdir=out/'pem_certificates'; pemdir.mkdir(exist_ok=True)
    report=[]; report.append('EyeToy Chat V033 - TLS trust/private-key material scan\n')
    report.append(f'Source: {src}\n')
    report.append('NOTE: hits are candidates only; they are not proof of the trusted EyeToy CA.\n\n')
    files=0; bytes_scanned=0; cand_count=0; pem_count=0; kw_count=0; medius_bin_count=0
    for p in iter_inputs(src):
        try:
            size=p.stat().st_size
            if size > args.max_file_mb*1024*1024: continue
            data=p.read_bytes()
        except Exception as e:
            report.append(f'[READ-ERROR] {p}: {e}\n'); continue
        files+=1; bytes_scanned+=len(data)
        rel=str(p.relative_to(src)) if src.is_dir() else p.name
        hits=[]
        low=data.lower()
        for kw in KEYWORDS:
            pos=0
            while True:
                pos=low.find(kw,pos)
                if pos < 0: break
                a,ctx=printable_context(data,pos)
                hits.append((kw.decode('ascii','replace'),pos,a,ctx)); kw_count+=1
                pos += max(1,len(kw))
                if len(hits) >= 50: break
            if len(hits) >= 50: break
        medius_hits=[]
        for label, blob in KNOWN_MEDIUS_BINARY.items():
            pos=0
            while True:
                pos=data.find(blob,pos)
                if pos < 0: break
                medius_hits.append((label,pos,hashlib.sha1(blob).hexdigest(),hashlib.sha256(blob).hexdigest()))
                medius_bin_count += 1
                pos += 1
        pem_items=pem_certificates(data)
        pems=len(pem_items)
        cands=der_candidates(data)
        if hits or medius_hits or pems or cands:
            report.append(f'\n=== {rel} ({len(data)} bytes) ===\n')
            for kw,pos,a,ctx in hits:
                report.append(f'[STRING] {kw!r} @ 0x{pos:X}; context@0x{a:X}: {ctx}\n')
            for label,pos,s1,s256 in medius_hits:
                report.append(f'[MEDIUS-RSA-BINARY] {label} @ 0x{pos:X}; sha1={s1}; sha256={s256} *** EXACT 64-BYTE MATCH ***\n')
            if pems:
                report.append(f'[PEM] BEGIN CERTIFICATE occurrences: {pems}\n')
                for poff,pem,der in pem_items:
                    pem_count += 1
                    s1,s256 = sha(der if der else pem)
                    pname=f'certificate_{pem_count:03d}_{p.name}_off_{poff:08X}.pem'.replace(os.sep,'_')
                    (pemdir/pname).write_bytes(pem+b'\n')
                    if s1 == SCEE_ROOT_SHA1 or s256 == SCEE_ROOT_SHA256:
                        label = ' *** MATCH SCEE MIS ROOT 2002 ***'
                    elif s1 == BETA_TEST_CA_SHA1 or s256 == BETA_TEST_CA_SHA256:
                        label = ' *** MATCH BETA TEST CA CN=43.194.211.76 ***'
                    else:
                        label = ''
                    report.append(f'[PEM-CERT] offset=0x{poff:X} der_len={len(der)} sha1={s1} sha256={s256}{label} -> pem_certificates/{pname}\n')
            for off,blob in cands:
                cand_count+=1; s1,s256=sha(blob)
                name=f'candidate_{cand_count:03d}_{p.name}_off_{off:08X}_{s1[:12]}.der'.replace(os.sep,'_')
                (canddir/name).write_bytes(blob)
                report.append(f'[DER-CANDIDATE] offset=0x{off:X} len={len(blob)} sha1={s1} sha256={s256} -> der_candidates/{name}\n')
    report.append('\n=== SUMMARY ===\n')
    report.append(f'Files scanned: {files}\nBytes scanned: {bytes_scanned}\nString hits: {kw_count}\nExact Medius RSA modulus hits: {medius_bin_count}\nPEM certificates extracted: {pem_count}\nDER candidates extracted: {cand_count}\n')
    report.append('Known SCERT key: GLOBAL MEDIUS RSA n, 512-bit, e=17; scanner checks exact 64-byte BE and LE forms.\nKnown beta anchors: SCEE MIS root SHA1=' + SCEE_ROOT_SHA1 + '; Beta Test CA SHA1=' + BETA_TEST_CA_SHA1 + '\n')
    report.append('NOTE: a PRIVATE KEY string hit can come from OpenSSL library text; only an actual PEM/DER key blob would be actionable.\n')
    rp=out/'trust_scan_report.txt'; rp.write_text(''.join(report),encoding='utf-8',errors='replace')
    print(f'Done. Report: {rp}')
    print(f'PEM certificates: {pem_count} in {pemdir}')
    print(f'DER candidates: {cand_count} in {canddir}')
    return 0
if __name__=='__main__':
    raise SystemExit(main())
