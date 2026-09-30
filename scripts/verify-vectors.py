#!/usr/bin/env python3
"""IF-CJSON-1 + IF-ENVELOPE-1 conformance verifier — independent Python implementation.

Reimplements the canonicalisation rules and Ed25519 envelope verification from
scratch (unicodedata NFC check, ASCII-key sorting, integer-only numbers) so the
Node/WebCrypto implementations are anchored by a second language, not just a
second API surface of the same runtime.
"""
import json
import re
import sys
import unicodedata
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

KEY_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$')
FORBIDDEN = {'__proto__', 'prototype', 'constructor'}

class CanonError(Exception):
    pass

ESC = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\t': '\\t', '\n': '\\n', '\f': '\\f', '\r': '\\r'}

def esc_string(s):
    # Exact JSON.stringify string escaping: shorthands for the five standard
    # controls, \uXXXX for other <0x20 controls, everything else literal.
    out = []
    for ch in s:
        o = ord(ch)
        if ch in ESC: out.append(ESC[ch])
        elif o < 0x20: out.append(f'\\u{o:04x}')
        elif 0xD800 <= o <= 0xDFFF: raise CanonError('lone surrogate')
        else: out.append(ch)
    return '"' + ''.join(out) + '"'

def canon(value, depth=0):
    if depth > 32: raise CanonError('depth')
    if value is None: return 'null'
    if value is True or value is False: return 'true' if value else 'false'
    if isinstance(value, (int,)):
        if abs(value) > 2**53 - 1: raise CanonError('unsafe integer')
        return str(value)
    if isinstance(value, float): raise CanonError('float')
    if isinstance(value, str):
        if unicodedata.normalize('NFC', value) != value: raise CanonError('non-NFC')
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value): raise CanonError('surrogate')
        if len(value) > 65536: raise CanonError('too long')
        return esc_string(value)
    if isinstance(value, list):
        if len(value) > 10000: raise CanonError('array too long')
        return '[' + ','.join(canon(v, depth + 1) for v in value) + ']'
    if isinstance(value, dict):
        if len(value) > 256: raise CanonError('object too large')
        for k in value:
            if not KEY_RE.match(k) or k in FORBIDDEN: raise CanonError('bad key')
        return '{' + ','.join(esc_string(k) + ':' + canon(value[k], depth + 1) for k in sorted(value)) + '}'
    raise CanonError('unsupported value')

def b64url(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def main():
    # parse_int hook preserves -0 as a float sentinel so it hits the float
    # rejection rule exactly like Node's JSON.parse(-0) -> -0.
    cv = json.load(open('vectors/canonical-vectors.json'), parse_int=lambda s: -0.0 if s == '-0' else int(s))
    failed = 0
    for v in cv['vectors']:
        try:
            got = canon(v['input'])
            ok = got == v['canonical'] and not v.get('error')
        except CanonError:
            ok = v['canonical'] is None
        except Exception:
            ok = v['canonical'] is None
        if not ok:
            failed += 1
            print(f"FAIL canonical/{v['name']}")
    ev = json.load(open('vectors/envelope-vectors.json'))
    for v in ev['vectors']:
        env = v['envelope']
        if sorted(env) != ['payload', 'protected', 'signature'] or sorted(env['protected']) != ['key_id', 'profile', 'purpose', 'suite']:
            failed += 1; print(f"FAIL envelope-shape/{v['name']}"); continue
        if env['protected']['profile'] != 'IF-CJSON-1' or env['protected']['suite'] != 'Ed25519' or env['protected']['purpose'] != v['purpose']:
            failed += 1; print(f"FAIL header/{v['name']}"); continue
        message = canon({'protected': env['protected'], 'payload': env['payload']}).encode()
        pub = serialization.load_pem_public_key(v['public_key'].encode())
        try:
            Ed25519PublicKey.from_public_bytes(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).verify(b64url(env['signature']), message)
        except InvalidSignature:
            failed += 1; print(f"FAIL signature/{v['name']}")
        # Tamper once: any single-bit mutation of the message must reject.
        tampered = bytearray(message); tampered[0] ^= 1
        try:
            Ed25519PublicKey.from_public_bytes(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).verify(b64url(env['signature']), bytes(tampered))
            failed += 1; print(f"FAIL tamper-accepted/{v['name']}")
        except InvalidSignature:
            pass
    print(f"python: {len(cv['vectors'])} canonical + {len(ev['vectors'])} envelope vectors, {failed} failures")
    return 1 if failed else 0

if __name__ == '__main__':
    sys.exit(main())
