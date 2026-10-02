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
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

KEY_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$')
# Parity with src/canonical.mjs: every Object.prototype member name is a
# forbidden key, not only the classic pollution trio (w8-canonical F6).
FORBIDDEN = {'__proto__', 'prototype', 'constructor', 'toString',
             'toLocaleString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf',
             'propertyIsEnumerable', '__defineGetter__', '__defineSetter__',
             '__lookupGetter__', '__lookupSetter__', 'watch', 'unwatch'}

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
        # The bound counts UTF-16 code units — the wire unit — not code
        # points; 40000 astral chars are 80000 units (w8-canonical F7).
        if len(value.encode('utf-16-le')) // 2 > 65536: raise CanonError('too long')
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
    def verify_envelope(env, purpose):
        # Mirrors verifySigned's envelope checks: exact 3-key envelope,
        # exact 4-key protected header, purpose and suite binding, then
        # Ed25519 verification over the canonical message.
        if sorted(env) != ['payload', 'protected', 'signature']: return False
        if sorted(env['protected']) != ['key_id', 'profile', 'purpose', 'suite']: return False
        if env['protected']['profile'] != 'IF-CJSON-1' or env['protected']['suite'] != 'Ed25519' or env['protected']['purpose'] != purpose: return False
        sig = env['signature']
        if not isinstance(sig, str) or not re.fullmatch(r'[A-Za-z0-9_-]{86}', sig): return False
        if base64.urlsafe_b64encode(b64url(sig)).rstrip(b'=').decode() != sig: return False
        message = canon({'protected': env['protected'], 'payload': env['payload']}).encode()
        pub = serialization.load_pem_public_key(v['public_key'].encode())
        try:
            Ed25519PublicKey.from_public_bytes(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).verify(b64url(sig), message)
            return True
        except InvalidSignature:
            return False
    for v in ev['vectors']:
        env = v['envelope']
        if v.get('expect') == 'reject':
            if verify_envelope(env, v['purpose']): failed += 1; print(f"FAIL rejection-accepted/{v['name']}")
            continue
        if not verify_envelope(env, v['purpose']):
            failed += 1; print(f"FAIL envelope/{v['name']}"); continue
        message = canon({'protected': env['protected'], 'payload': env['payload']}).encode()
        pub = serialization.load_pem_public_key(v['public_key'].encode())
        # Tamper once: any single-bit mutation of the message must reject.
        tampered = bytearray(message); tampered[0] ^= 1
        try:
            Ed25519PublicKey.from_public_bytes(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).verify(b64url(env['signature']), bytes(tampered))
            failed += 1; print(f"FAIL tamper-accepted/{v['name']}")
        except InvalidSignature:
            pass
    print(f"python: {len(cv['vectors'])} canonical + {len(ev['vectors'])} envelope vectors, {failed} failures")

    # IF-PARSE-1: strict-parse vectors. Python's json models most of the
    # grammar via hooks (dup keys, number lexemes, trailing data); vectors
    # marked impl_only exercise bounds only the shipped parser expresses
    # (depth, UTF-16 length, pre-parse byte caps).
    pv = json.load(open('vectors/parse-vectors.json'))
    def strict_hook(pairs):
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys): raise ValueError('dup key')
        # Key grammar is enforced at parse, not only at canon: escaped and
        # literal proto-member keys are schema violations (w8-canonical F6).
        if any(k in FORBIDDEN or not KEY_RE.match(k) for k in keys): raise ValueError('bad key')
        return dict(pairs)
    def num_hook(s):
        if not re.fullmatch(r'-?(0|[1-9][0-9]*)', s) or s == '-0' or abs(int(s)) > 2**53 - 1:
            raise ValueError('number grammar')
        return int(s)
    for v in pv['vectors']:
        if v.get('impl_only'): continue
        try:
            json.loads(v['text'], object_pairs_hook=strict_hook, parse_int=num_hook, parse_float=num_hook,
                       parse_constant=lambda s: (_ for _ in ()).throw(ValueError('literal')))
            ok = v['expect'] == 'accept'
        except Exception:
            ok = v['expect'] == 'reject'
        if not ok:
            failed += 1; print(f"FAIL parse/{v['name']}")
    print(f"python: {len([v for v in pv['vectors'] if not v.get('impl_only')])} parse vectors checked, {failed} total failures")

    ev2 = json.load(open('vectors/envelope-es256-vectors.json'))
    for v in ev2['vectors']:
        env = v['envelope']
        if env['protected']['suite'] != 'ES256':
            failed += 1; print(f"FAIL es256-header/{v['name']}"); continue
        message = canon({'protected': env['protected'], 'payload': env['payload']}).encode()
        pub = serialization.load_pem_public_key(v['public_key'].encode())
        raw = b64url(env['signature'])
        if len(raw) != 64:
            failed += 1; print(f"FAIL es256-length/{v['name']}"); continue
        der = encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big'))
        try:
            pub.verify(der, message, ECDSA(SHA256()))
        except InvalidSignature:
            failed += 1; print(f"FAIL es256-signature/{v['name']}")
        tampered = bytearray(message); tampered[0] ^= 1
        try:
            pub.verify(der, bytes(tampered), ECDSA(SHA256()))
            failed += 1; print(f"FAIL es256-tamper-accepted/{v['name']}")
        except InvalidSignature:
            pass
    print(f"python: {len(ev2['vectors'])} ES256 envelope vectors, {failed} total failures")
    # A truncated corpus must not pass: per-vector asserts alone would let a
    # commit halve coverage undetected (w11-supply SC-10).
    if len(cv['vectors']) < 18 or len(ev['vectors']) < 11 or len(ev2['vectors']) < 2 or len([v for v in pv['vectors'] if not v.get('impl_only')]) < 21:
        print(f"FAIL python-corpus: truncated vector sets (canonical={len(cv['vectors'])}, envelope={len(ev['vectors'])}, parse={len(pv['vectors'])}, es256={len(ev2['vectors'])})")
        return 1
    return 1 if failed else 0

if __name__ == '__main__':
    sys.exit(main())
