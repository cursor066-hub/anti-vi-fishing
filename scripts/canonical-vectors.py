#!/usr/bin/env python3
"""Independent IF-CJSON-1 canonical digest conformance (not a signature verifier).

Shares the strict canonicalizer from verify-vectors.py — a second, weaker
implementation would let this "reference" accept canonical forms the runtime
rejects (w23-supply F12). verify-vectors.py is loaded by path since the
hyphenated name is not importable directly.
"""
import hashlib, importlib.util, json, sys, pathlib

_spec = importlib.util.spec_from_file_location('verify_vectors', pathlib.Path(__file__).with_name('verify-vectors.py'))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
canon = _mod.canon
CanonError = _mod.CanonError


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


if __name__ == '__main__':
    vectors = json.load(open(sys.argv[1], encoding='utf-8'), object_pairs_hook=unique_pairs,
                        parse_int=lambda s: -0.0 if s == '-0' else int(s))
    for vector in vectors:
        try:
            got = canon(vector['value'])
            actual = hashlib.sha256(got.encode('utf-8')).hexdigest()
        except CanonError:
            raise SystemExit('FAIL (rejected input): ' + vector['name'])
        if actual != vector['sha256']:
            raise SystemExit('FAIL: ' + vector['name'])
    print(json.dumps({'valid': True, 'vectors': len(vectors), 'implementation': 'Python standard library'}))
