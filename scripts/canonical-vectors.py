#!/usr/bin/env python3
"""Independent IF-CJSON-1 canonical digest conformance (not a signature verifier)."""
import hashlib, json, re, sys, unicodedata

def canonical(value, depth=0):
    if depth > 32:
        raise ValueError('Maximum depth')
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9007199254740991:
            raise ValueError('Unsafe integer')
        return str(value)
    if isinstance(value, str):
        if unicodedata.normalize('NFC', value) != value or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError('Invalid Unicode')
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if isinstance(value, list):
        return '[' + ','.join(canonical(x, depth + 1) for x in value) + ']'
    if isinstance(value, dict):
        for key in value:
            if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}', key) or key in ('constructor', '__proto__', 'prototype'):
                raise ValueError('Invalid key')
        return '{' + ','.join(json.dumps(k) + ':' + canonical(value[k], depth + 1) for k in sorted(value)) + '}'
    raise ValueError('Unsupported type')

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result

if __name__ == '__main__':
    vectors = json.load(open(sys.argv[1], encoding='utf-8'), object_pairs_hook=unique_pairs)
    for vector in vectors:
        actual = hashlib.sha256(canonical(vector['value']).encode('utf-8')).hexdigest()
        if actual != vector['sha256']:
            raise SystemExit('FAIL: ' + vector['name'])
    print(json.dumps({'valid': True, 'vectors': len(vectors), 'implementation': 'Python standard library'}))
