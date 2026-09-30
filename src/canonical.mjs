import { createHash } from 'node:crypto';
import { invalid } from './errors.mjs';

// IF-CJSON-1: NFC strings, ASCII object keys, safe integers, no floating point.
// This deliberately restricted profile is NOT advertised as general RFC 8785.
export function canonical(value, depth = 0) {
  if (depth > 32) throw invalid('Maximum nesting depth exceeded');
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw invalid('Only safe non-negative-zero integers are supported');
    return String(value);
  }
  if (typeof value === 'string') {
    if (value !== value.normalize('NFC') || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) throw invalid('Strings must be valid NFC Unicode');
    if (value.length > 65536) throw invalid('String too long');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (value.length > 10000) throw invalid('Array too long');
    return '[' + Array.from(value, v => canonical(v, depth + 1)).join(',') + ']';
  }
  if (value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    const keys = Object.keys(value).sort();
    if (keys.length > 256) throw invalid('Object too large');
    return '{' + keys.map(k => {
      if (!/^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/.test(k) || ['__proto__', 'prototype', 'constructor'].includes(k)) throw invalid('Unsupported object key');
      return JSON.stringify(k) + ':' + canonical(value[k], depth + 1);
    }).join(',') + '}';
  }
  throw invalid('Unsupported canonical value');
}
export function digest(value) { return createHash('sha256').update(canonical(value)).digest('hex'); }
export function hashBytes(value) { return createHash('sha256').update(value).digest('hex'); }
export function clone(value) { return JSON.parse(canonical(value)); }

// JSON.parse alone silently accepts duplicate keys; signatures must never do so.
export function parseStrict(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 1048576) throw invalid('JSON body exceeds 1 MiB');
  let i = 0;
  const ws = () => { while (/[\x20\t\r\n]/.test(text[i] ?? '') && i < text.length) i++; };
  function str() {
    const start = i++;
    while (i < text.length) {
      if (text[i] === '\\') { i += 2; continue; }
      if (text[i++] === '"') {
        try { return JSON.parse(text.slice(start, i)); } catch { throw invalid('Invalid JSON string'); }
      }
    }
    throw invalid('Unterminated JSON string');
  }
  function read(depth) {
    if (depth > 32) throw invalid('Maximum nesting depth exceeded');
    ws(); const c = text[i];
    if (c === '"') return str();
    if (c === '{') {
      i++; ws(); const out = Object.create(null), keys = new Set();
      if (text[i] === '}') { i++; return out; }
      while (i < text.length) {
        ws(); if (text[i] !== '"') throw invalid('Expected object key');
        const k = str(); if (keys.has(k)) throw invalid('Duplicate JSON key'); keys.add(k);
        ws(); if (text[i++] !== ':') throw invalid('Expected colon'); out[k] = read(depth + 1); ws();
        const end = text[i++]; if (end === '}') return out; if (end !== ',') throw invalid('Expected comma');
      }
    } else if (c === '[') {
      i++; ws(); const out = []; if (text[i] === ']') { i++; return out; }
      while (i < text.length) {
        out.push(read(depth + 1)); if (out.length > 10000) throw invalid('Array too long'); ws();
        const end = text[i++]; if (end === ']') return out; if (end !== ',') throw invalid('Expected comma');
      }
    } else {
      for (const [word, val] of [['true', true], ['false', false], ['null', null]]) {
        if (text.slice(i, i + word.length) === word) { i += word.length; return val; }
      }
      const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i));
      if (m) { i += m[0].length; return Number(m[0]); }
    }
    throw invalid('Invalid JSON');
  }
  const value = read(0); ws(); if (i !== text.length) throw invalid('Trailing JSON data');
  canonical(value); return value;
}
