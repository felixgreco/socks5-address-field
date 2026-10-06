import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAddress, serializeAddress, ADDR_TYPE } from '../src/index.js';

/** Helper: concatenate a list of Uint8Array views into a new buffer. */
function concat(arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

test('parses a well-formed IPv4 address field', () => {
  const buf = new Uint8Array([ADDR_TYPE.IPV4, 192, 168, 1, 10]);
  const r = parseAddress(buf, 0);
  assert.equal(r.ok, true);
  assert.equal(r.type, 'ipv4');
  assert.equal(r.address, '192.168.1.10');
  assert.equal(r.bytesRead, 5);
});

test('parses an IPv4 field that does not start at offset 0', () => {
  const prefix = new Uint8Array([0x05, 0x01, 0x00]);
  const addr = new Uint8Array([ADDR_TYPE.IPV4, 10, 0, 0, 1]);
  const buf = concat([prefix, addr]);
  const r = parseAddress(buf, prefix.length);
  assert.equal(r.ok, true);
  assert.equal(r.address, '10.0.0.1');
  assert.equal(r.bytesRead, 5);
});

test('parses a domain field with a one-octet length prefix', () => {
  const name = 'proxy.example.net';
  const enc = new TextEncoder().encode(name);
  const buf = new Uint8Array(1 + 1 + enc.length);
  buf[0] = ADDR_TYPE.DOMAIN;
  buf[1] = enc.length;
  buf.set(enc, 2);
  const r = parseAddress(buf, 0);
  assert.equal(r.ok, true);
  assert.equal(r.type, 'domain');
  assert.equal(r.address, name);
  assert.equal(r.bytesRead, 1 + 1 + enc.length);
});

test('parses a 255-byte domain at the length-prefix limit', () => {
  const name = 'a'.repeat(255);
  const enc = new TextEncoder().encode(name);
  const buf = new Uint8Array(1 + 1 + enc.length);
  buf[0] = ADDR_TYPE.DOMAIN;
  buf[1] = enc.length;
  buf.set(enc, 2);
  const r = parseAddress(buf, 0);
  assert.equal(r.ok, true);
  assert.equal(r.type, 'domain');
  assert.equal(r.address, name);
  assert.equal(r.bytesRead, 1 + 1 + enc.length);
});

test('parses an IPv6 field (canonical, no compression)', () => {
  const groups = [0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001];
  const buf = new Uint8Array(1 + 16);
  buf[0] = ADDR_TYPE.IPV6;
  let i = 1;
  for (const g of groups) {
    buf[i++] = (g >> 8) & 0xff;
    buf[i++] = g & 0xff;
  }
  const r = parseAddress(buf, 0);
  assert.equal(r.ok, true);
  assert.equal(r.type, 'ipv6');
  assert.equal(r.address, '2001:db8:0:0:0:0:0:1');
  assert.equal(r.bytesRead, 17);
});

test('rejects an unknown ATYP byte', () => {
  const buf = new Uint8Array([0x00, 1, 2, 3, 4]);
  const r = parseAddress(buf, 0);
  assert.equal(r.ok, false);
  assert.match(r.error, /unknown ATYP byte: 0x00/);
});

test('rejects a truncated IPv4 field', () => {
  const buf = new Uint8Array([ADDR_TYPE.IPV4, 192, 168, 1]);
  const r = parseAddress(buf, 0);
  assert.equal(r.ok, false);
  assert.match(r.error, /truncated IPv4/);
});

test('rejects a truncated IPv6 field', () => {
  const buf = new Uint8Array([ADDR_TYPE.IPV6, 0x20, 0x01]);
  const r = parseAddress(buf, 0);
  assert.equal(r.ok, false);
  assert.match(r.error, /truncated IPv6/);
});

test('rejects a truncated domain length byte', () => {
  const buf = new Uint8Array([ADDR_TYPE.DOMAIN]);
  const r = parseAddress(buf, 0);
  assert.equal(r.ok, false);
  assert.match(r.error, /truncated domain length/);
});

test('rejects a truncated domain body', () => {
  const buf = new Uint8Array([ADDR_TYPE.DOMAIN, 5, 97, 98, 99]);
  const r = parseAddress(buf, 0);
  assert.equal(r.ok, false);
  assert.match(r.error, /truncated domain name/);
});

test('rejects an offset at end of buffer', () => {
  const buf = new Uint8Array([ADDR_TYPE.IPV4, 1, 2, 3, 4]);
  const r = parseAddress(buf, buf.length);
  assert.equal(r.ok, false);
  assert.match(r.error, /end of buffer/);
});

test('rejects a non-Uint8Array buffer', () => {
  const r = parseAddress([ADDR_TYPE.IPV4, 1, 2, 3, 4], 0);
  assert.equal(r.ok, false);
  assert.match(r.error, /Uint8Array/);
});

test('serializes a dotted-quad string as IPv4', () => {
  const r = serializeAddress('192.168.1.10');
  assert.equal(r.ok, true);
  assert.deepEqual(Array.from(r.bytes), [ADDR_TYPE.IPV4, 192, 168, 1, 10]);
});

test('serializes a domain name with a length prefix', () => {
  const name = 'proxy.example.net';
  const enc = new TextEncoder().encode(name);
  const r = serializeAddress(name, 'domain');
  assert.equal(r.ok, true);
  const expected = [ADDR_TYPE.DOMAIN, enc.length, ...enc];
  assert.deepEqual(Array.from(r.bytes), expected);
});

test('serializes a compressed IPv6 string into 16 bytes', () => {
  const r = serializeAddress('2001:db8::1', 'ipv6');
  assert.equal(r.ok, true);
  assert.equal(r.bytes.length, 17);
  assert.equal(r.bytes[0], ADDR_TYPE.IPV6);
  // Round-trip: parsing the serialized bytes must yield the same 16 address bytes
  // as a freshly constructed canonical buffer.
  const expected = new Uint8Array([
    0x20, 0x01, 0x0d, 0xb8,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
  ]);
  assert.deepEqual(Array.from(r.bytes.subarray(1)), Array.from(expected));
});

test('round-trips IPv4 through serialize then parse', () => {
  const s = serializeAddress('8.8.8.8');
  assert.equal(s.ok, true);
  const p = parseAddress(s.bytes, 0);
  assert.equal(p.ok, true);
  assert.equal(p.type, 'ipv4');
  assert.equal(p.address, '8.8.8.8');
});

test('round-trips an IPv6 address through serialize then parse', () => {
  // Note: parse emits uncompressed form, so we compare against an explicit
  // expected buffer rather than the original compressed text.
  const s = serializeAddress('fe80::1', 'ipv6');
  assert.equal(s.ok, true);
  const p = parseAddress(s.bytes, 0);
  assert.equal(p.ok, true);
  assert.equal(p.type, 'ipv6');
  assert.equal(p.address, 'fe80:0:0:0:0:0:0:1');
});

test('rejects a domain name longer than 255 bytes when serialized', () => {
  const name = 'a'.repeat(256);
  const r = serializeAddress(name, 'domain');
  assert.equal(r.ok, false);
  assert.match(r.error, /too long/);
});

test('rejects an explicitly-typed IPv4 string that is not a valid quad', () => {
  const r = serializeAddress('192.168.1.300', 'ipv4');
  assert.equal(r.ok, false);
  assert.match(r.error, /out of range/);
});

test('rejects an explicitly-typed IPv6 string with too many groups', () => {
  const r = serializeAddress('1:2:3:4:5:6:7:8:9', 'ipv6');
  assert.equal(r.ok, false);
  assert.match(r.error, /too many groups|must have 8 groups/);
});

test('inference falls back to domain when a string is neither IPv4 nor IPv6', () => {
  const r = serializeAddress('not-an-ip.example');
  assert.equal(r.ok, true);
  assert.equal(r.bytes[0], ADDR_TYPE.DOMAIN);
});

test('serializes a Uint8Array host as IPv4 bytes when type is ipv4', () => {
  const r = serializeAddress(new Uint8Array([10, 1, 2, 3]), 'ipv4');
  assert.equal(r.ok, true);
  assert.deepEqual(Array.from(r.bytes), [ADDR_TYPE.IPV4, 10, 1, 2, 3]);
});

test('rejects a Uint8Array host without an explicit type', () => {
  const r = serializeAddress(new Uint8Array([10, 1, 2, 3]));
  assert.equal(r.ok, false);
  assert.match(r.error, /type is required/);
});

test('rejects an empty host string', () => {
  const r = serializeAddress('');
  assert.equal(r.ok, false);
  assert.match(r.error, /must not be empty/);
});
