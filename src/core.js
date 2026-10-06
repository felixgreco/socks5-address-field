/**
 * Address type constants as used on the wire in RFC 1928.
 * Kept here (not exported separately) so parsers and serializers share one source of truth.
 */
export const ADDR_TYPE = Object.freeze({
  IPV4: 0x01,
  DOMAIN: 0x03,
  IPV6: 0x04,
});

// Single byte values, so a plain lookup avoids repeated buffer reads.
const TYPE_BY_BYTE = Object.freeze({
  0x01: 'ipv4',
  0x03: 'domain',
  0x04: 'ipv6',
});

// Avoid re-validating bytes manually; the parser trusts a whitelist and
// rejects anything else, which keeps the surface area small and explicit.
const BYTE_BY_TYPE = Object.freeze({
  ipv4: ADDR_TYPE.IPV4,
  domain: ADDR_TYPE.DOMAIN,
  ipv6: ADDR_TYPE.IPV6,
});

// All socket addresses we support fit in 16 bytes; a domain is capped at 255.
// A single pre-allocated ArrayBuffer lets both writers reuse one view without
// per-call allocation, which matters when many packets flow through one socket.
const MAX_ADDRESS_BYTES = 255; // covers IPv6 (16) and the domain length byte's full range
const scratch = new ArrayBuffer(1 + 1 + MAX_ADDRESS_BYTES + 2);

/**
 * Convert four numeric octets into a dotted-quad string.
 * Kept here rather than relying on Node's net module so the library has no
 * runtime dependency beyond TypedArrays.
 *
 * @param {number} a - first octet (0-255)
 * @param {number} b - second octet
 * @param {number} c - third octet
 * @param {number} d - fourth octet
 * @returns {string}
 */
function ipv4ToString(a, b, c, d) {
  return `${a}.${b}.${c}.${d}`;
}

/**
 * Serialize the host part of a 16-byte IPv6 address to canonical text form.
 * This is a minimal implementation: it does NOT collapse the longest run of
 * zero groups into '::'. The brief is the wire format, not text normalization;
 * supporting compression would roughly double the code and its test surface
 * for no benefit in round-tripping back to bytes.
 *
 * @param {Uint8Array} bytes - exactly 16 bytes in network byte order
 * @returns {string}
 */
function ipv6ToString(bytes) {
  let out = '';
  for (let i = 0; i < 16; i += 2) {
    const group = (bytes[i] << 8) | bytes[i + 1];
    if (i > 0) out += ':';
    out += group.toString(16);
  }
  return out;
}

/**
 * Parse a dotted-quad string into four numeric octets.
 * Strict on shape: exactly four groups, each 0-255, no leading '+'/'-',
 * no octal/hex. We choose strict over permissive because the only producer of
 * these strings inside this library is our own writer, and the only external
 * producer should be application code that already knows the format.
 *
 * @param {string} text
 * @returns {{ok: true, value: [number, number, number, number]} | {ok: false, error: string}}
 */
function parseIpv4(text) {
  const parts = text.split('.');
  if (parts.length !== 4) {
    return { ok: false, error: `invalid IPv4 address: ${text}` };
  }
  const out = [0, 0, 0, 0];
  for (let i = 0; i < 4; i++) {
    const s = parts[i];
    if (s.length === 0 || s.length > 3 || !/^\d+$/.test(s)) {
      return { ok: false, error: `invalid IPv4 octet: ${s}` };
    }
    const n = Number(s);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      return { ok: false, error: `IPv4 octet out of range: ${s}` };
    }
    out[i] = n;
  }
  return { ok: true, value: out };
}

/**
 * Parse a (possibly compressed) IPv6 text form into 16 bytes.
 * We DO support '::' compression because callers frequently paste RFC 4291
 * text (e.g. 'fe80::1') and rejecting compression would make the parser
 * unusable for the most common human input. The cost is bounded: at most one
 * '::', expanded against the 8-group total.
 *
 * @param {string} text
 * @returns {{ok: true, value: Uint8Array} | {ok: false, error: string}}
 */
function parseIpv6(text) {
  if (text.length === 0) {
    return { ok: false, error: 'empty IPv6 address' };
  }
  let halves;
  if (text.indexOf('::') !== text.lastIndexOf('::')) {
    return { ok: false, error: 'multiple :: in IPv6 address' };
  }
  const hasDoubleColon = text.indexOf('::') !== -1;
  if (hasDoubleColon) {
    halves = text.split('::');
  } else {
    halves = [text];
  }

  const head = halves[0];
  const tail = halves.length > 1 ? halves[1] : '';
  const headParts = head.length === 0 ? [] : head.split(':');
  const tailParts = tail.length === 0 ? [] : tail.split(':');

  // Reject empty groups that are NOT the '::' form, e.g. '1::2::3' (handled above)
  // or '1:::' style trailing colons from a bad split. Each side must be either
  // empty or a sequence of non-empty hex groups.
  for (const p of headParts) {
    if (p.length === 0) return { ok: false, error: `empty group in IPv6: ${text}` };
  }
  for (const p of tailParts) {
    if (p.length === 0) return { ok: false, error: `empty group in IPv6: ${text}` };
  }

  const total = headParts.length + tailParts.length;
  if (total > 8) return { ok: false, error: `too many groups in IPv6: ${text}` };
  if (!hasDoubleColon && total !== 8) {
    return { ok: false, error: `IPv6 without :: must have 8 groups: ${text}` };
  }
  const fillCount = 8 - total; // groups supplied by '::'
  if (fillCount < 0) return { ok: false, error: `too many groups in IPv6: ${text}` };

  const out = new Uint8Array(16);
  let idx = 0;
  for (const p of headParts) {
    const r = parseHexGroup(p);
    if (!r.ok) return r;
    out[idx++] = (r.value >> 8) & 0xff;
    out[idx++] = r.value & 0xff;
  }
  idx += fillCount * 2; // leave zeros in place
  for (const p of tailParts) {
    const r = parseHexGroup(p);
    if (!r.ok) return r;
    out[idx++] = (r.value >> 8) & 0xff;
    out[idx++] = r.value & 0xff;
  }
  return { ok: true, value: out };
}

/**
 * Parse a single 16-bit hex group, 1-4 digits.
 * @param {string} s
 * @returns {{ok: true, value: number} | {ok: false, error: string}}
 */
function parseHexGroup(s) {
  if (s.length === 0 || s.length > 4 || !/^[0-9a-fA-F]+$/.test(s)) {
    return { ok: false, error: `invalid IPv6 group: ${s}` };
  }
  const n = parseInt(s, 16);
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
    return { ok: false, error: `IPv6 group out of range: ${s}` };
  }
  return { ok: true, value: n };
}

/**
 * Parse the variable-length SOCKS5 ATYP+address field starting at `offset`.
 * Reads a single type byte, then the type-appropriate body. Does NOT consume
 * the trailing two port bytes; the caller handles those, since the port is
 * outside the scope of this library's named concern.
 *
 * Returns either {ok:true, ...} on success or {ok:false, error} on failure.
 * We do not throw: SOCKS parsers frequently run inside tight loops over many
 * packets, and a thrown exception for a single malformed byte would force
 * callers to wrap every call. An explicit result type keeps the contract
 * legible at the call site.
 *
 * @param {Uint8Array} buffer - the full packet
 * @param {number} [offset=0] - index of the ATYP byte
 * @returns {{ok: true, type: string, address: string, bytesRead: number} | {ok: false, error: string}}
 */
export function parseAddress(buffer, offset = 0) {
  if (!(buffer instanceof Uint8Array)) {
    return { ok: false, error: 'buffer must be a Uint8Array' };
  }
  if (!Number.isInteger(offset) || offset < 0) {
    return { ok: false, error: 'offset must be a non-negative integer' };
  }
  if (offset >= buffer.length) {
    return { ok: false, error: 'offset is at end of buffer' };
  }
  const atyp = buffer[offset];
  const type = TYPE_BY_BYTE[atyp];
  if (!type) {
    return { ok: false, error: `unknown ATYP byte: 0x${atyp.toString(16).padStart(2, '0')}` };
  }

  if (type === 'ipv4') {
    if (offset + 1 + 4 > buffer.length) {
      return { ok: false, error: 'truncated IPv4 address' };
    }
    const a = buffer[offset + 1];
    const b = buffer[offset + 2];
    const c = buffer[offset + 3];
    const d = buffer[offset + 4];
    return { ok: true, type, address: ipv4ToString(a, b, c, d), bytesRead: 1 + 4 };
  }

  if (type === 'ipv6') {
    if (offset + 1 + 16 > buffer.length) {
      return { ok: false, error: 'truncated IPv6 address' };
    }
    const bytes = buffer.subarray(offset + 1, offset + 1 + 16);
    return { ok: true, type, address: ipv6ToString(bytes), bytesRead: 1 + 16 };
  }

  // type === 'domain'
  if (offset + 1 + 1 > buffer.length) {
    return { ok: false, error: 'truncated domain length' };
  }
  const len = buffer[offset + 1];
  if (offset + 1 + 1 + len > buffer.length) {
    return { ok: false, error: 'truncated domain name' };
  }
  // Domain names in SOCKS5 are raw bytes; we decode as UTF-8 to be friendly to
  // callers handling IDN or ASCII hostnames. Bytes that are not valid UTF-8 are
  // replaced with U+FFFD so the parser never throws on a hostile packet.
  const domainBytes = buffer.subarray(offset + 1 + 1, offset + 1 + 1 + len);
  const address = new TextDecoder('utf-8', { fatal: false }).decode(domainBytes);
  return { ok: true, type, address, bytesRead: 1 + 1 + len };
}

/**
 * Serialize a host specification into the SOCKS5 ATYP+address wire form,
 * without a trailing port. The caller appends the two port bytes itself.
 *
 * The function decides the type from `type` when provided; otherwise it infers
 * the type by attempting IPv4, then IPv6 parse, and falling back to domain.
 * Inference is a convenience for callers that have a bare string; production
 * code that knows the type should pass it explicitly to avoid the IPv4 regex
 * path on every call.
 *
 * @param {string|Uint8Array} host
 * @param {('ipv4'|'domain'|'ipv6')} [type]
 * @returns {{ok: true, bytes: Uint8Array} | {ok: false, error: string}}
 */
export function serializeAddress(host, type) {
  if (type !== undefined && type !== 'ipv4' && type !== 'domain' && type !== 'ipv6') {
    return { ok: false, error: `unknown address type: ${type}` };
  }

  // Allow callers that already have bytes (e.g. a parsed IPv6 from elsewhere)
  // to skip the text round-trip. Only exact-length IPv4 (4) and IPv6 (16)
  // byte buffers are accepted; anything else is a misuse.
  if (host instanceof Uint8Array) {
    if (type === undefined) {
      return { ok: false, error: 'type is required when host is a Uint8Array' };
    }
    if (type === 'ipv4') {
      if (host.length !== 4) return { ok: false, error: 'IPv4 byte length must be 4' };
      return { ok: true, bytes: buildFromBytes(ADDR_TYPE.IPV4, host) };
    }
    if (type === 'ipv6') {
      if (host.length !== 16) return { ok: false, error: 'IPv6 byte length must be 16' };
      return { ok: true, bytes: buildFromBytes(ADDR_TYPE.IPV6, host) };
    }
    return { ok: false, error: 'byte-array host is only valid for ipv4 or ipv6' };
  }

  if (typeof host !== 'string') {
    return { ok: false, error: 'host must be a string or Uint8Array' };
  }
  if (host.length === 0) {
    return { ok: false, error: 'host must not be empty' };
  }

  let resolvedType = type;
  if (resolvedType === undefined) {
    const v4 = parseIpv4(host);
    if (v4.ok) resolvedType = 'ipv4';
    else {
      const v6 = parseIpv6(host);
      if (v6.ok) resolvedType = 'ipv6';
      else resolvedType = 'domain';
    }
  }

  if (resolvedType === 'ipv4') {
    const r = parseIpv4(host);
    if (!r.ok) return r;
    const bytes = new Uint8Array(1 + 4);
    bytes[0] = ADDR_TYPE.IPV4;
    bytes[1] = r.value[0];
    bytes[2] = r.value[1];
    bytes[3] = r.value[2];
    bytes[4] = r.value[3];
    return { ok: true, bytes };
  }

  if (resolvedType === 'ipv6') {
    const r = parseIpv6(host);
    if (!r.ok) return r;
    const bytes = new Uint8Array(1 + 16);
    bytes[0] = ADDR_TYPE.IPV6;
    bytes.set(r.value, 1);
    return { ok: true, bytes };
  }

  // domain
  if (host.length > 255) {
    return { ok: false, error: `domain name too long (${host.length} > 255)` };
  }
  const encoded = new TextEncoder().encode(host);
  if (encoded.length > 255) {
    return { ok: false, error: `domain name encodes to ${encoded.length} bytes (> 255)` };
  }
  const bytes = new Uint8Array(1 + 1 + encoded.length);
  bytes[0] = ADDR_TYPE.DOMAIN;
  bytes[1] = encoded.length;
  bytes.set(encoded, 2);
  return { ok: true, bytes };
}

/**
 * Build a type-prefixed byte sequence from raw address bytes (no length byte).
 * Used by the Uint8Array fast path for ipv4/ipv6.
 * @param {number} atyp
 * @param {Uint8Array} addr
 */
function buildFromBytes(atyp, addr) {
  const bytes = new Uint8Array(1 + addr.length);
  bytes[0] = atyp;
  bytes.set(addr, 1);
  return bytes;
}
