# socks5-address-field

Serialize and parse the variable-length ATYP+address field used in SOCKS5 request and reply packets (RFC 1928). The library handles the address field only; the trailing two-byte port is left to the caller.

## Usage

```js
import { parseAddress, serializeAddress, ADDR_TYPE } from 'socks5-address-field';

// Parse: bytes 0..4 are ATYP + 4 octets
const parsed = parseAddress(new Uint8Array([ADDR_TYPE.IPV4, 192, 168, 1, 10]), 0);
if (parsed.ok) {
  console.log(parsed.type);    // 'ipv4'
  console.log(parsed.address); // '192.168.1.10'
  console.log(parsed.bytesRead); // 5
}

// Serialize: produce ATYP+address bytes, no port
const out = serializeAddress('proxy.example.net', 'domain');
if (out.ok) {
  // out.bytes: [0x03, 16, ...UTF-8 bytes of the hostname]
}
```

## Exports

- `parseAddress(buffer, offset = 0)` — `{ ok, type, address, bytesRead }` on success, `{ ok: false, error }` on failure. `type` is one of `'ipv4'`, `'domain'`, `'ipv6'`.
- `serializeAddress(host, type?)` — `{ ok, bytes }` on success, `{ ok: false, error }` on failure. `host` is a string or, for `ipv4`/`ipv6`, a `Uint8Array` of 4 or 16 bytes. If `type` is omitted, the type is inferred by attempting IPv4 then IPv6 parse, falling back to `domain`.
- `ADDR_TYPE` — frozen object `{ IPV4: 0x01, DOMAIN: 0x03, IPV6: 0x04 }`.

## Why this exists

Every SOCKS5 implementation ends up re-implementing the same three-branch address codec. This library isolates that logic so it can be tested once and reused. The trade-off is scope: it deliberately does not parse the full SOCKS5 header, does not validate the port, and does not round-trip the textual form of IPv6 addresses.

## The awkward edge

IPv6 text is parsed with full `::` compression support, but the *serializer emits the uncompressed 16-byte form*, and the parser emits the corresponding non-compressed text (`2001:db8:0:0:0:0:0:1`, not `2001:db8::1`). If your code compares the original text to the round-tripped text, it will not match even though the bytes are identical. Compare bytes, or compare against the canonical non-compressed form.

Domain names are decoded as UTF-8 with replacement (`U+FFFD`) rather than rejected, so a packet containing non-UTF-8 octets parses without throwing. Callers that need byte-exact domain handling should read the raw bytes from the input buffer rather than relying on the decoded `address` string.
