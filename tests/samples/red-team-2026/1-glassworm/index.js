// GlassWorm-style invisible Unicode variation selectors payload encoding.
// Pattern reproduction for muaddib audit 2026-05 / Phase 2 — NOT a working exploit.
// Variation selectors U+FE00 .. U+FE0F encode 1 nibble each (0..15).

function decodeVS(carrier) {
  // For each char in carrier, examine following variation selectors and decode bytes.
  const bytes = [];
  let nibbles = [];
  for (let i = 0; i < carrier.length; i++) {
    const cp = carrier.codePointAt(i);
    if (cp >= 0xFE00 && cp <= 0xFE0F) {
      nibbles.push(cp - 0xFE00);
      if (nibbles.length === 2) {
        bytes.push((nibbles[0] << 4) | nibbles[1]);
        nibbles = [];
      }
    }
  }
  return String.fromCharCode(...bytes);
}

// Carrier string contains hidden variation selectors. Decoded payload = 'log("ok")'
// (audit benign placeholder — real GlassWorm carriers decode to obfuscated exfil).
const carrier = 'a︆︌︆️︆︇︂︈︂︂︆️︆︋︂︂︂︉';
const payload = decodeVS(carrier);

// Indirect eval via Function constructor — same primitive, different shape.
const fn = new Function('console', payload);
fn(console);

module.exports = { decodeVS };
