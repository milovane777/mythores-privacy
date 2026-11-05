// Reads the part of a card link after '#': base64url(gzip(JSON)), the same
// packing the app uses for every code (PackedPayload in lib/domain/transfer.dart).
// Runs in a browser (DecompressionStream) and in Node (zlib). check.mjs proves
// it unpacks exactly what the Dart code packs.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.MythoresCardLink = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Same ceilings as the app: this is reading bytes a stranger produced.
  const MAX_CHARS = 200000;
  const MAX_BYTES = 512 * 1024;

  function b64uToBytes(s) {
    if (!/^[A-Za-z0-9_-]+$/.test(s)) throw new Error('not base64url');
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4);
    if (typeof atob === 'function') return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }

  async function gunzip(bytes) {
    if (typeof DecompressionStream === 'function') {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
      const reader = stream.getReader();
      const parts = []; let size = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > MAX_BYTES) { reader.cancel(); throw new Error('too big'); }
        parts.push(value);
      }
      const out = new Uint8Array(size); let at = 0;
      for (const p of parts) { out.set(p, at); at += p.length; }
      return out;
    }
    const out = require('zlib').gunzipSync(bytes, { maxOutputLength: MAX_BYTES });
    return new Uint8Array(out);
  }

  /// Returns { doc, name } or null. Never throws.
  async function read(fragment) {
    try {
      const s = String(fragment || '').replace(/^#/, '');
      if (!s || s.length > MAX_CHARS) return null;
      const j = JSON.parse(new TextDecoder().decode(await gunzip(b64uToBytes(s))));
      if (!j || j.t !== 'card' || typeof j.doc !== 'object' || j.doc === null) return null;
      return { doc: j.doc, name: typeof j.name === 'string' ? j.name : '' };
    } catch (_) {
      return null;
    }
  }

  return { read };
}));
