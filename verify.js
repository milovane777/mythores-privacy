// Mythores pet token — second implementation of docs/spec/pet-token-v1.md.
// Plain JavaScript, no dependencies beyond WebCrypto. Runs in a browser and in
// Node (>= 20). Everything here is checked against the Dart reference by
// check.mjs; the page (index.html) inlines this file unchanged.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.MythoresToken = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const STANDARD = 'mythores.pet.v1';
  const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const subtle = (typeof crypto !== 'undefined' && crypto.subtle) ? crypto.subtle
    : (typeof require === 'function' ? require('crypto').webcrypto.subtle : null);

  // ---- bytes ---------------------------------------------------------------
  const enc = new TextEncoder();
  function b64uToBytes(s) {
    if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('not base64url');
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4);
    const bin = typeof atob === 'function' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64u(bytes) {
    let bin = ''; for (const b of bytes) bin += String.fromCharCode(b);
    const b64 = typeof btoa === 'function' ? btoa(bin) : Buffer.from(bin, 'binary').toString('base64');
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function hex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
  async function sha256(bytes) { return new Uint8Array(await subtle.digest('SHA-256', bytes)); }
  function concat(a, b) { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }

  // ---- canonical JSON (§1): sorted keys, no spaces, no floats -----------------
  function canonical(v) {
    if (v === null || typeof v === 'boolean' || typeof v === 'number') return JSON.stringify(v);
    if (typeof v === 'string') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }

  // ---- signatures ----------------------------------------------------------
  async function ed25519Verify(pubB64u, message, sigB64u) {
    const pub = b64uToBytes(pubB64u), sig = b64uToBytes(sigB64u);
    if (pub.length !== 32 || sig.length !== 64) return false;
    if (bytesToB64u(pub) !== pubB64u || bytesToB64u(sig) !== sigB64u) return false; // canonical encoding only
    try {
      const key = await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify({ name: 'Ed25519' }, key, sig, message);
    } catch (e) { return false; }
  }

  // ---- identity (§2, §3) ---------------------------------------------------
  const SIGNED_KEYS = ['birth', 'gen', 'genesis_device', 'genesis_pubkey', 'issue', 'marking',
    'palette', 'rarity', 'region', 'season', 'serial', 'shiny', 'species', 'traits'];
  function identityMap(doc) {
    const m = {};
    for (const k of SIGNED_KEYS) {
      if (k === 'issue') { if (doc.issue && typeof doc.issue.number === 'number') m.issue = doc.issue.number; continue; }
      if ((k === 'marking' || k === 'region') && doc[k] === undefined) continue;
      m[k] = doc[k];
    }
    return m;
  }
  async function installIdFor(pubB64u) {
    const d = await sha256(concat(enc.encode('MYTHORES-INSTALL'), b64uToBytes(pubB64u)));
    return hex(d.subarray(0, 8));
  }
  async function shortSig(sigB64u) {
    const d = await sha256(b64uToBytes(sigB64u));
    let s = ''; for (let i = 0; i < 8; i++) s += CROCKFORD[d[i] % 32];
    return s;
  }
  async function petId(doc, registry) {
    const sp = registry.species.find(s => s.key === doc.species);
    const tier = registry.rarities.find(r => r.key === doc.rarity);
    if (!sp || !tier) return null;
    return `MY-${doc.season}-${sp.code}-${tier.code}-${await installIdFor(doc.genesis_pubkey)}-` +
      `${String(doc.serial).padStart(6, '0')}-${await shortSig(doc.genesis_sig)}`;
  }

  // ---- verification (§8) ---------------------------------------------------
  // "26S3" from an ISO instant, the way lib/domain/season.dart does it.
  function seasonOf(at) {
    const d = new Date(at);
    const yy = String(d.getUTCFullYear() % 100).padStart(2, '0');
    return `${yy}S${Math.floor(d.getUTCMonth() / 3) + 1}`;
  }

  // The grade curve, mirroring Grade.scoreOf in lib/domain/grade.dart. Bands
  // come from the registry rather than being copied, so the two cannot drift.
  function gradeOf(sweeps, neglect, registry) {
    const g = registry.grade;
    let score = g.min;
    for (const [from, step] of g.sweep_bands) {
      if (sweeps >= from) { score = step; break; }
    }
    for (const [from, penalty] of g.neglect_bands) {
      if (neglect >= from) { score -= penalty; break; }
    }
    return Math.min(g.max, Math.max(g.min, score));
  }

  async function verify(doc, registry) {
    const out = { ok: false, reasons: [], id: null, contentHash: null, owner: null };
    if (!doc || doc.standard !== STANDARD) { out.reasons.push('standard'); return out; }
    const canon = canonical(doc);
    out.contentHash = hex(await sha256(enc.encode(canon)));
    const idm = identityMap(doc);
    if (!(await ed25519Verify(doc.genesis_pubkey, enc.encode(canonical(idm)), doc.genesis_sig))) out.reasons.push('genesis_sig');
    if (doc.genesis_device !== await installIdFor(doc.genesis_pubkey)) out.reasons.push('device_key_mismatch');
    out.id = await petId(doc, registry);
    if (out.id !== doc.id) out.reasons.push('id');
    if (!/^\d{2}S[1-4]$/.test(doc.season || '')) out.reasons.push('season');
    if (!(Number.isInteger(doc.palette) && doc.palette >= 0 && doc.palette < 16)) out.reasons.push('palette');
    if (!(Number.isInteger(doc.serial) && doc.serial >= 1 && doc.serial <= 999999)) out.reasons.push('serial');
    if (!Array.isArray(doc.traits) || doc.traits.length !== 2 || doc.traits[0] === doc.traits[1]) out.reasons.push('traits');
    // §4 provenance
    const links = Array.isArray(doc.provenance) ? doc.provenance : [];
    if (links.length > 12) out.reasons.push('chain_length');
    let from = doc.genesis_pubkey;
    for (let i = 0; i < links.length; i++) {
      const l = links[i];
      if (l.from !== from) { out.reasons.push(`chain[${i}].from`); break; }
      if (!(await ed25519Verify(l.from, enc.encode(`MYOFFER|${doc.id}|${l.nonce}|${l.exp}`), l.sig_from))) out.reasons.push(`chain[${i}].sig_from`);
      if (!(await ed25519Verify(l.to, enc.encode(`MYACCEPT|${doc.id}|${l.nonce}|${l.to}|${l.at}`), l.sig_to))) out.reasons.push(`chain[${i}].sig_to`);
      if (!(l.at <= l.exp)) out.reasons.push(`chain[${i}].expired`);
      from = l.to;
    }
    out.owner = from;
    // §2.1 awakening: appended and signed by somebody who has held the pet.
    if (doc.awakening) {
      const w = doc.awakening;
      const owners = [doc.genesis_pubkey, ...links.map(l => l.to)];
      if (!owners.includes(w.by)) out.reasons.push('awakening.by');
      const msg = `MYAWAKE|${doc.id}|${w.form}|${w.at}|${w.by}|${w.xp}|${w.care}`;
      if (!(await ed25519Verify(w.by, enc.encode(msg), w.sig))) out.reasons.push('awakening.sig');
      if (!registry.awakened.forms.includes(w.form)) out.reasons.push('awakening.form');
      if (doc.rarity === registry.awakened.top_tier) out.reasons.push('awakening.top_tier');
      if (!(Number.isInteger(w.xp) && w.xp >= registry.awakened.min_xp)) out.reasons.push('awakening.xp');
      if (!(Number.isInteger(w.care) && w.care >= registry.awakened.min_care)) out.reasons.push('awakening.care');
    }
    // §2.2 grades: condition, pinned and signed by an owner, one per season.
    // The evidence is signed beside the verdict, so a reader that has never
    // seen the app can redo the arithmetic instead of trusting the grader.
    const grades = Array.isArray(doc.grades) ? doc.grades : [];
    if (grades.length > registry.grade.max_per_pet) out.reasons.push('grades.too_many');
    const gradeSeasons = new Set();
    for (const g of grades) {
      const owners = [doc.genesis_pubkey, ...links.map(l => l.to)];
      if (!owners.includes(g.by)) out.reasons.push('grades.by');
      if (!(Number.isInteger(g.grade) && g.grade >= registry.grade.min && g.grade <= registry.grade.max)) {
        out.reasons.push('grades.range');
      }
      if (gradeOf(g.sweeps, g.neglect, registry) !== g.grade) out.reasons.push('grades.arithmetic');
      const season = seasonOf(g.at);
      if (gradeSeasons.has(season)) out.reasons.push('grades.season_twice');
      gradeSeasons.add(season);
      const msg = `MYGRADE|${doc.id}|${g.grade}|${g.at}|${g.by}|${g.sweeps}|${g.neglect}`;
      if (!(await ed25519Verify(g.by, enc.encode(msg), g.sig))) out.reasons.push('grades.sig');
    }
    out.grade = grades.length ? grades[grades.length - 1].grade : 0;
    // §2.3 witnesses: signed by somebody who is *not* an owner, one line per
    // key. Nothing here requires the signer to have held the pet — that is the
    // whole point of an outside opinion.
    const witnesses = Array.isArray(doc.witnesses) ? doc.witnesses : [];
    if (witnesses.length > registry.witness.max_per_pet) out.reasons.push('witnesses.too_many');
    const seenKeys = new Set();
    for (const w of witnesses) {
      if (seenKeys.has(w.by)) out.reasons.push('witnesses.twice');
      seenKeys.add(w.by);
      if (!registry.regions.some(r => r.key === w.band)) out.reasons.push('witnesses.band');
      const msg = `MYWIT|${doc.id}|${w.hash}|${w.band}|${w.at}|${w.by}`;
      if (!(await ed25519Verify(w.by, enc.encode(msg), w.sig))) out.reasons.push('witnesses.sig');
    }
    out.witnesses = witnesses.length;
    out.bands = [...new Set(witnesses.map(w => w.band))];
    out.ok = out.reasons.length === 0;
    return out;
  }

  // ---- colour (§5), mirroring lib/domain/art/colour.dart -------------------
  function argb(a, r, g, b) { return ((a & 255) << 24 | (r & 255) << 16 | (g & 255) << 8 | (b & 255)) >>> 0; }
  const A = c => (c >>> 24) & 255, R = c => (c >>> 16) & 255, G = c => (c >>> 8) & 255, B = c => c & 255;
  function fromHex(h) { return (0xFF000000 | parseInt(h.slice(1), 16)) >>> 0; }
  function toHex(c) { return '#' + [R(c), G(c), B(c)].map(x => x.toString(16).padStart(2, '0')).join(''); }
  function toHsl(c) {
    const r = R(c) / 255, g = G(c) / 255, b = B(c) / 255;
    const max = Math.max(r, g, b), min = Math.min(r, g, b), d = max - min, l = (max + min) / 2;
    if (d === 0) return [0, 0, l];
    const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    let h;
    if (max === r) h = (g - b) / d + (g < b ? 6 : 0);
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    return [h * 60, s, l];
  }
  function fromHsl(a, h, s, l) {
    if (s === 0) { const v = Math.round(l * 255); return argb(a, v, v, v); }
    const q = l < 0.5 ? l * (1 + s) : l + s - l * s, p = 2 * l - q, hk = ((h % 360) + 360) % 360 / 360;
    const ch = t => { if (t < 0) t += 1; if (t > 1) t -= 1;
      if (t < 1 / 6) return p + (q - p) * 6 * t; if (t < 1 / 2) return q;
      if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6; return p; };
    return argb(a, Math.round(ch(hk + 1 / 3) * 255), Math.round(ch(hk) * 255), Math.round(ch(hk - 1 / 3) * 255));
  }
  const clamp01 = x => Math.min(1, Math.max(0, x));
  function shift(c, amount, desat) {
    const [h, s, l] = toHsl(c);
    return fromHsl(A(c), h, clamp01(s - (desat || 0)), clamp01(l + amount));
  }
  function withOpacity(c, o) { return argb(Math.round(clamp01(o) * 255), R(c), G(c), B(c)); }
  function over(under, top) {
    const a = A(top) / 255;
    if (a >= 1) return (top | 0xFF000000) >>> 0;
    if (a <= 0) return under;
    const mix = (u, t) => Math.min(255, Math.max(0, Math.round(u + (t - u) * a)));
    return argb(A(under), mix(R(under), R(top)), mix(G(under), G(top)), mix(B(under), B(top)));
  }
  function mixRgb(a, b, t) {
    const ch = (x, y) => Math.min(255, Math.max(0, Math.round(x + (y - x) * t)));
    return argb(255, ch(R(a), R(b)), ch(G(a), G(b)), ch(B(a), B(b)));
  }

  // ---- palette resolution, mirroring Palettes.of ---------------------------
  function paletteFor(doc, sp, registry) {
    const base = doc.shiny ? sp.shiny : sp.palettes[Math.min(15, Math.max(0, doc.palette | 0))];
    let p = { body: fromHex(base.body), accent: fromHex(base.accent), belly: fromHex(base.belly), cheek: fromHex(base.cheek) };
    const awakenedForm = doc.awakening && doc.awakening.form;
    if (awakenedForm && registry.awakened[awakenedForm]) {
      const pull = fromHex(registry.awakened[awakenedForm].pull), m = registry.awakened.mix;
      p = { body: mixRgb(p.body, pull, m.body), accent: mixRgb(p.accent, pull, m.accent), belly: mixRgb(p.belly, pull, m.belly), cheek: p.cheek };
    }
    if (doc.region) {
      const reg = registry.regions.find(r => r.key === doc.region);
      if (reg) { const pull = fromHex(reg.pull), m = registry.region_mix;
        p = { body: mixRgb(p.body, pull, m.body), accent: mixRgb(p.accent, pull, m.accent), belly: mixRgb(p.belly, pull, m.belly), cheek: p.cheek }; }
    }
    return p;
  }
  function slotColours(p) {
    return { o: shift(p.body, -0.34, 0.45), b: p.body, s: shift(p.body, -0.10), h: shift(p.body, 0.10),
      l: p.belly, a: p.accent, e: 0xFF2E2630 >>> 0, w: 0xFFFFFFFF >>> 0, c: p.cheek };
  }

  // ---- compose + SVG, mirroring Sprite.compose and PixelSvg.render --------
  function compose(doc, registry) {
    const sp = registry.species.find(s => s.key === doc.species);
    if (!sp) throw new Error('unknown species ' + doc.species);
    const p = paletteFor(doc, sp, registry), colours = slotColours(p), n = sp.grid.length;
    const px = sp.grid.map(row => Array.from({ length: n }, (_, x) => {
      const ch = row[x]; if (ch === undefined || ch === '.') return 0;
      return colours[ch] !== undefined ? colours[ch] : colours.b;
    }));
    const marking = doc.marking || 'plain';
    const dots = (sp.markings && sp.markings[marking]) || [];
    for (const [x, y, pi] of dots) {
      const paint = registry.marking_paints[pi];
      const top = paint.ink ? withOpacity(p.accent, paint.alpha) : withOpacity(fromHex(paint.rgb), paint.alpha);
      px[y][x] = over(px[y][x], top);
    }
    return px;
  }
  function svg(px) {
    const n = px.length, paths = new Map();
    for (let y = 0; y < n; y++) {
      const row = px[y]; let x = 0;
      while (x < row.length) {
        const c = row[x]; if (c === 0) { x++; continue; }
        let end = x + 1; while (end < row.length && row[end] === c) end++;
        if (!paths.has(c)) paths.set(c, '');
        paths.set(c, paths.get(c) + `M${x} ${y}h${end - x}v1h-${end - x}z`);
        x = end;
      }
    }
    let out = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n} ${n}" width="${n}" height="${n}" shape-rendering="crispEdges">`;
    for (const [c, d] of paths) {
      out += `<path fill="${toHex(c)}"`;
      if (A(c) < 255) out += ` fill-opacity="${(A(c) / 255).toFixed(3)}"`;
      out += ` d="${d}"/>`;
    }
    return out + '</svg>';
  }

  return { STANDARD, canonical, verify, compose, svg, petId, installIdFor, shortSig, sha256, hex, b64uToBytes };
}));
