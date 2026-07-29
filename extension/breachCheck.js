/**
 * breachCheck.js — HIBP Pwned Passwords breach checker (k-anonymity model).
 *
 * HOW IT WORKS:
 *   1. Compute SHA-1 hash of the plaintext password, uppercase hex.
 *   2. Split into prefix (first 5 chars) + suffix (remaining 35 chars).
 *   3. Send ONLY the prefix to GET https://api.pwnedpasswords.com/range/{prefix}
 *   4. API returns "SUFFIX:COUNT" lines for all hashes sharing that prefix.
 *   5. Locally compare the returned suffixes against our suffix.
 *
 * PRIVACY: The plaintext password and full hash NEVER leave the local machine.
 * Only 5 hex characters of the hash prefix are sent (k-anonymity).
 *
 * OFF BY DEFAULT: The caller (background.js) must check the hibpCheckEnabled
 * setting before calling these functions.
 */

const HIBP_API_BASE = 'https://api.pwnedpasswords.com/range';
const BATCH_THROTTLE_MS = 250;

// v6.6: Bounded LRU cache (max 256 entries). The old unbounded Map could
// grow to 16^5 = 1M entries in a long session — a memory leak. 256 is
// plenty for any realistic vault health scan (max 256 unique 5-char
// SHA-1 prefixes per session), and evicts least-recently-used entries
// when full.
const _prefixCache = new Map();
const PREFIX_CACHE_MAX = 256;

function prefixCacheGet(key) {
  if (!_prefixCache.has(key)) return undefined;
  // Move to end (most recently used) — Map preserves insertion order,
  // so delete + re-set puts it at the end.
  const value = _prefixCache.get(key);
  _prefixCache.delete(key);
  _prefixCache.set(key, value);
  return value;
}

function prefixCacheSet(key, value) {
  if (_prefixCache.has(key)) _prefixCache.delete(key);
  _prefixCache.set(key, value);
  // Evict oldest entry if over capacity (first entry = least recently used)
  if (_prefixCache.size > PREFIX_CACHE_MAX) {
    const oldestKey = _prefixCache.keys().next().value;
    _prefixCache.delete(oldestKey);
  }
}

async function sha1Hex(plaintext) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  data.fill(0);
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function fetchRange(prefix) {
  const url = `${HIBP_API_BASE}/${prefix}`;
  const resp = await fetch(url, {
    headers: {
      'Add-Padding': 'true',
      'User-Agent': 'SecureVault-BreachCheck/1.0',
    },
  });
  if (!resp.ok) throw new Error(`HIBP API returned ${resp.status}`);
  return await resp.text();
}

function parseRangeResponse(text) {
  const map = new Map();
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx < 0) continue;
    const suffix = trimmed.substring(0, colonIdx).toUpperCase();
    const count = parseInt(trimmed.substring(colonIdx + 1), 10);
    if (suffix.length === 35 && !isNaN(count)) {
      map.set(suffix, count);
    }
  }
  return map;
}

export async function checkPwnedPassword(password) {
  if (!password || typeof password !== 'string') {
    return { breached: false, count: 0, error: 'No password provided' };
  }
  let hash;
  try {
    hash = await sha1Hex(password);
  } catch (e) {
    return { breached: false, count: 0, error: 'Hash computation failed: ' + e.message };
  }
  const prefix = hash.substring(0, 5);
  const suffix = hash.substring(5);
  let rangeMap = prefixCacheGet(prefix);
  if (!rangeMap) {
    try {
      const text = await fetchRange(prefix);
      rangeMap = parseRangeResponse(text);
      prefixCacheSet(prefix, rangeMap);
    } catch (e) {
      return { breached: false, count: 0, error: 'Network error: ' + e.message };
    }
  }
  const count = rangeMap.get(suffix) || 0;
  return { breached: count > 0, count, error: null };
}

export async function vaultHealthScan(entries, onProgress) {
  const results = [];
  const seen = new Set();
  const passwords = [];
  for (const entry of entries) {
    const pw = entry.pass || entry.password || '';
    if (!pw || seen.has(pw)) continue;
    seen.add(pw);
    passwords.push({ site: entry.site || entry.name || 'Unknown', password: pw });
  }
  const total = passwords.length;
  let checked = 0;
  for (const item of passwords) {
    const result = await checkPwnedPassword(item.password);
    results.push({ site: item.site, breached: result.breached, count: result.count, error: result.error });
    checked++;
    if (onProgress) onProgress(checked, total, item.site, result);
    if (checked < total) await new Promise(r => setTimeout(r, BATCH_THROTTLE_MS));
  }
  return results;
}

export function clearBreachCache() {
  _prefixCache.clear();
}
