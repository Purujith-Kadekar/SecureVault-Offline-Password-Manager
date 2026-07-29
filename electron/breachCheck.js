'use strict';
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
 * OFF BY DEFAULT: The caller must check the hibpCheckEnabled setting before calling.
 */

const HIBP_API_BASE = 'https://api.pwnedpasswords.com/range';
const BATCH_THROTTLE_MS = 250;

const _prefixCache = new Map();

function sha1Hex(plaintext) {
  return require('crypto').createHash('sha1').update(plaintext, 'utf8').digest('hex').toUpperCase();
}

async function fetchRange(prefix) {
  const url = `${HIBP_API_BASE}/${prefix}`;
  const options = {
    headers: {
      'Add-Padding': 'true',
      'User-Agent': 'SecureVault-BreachCheck/1.0',
    },
  };

  if (typeof fetch === 'function') {
    const resp = await fetch(url, options);
    if (!resp.ok) throw new Error(`HIBP API returned ${resp.status}`);
    return await resp.text();
  }

  // Fallback to https module
  const https = require('https');
  return new Promise((resolve, reject) => {
    const req = https.get(url, options, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HIBP API returned ${res.statusCode}`));
        return;
      }
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => resolve(body));
    });
    req.on('error', reject);
    req.setTimeout(10000, () => req.destroy(new Error('HIBP API timeout')));
  });
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

async function checkPwnedPassword(password) {
  if (!password || typeof password !== 'string') {
    return { breached: false, count: 0, error: 'No password provided' };
  }
  let hash;
  try {
    hash = sha1Hex(password);
  } catch (e) {
    return { breached: false, count: 0, error: 'Hash computation failed: ' + e.message };
  }
  const prefix = hash.substring(0, 5);
  const suffix = hash.substring(5);
  let rangeMap = _prefixCache.get(prefix);
  if (!rangeMap) {
    try {
      const text = await fetchRange(prefix);
      rangeMap = parseRangeResponse(text);
      _prefixCache.set(prefix, rangeMap);
    } catch (e) {
      return { breached: false, count: 0, error: 'Network error: ' + e.message };
    }
  }
  const count = rangeMap.get(suffix) || 0;
  return { breached: count > 0, count, error: null };
}

async function vaultHealthScan(entries, onProgress) {
  const results = [];
  const seen = new Set();
  const passwords = [];
  for (const entry of entries) {
    const pw = entry.pass || entry.login_password || '';
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

function clearBreachCache() {
  _prefixCache.clear();
}

module.exports = { checkPwnedPassword, vaultHealthScan, clearBreachCache, sha1Hex };
