/**
 * generator.js — Password generation logic (ES module).
 *
 * E10: Extracted from background.js for modular decomposition.
 * Contains random password generation, passphrase generation,
 * strength estimation, and crypto-safe random helpers.
 *
 * Depends on wordlist.js for the passphrase wordlist.
 */

import { WORDLIST } from './wordlist.js';

// ─── Character sets ───────────────────────────────────────────────────

const CHARSETS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?/'
};
const AMBIGUOUS = new Set('0OIl1B8G6S5Z2DQOo'.split('')); // commonly confused chars

// ─── Crypto-safe random helpers ────────────────────────────────────────

/**
 * Pick a uniformly-random index in [0, range) using rejection sampling
 * to eliminate modulo bias.
 */
function unbiasedRandomInt(range) {
  if (range <= 0) throw new Error('range must be positive');
  const maxUint32 = 0xFFFFFFFF;
  const limit = maxUint32 - (maxUint32 % range);
  const buf = new Uint32Array(1);
  while (true) {
    crypto.getRandomValues(buf);
    if (buf[0] <= limit) return buf[0] % range;
  }
}

function pickRandomChar(charset) {
  return charset[unbiasedRandomInt(charset.length)];
}

function shuffleArray(arr) {
  // Fisher-Yates with unbiased random
  for (let i = arr.length - 1; i > 0; i--) {
    const j = unbiasedRandomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// ─── Password generation ───────────────────────────────────────────────

function generateRandomPassword(opts) {
  const length = Math.max(5, Math.min(128, opts.length || 20));
  const useUpper = opts.uppercase !== false;
  const useLower = opts.lowercase !== false;
  const useNumbers = opts.numbers !== false;
  const useSymbols = opts.symbols !== false;
  const avoidAmbiguous = opts.avoidAmbiguous === true;

  let charset = '';
  if (useUpper) charset += CHARSETS.uppercase;
  if (useLower) charset += CHARSETS.lowercase;
  if (useNumbers) charset += CHARSETS.numbers;
  if (useSymbols) charset += CHARSETS.symbols;
  if (avoidAmbiguous) {
    charset = charset.split('').filter(c => !AMBIGUOUS.has(c)).join('');
  }
  if (!charset) charset = CHARSETS.lowercase;

  // Guarantee at least one of each selected class (when length allows).
  const guaranteed = [];
  const classes = [];
  if (useUpper) classes.push(CHARSETS.uppercase);
  if (useLower) classes.push(CHARSETS.lowercase);
  if (useNumbers) classes.push(CHARSETS.numbers);
  if (useSymbols) classes.push(CHARSETS.symbols);
  if (avoidAmbiguous) {
    for (let i = 0; i < classes.length; i++) {
      classes[i] = classes[i].split('').filter(c => !AMBIGUOUS.has(c)).join('');
    }
  }
  for (const cls of classes) {
    if (cls.length > 0 && guaranteed.length < length) {
      guaranteed.push(pickRandomChar(cls));
    }
  }
  // Fill the rest randomly.
  const remaining = length - guaranteed.length;
  for (let i = 0; i < remaining; i++) {
    guaranteed.push(pickRandomChar(charset));
  }
  return shuffleArray(guaranteed).join('');
}

function generatePassphrase(opts) {
  const wordCount = Math.max(3, Math.min(10, opts.wordCount || 4));
  const separator = opts.separator !== undefined ? opts.separator : '-';
  const capitalize = opts.capitalize === true;
  const includeNumber = opts.includeNumber === true;

  const chosen = [];
  for (let i = 0; i < wordCount; i++) {
    const w = WORDLIST[unbiasedRandomInt(WORDLIST.length)];
    chosen.push(capitalize ? (w.charAt(0).toUpperCase() + w.slice(1)) : w);
  }
  let result = chosen.join(separator);
  if (includeNumber) {
    result += separator + String(unbiasedRandomInt(1000)).padStart(3, '0');
  }
  return result;
}

function generatePassword(options = {}) {
  const mode = options.mode || 'random';
  let password;
  if (mode === 'passphrase') {
    password = generatePassphrase(options);
  } else {
    password = generateRandomPassword(options);
  }
  const strength = estimateStrength(password, mode, options);
  return { password, strength, entropyBits: strength.entropyBits, label: strength.label };
}

function estimateStrength(password, mode, options) {
  let poolSize;
  if (mode === 'passphrase') {
    poolSize = WORDLIST.length;
    const wordCount = Math.max(3, Math.min(10, options.wordCount || 4));
    let bits = Math.log2(poolSize) * wordCount;
    if (options.includeNumber) bits += Math.log2(1000);
    return { entropyBits: Math.round(bits), label: labelForBits(bits) };
  } else {
    let cs = 0;
    if (options.uppercase !== false) cs += 26;
    if (options.lowercase !== false) cs += 26;
    if (options.numbers !== false) cs += 10;
    if (options.symbols !== false) cs += 26;
    if (cs === 0) cs = 26;
    const length = password.length;
    const bits = Math.log2(cs) * length;
    return { entropyBits: Math.round(bits), label: labelForBits(bits) };
  }
}

function labelForBits(bits) {
  if (bits < 40) return 'weak';
  if (bits < 70) return 'fair';
  if (bits < 100) return 'good';
  return 'strong';
}

export {
  CHARSETS,
  AMBIGUOUS,
  unbiasedRandomInt,
  pickRandomChar,
  shuffleArray,
  generateRandomPassword,
  generatePassphrase,
  generatePassword,
  estimateStrength,
  labelForBits
};
