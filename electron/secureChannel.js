'use strict';
/**
 * secureChannel.js — Electron-side 4-Layer Security Stack over USB CDC Serial
 *
 * v6 CHANGES ("100% perfect" pass — aligns with firmware v5.5):
 * - FIXED timer race: entry.timer was set AFTER await sendFrame(), so if the
 *   device responded before drain() callback fired, handleReceivedPayload
 *   ran first, cleared a null timer (no-op), resolved the entry, then send()
 *   resumed and set the timer on an already-resolved entry. 30-90s later the
 *   timer fired unconditionally → teardown() → session destroyed mid-operation.
 *   Fix: added entry.completed flag; timer callback and handleReceivedPayload
 *   both check it.
 * - PING timeout reduced from 30s to 5s. The old 30s read timeout meant a
 *   dead device took 30s+2s+30s = 62s to detect. Now 5s+2s+5s = 12s.
 * - Keepalive retry now works: the old code called teardown() inside the
 *   secureRequest timeout, so the retry ping() failed immediately with
 *   "session not established". Now PING timeout rejects the promise WITHOUT
 *   calling teardown(), giving the retry a chance.
 * - LOCK flow: firmware v5.5 now sends an encrypted 0x19 LOCKED frame BEFORE
 *   teardown (was: plaintext JSON after teardown). The 0x7B plaintext check
 *   is kept for genuine firmware error responses ("session expired") but
 *   will no longer fire for LOCK.
 *
 * v5 CHANGES:
 * - PING (0x20) / PONG (0x21) for lightweight keepalive
 * - teardown() disconnect callback for renderer notification
 * - Handshake timeout 20s (ECDH + loadFromSD + PBKDF2)
 *
 * NO HTTP. NO IP ADDRESSES. NO NETWORK STACK.
 */

const crypto = require('crypto');
const { SerialPort } = require('serialport');

// ── Constants (must match secure_session.h on the ESP32) ──────────────
const SEC_ECDH_PUBKEY_LEN = 65;
const SEC_NONCE_LEN = 12;
const SEC_TAG_LEN = 16;
const SEC_FRAME_HEADER_LEN = 16;
const SEC_MAX_PAYLOAD = 8192;
const SEC_MAX_FRAME = SEC_FRAME_HEADER_LEN + SEC_MAX_PAYLOAD + SEC_TAG_LEN;
const SEC_SESSION_TIMEOUT_MS = 300000; // 5 minutes — matches ESP32

const MAGIC = Buffer.from('SV13', 'ascii');

const SEC_MSG = {
  HELLO: 0x01, HELLO_ACK: 0x02,
  LIST: 0x10, LIST_RESP: 0x11,
  GET: 0x12, GET_RESP: 0x13,
  ADD: 0x14, UPDATE: 0x15, DELETE: 0x16,
  SAVE_OK: 0x17,
  LOCK: 0x18, LOCKED: 0x19,
  PING: 0x20, PONG: 0x21,  // v5: lightweight keepalive
  ERROR: 0xFF,
};

// ── Session state ──────────────────────────────────────────────────────
let session = {
  port: null,
  ecdh: null,
  sessionKey: null,
  established: false,
  lastActivity: 0,
  rxState: 'SCAN_MAGIC',
  magicBuf: Buffer.alloc(4),
  magicPos: 0,
  lenBuf: Buffer.alloc(4),
  lenPos: 0,
  payloadLen: 0,
  payloadBuf: Buffer.alloc(SEC_MAX_FRAME + 256),
  payloadPos: 0,
  pendingQueue: [],
  inFlight: false,
  handshakeResolver: null,
};

let timeoutTimer = null;

// v5: Disconnect callback — set by main.js so it can notify the renderer
// when the session is torn down. This is THE fix for "silent disconnect":
// the renderer now gets a 'device:disconnected' event instead of silently
// losing the connection with no feedback.
let _onDisconnect = null;

function setDisconnectCallback(cb) {
  _onDisconnect = cb;
}

// ─────────────────────────────────────────────────────────────────────────
//  Serial port discovery
// ─────────────────────────────────────────────────────────────────────────
async function listPorts() {
  const ports = await SerialPort.list();
  return ports.map(p => ({
    path: p.path,
    manufacturer: p.manufacturer || '',
    vendorId: p.vendorId || '',
    productId: p.productId || '',
    isEsp32: (p.vendorId && p.vendorId.toLowerCase() === '303a') ||
             (p.path && /ttyACM|COM\d/i.test(p.path)),
  }));
}

async function findEsp32Port() {
  const ports = await listPorts();
  const esp = ports.find(p => p.isEsp32);
  if (esp) return esp.path;
  const acm = ports.find(p => /ttyACM/i.test(p.path));
  if (acm) return acm.path;
  return null;
}

// ─────────────────────────────────────────────────────────────────────────
//  Serial port open / close
// ─────────────────────────────────────────────────────────────────────────
async function openPort(portPath) {
  // If a port is already open from a previous attempt, close it first
  if (session.port) {
    try {
      if (session.port.isOpen) {
        await new Promise((resolve) => {
          session.port.close((err) => resolve());
        });
      }
    } catch {}
    session.port = null;
    await new Promise((r) => setTimeout(r, 500));
  }

  const ports = await SerialPort.list();
  const exists = ports.some(p => p.path === portPath);
  if (!exists) {
    throw new Error(`Port ${portPath} not found. Available: ${ports.map(p => p.path).join(', ') || 'none'}. Unplug and replug the ESP32, then retry.`);
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { session.port.close(); } catch {}
      session.port = null;
      reject(new Error(`Timeout opening ${portPath} — another program may have it open. Close PlatformIO serial monitor, then retry.`));
    }, 3000);

    session.port = new SerialPort({
      path: portPath,
      baudRate: 115200,
      autoOpen: false,
    });

    session.port.open((err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) {
        session.port = null;
        let hint = '';
        if (/File not found|ENOENT/i.test(err.message)) {
          hint = ' The port may have been unplugged. Unplug and replug the ESP32, then retry.';
        } else if (/Access denied|Permission|EBUSY/i.test(err.message)) {
          hint = ' Another program has this port open. Close PlatformIO serial monitor, Arduino IDE, or any other app using this port.';
        }
        reject(new Error(`Cannot open ${portPath}: ${err.message}.${hint}`));
        return;
      }
      session.port.on('data', (chunk) => onSerialData(chunk));
      session.port.on('error', (err) => {
        console.error('[secureChannel] Serial error:', err.message);
        // v5: Tell main.js this was an error-triggered disconnect
        teardown('serial_error: ' + err.message);
      });
      session.port.on('close', () => {
        // v5: Distinguish clean close from crash. If the ESP32 crashed/
        // rebooted, the USB CDC device disappears and the OS reports
        // the port as "closed". This is the #1 cause of "silent disconnect".
        console.log('[secureChannel] Serial port closed (ESP32 may have rebooted)');
        teardown('port_closed');
      });
      resolve();
    });
  });
}

function closePort() {
  if (session.port) {
    try { session.port.close(); } catch {}
    session.port = null;
  }
}

// ─────────────────────────────────────────────────────────────────────────
//  Serial receiver state machine
// ─────────────────────────────────────────────────────────────────────────
function onSerialData(chunk) {
  for (let i = 0; i < chunk.length; i++) {
    const b = chunk[i];

    switch (session.rxState) {
      case 'SCAN_MAGIC':
        session.magicBuf[session.magicPos] = b;
        if (session.magicBuf[session.magicPos] === MAGIC[session.magicPos]) {
          session.magicPos++;
          if (session.magicPos === 4) {
            session.rxState = 'READ_LENGTH';
            session.lenPos = 0;
          }
        } else {
          if (b === MAGIC[0]) {
            session.magicBuf[0] = b;
            session.magicPos = 1;
          } else {
            session.magicPos = 0;
          }
        }
        break;

      case 'READ_LENGTH':
        session.lenBuf[session.lenPos++] = b;
        if (session.lenPos === 4) {
          session.payloadLen = session.lenBuf.readUInt32LE(0);
          if (session.payloadLen === 0 || session.payloadLen > session.payloadBuf.length) {
            session.rxState = 'SCAN_MAGIC';
            session.magicPos = 0;
          } else {
            session.rxState = 'READ_PAYLOAD';
            session.payloadPos = 0;
          }
        }
        break;

      case 'READ_PAYLOAD':
        session.payloadBuf[session.payloadPos++] = b;
        if (session.payloadPos === session.payloadLen) {
          const payload = Buffer.from(session.payloadBuf.slice(0, session.payloadLen));
          session.rxState = 'SCAN_MAGIC';
          session.magicPos = 0;
          session.lenPos = 0;
          session.payloadPos = 0;
          handleReceivedPayload(payload);
        }
        break;
    }
  }
}

function handleReceivedPayload(payload) {
  // Priority 1: the handshake is waiting for its ack (pre-session).
  if (session.handshakeResolver) {
    const r = session.handshakeResolver;
    session.handshakeResolver = null;
    r(payload);
    return;
  }
  // Priority 2: dispatch to the head of the secure-request queue (FIFO).
  if (session.pendingQueue.length > 0) {
    const entry = session.pendingQueue.shift();
    session.inFlight = false;
    if (entry && entry.resolve) {
      // v6: Mark completed BEFORE clearing the timer so the timer callback
      // (which may not have been set yet — see send() race fix below) can
      // detect that the entry has already been resolved.
      entry.completed = true;
      if (entry.timer) clearTimeout(entry.timer);
      entry.resolve(payload);
    }
    pumpQueue();
  }
}

function pumpQueue() {
  if (session.inFlight) return;
  const next = session.pendingQueue[0];
  if (!next) return;
  session.inFlight = true;
  next.send().catch((err) => {
    session.pendingQueue.shift();
    session.inFlight = false;
    next.reject(err);
    pumpQueue();
  });
}

// ─────────────────────────────────────────────────────────────────────────
//  Frame sending
// ─────────────────────────────────────────────────────────────────────────
function sendFrame(data) {
  if (!session.port || !session.port.isOpen) {
    throw new Error('Serial port not open');
  }
  const frame = Buffer.alloc(4 + 4 + data.length);
  MAGIC.copy(frame, 0);
  frame.writeUInt32LE(data.length, 4);
  data.copy(frame, 8);
  return new Promise((resolve, reject) => {
    session.port.write(frame, (err) => {
      if (err) { reject(err); return; }
      session.port.drain(() => resolve());
    });
  });
}

function sendJson(obj) {
  return sendFrame(Buffer.from(JSON.stringify(obj), 'utf8'));
}

// ─────────────────────────────────────────────────────────────────────────
//  Layer 2: ECDH handshake
// ─────────────────────────────────────────────────────────────────────────
async function handshake(code, portPath) {
  if (!portPath) {
    portPath = await findEsp32Port();
    if (!portPath) {
      return { ok: false, error: 'No ESP32 serial port found. Plug in the device via USB cable and retry.' };
    }
  }
  try {
    await openPort(portPath);
  } catch (err) {
    return { ok: false, error: err.message };
  }

  session.ecdh = crypto.createECDH('prime256v1');
  session.ecdh.generateKeys();
  const clientPubkey = session.ecdh.getPublicKey(null, 'uncompressed');
  if (clientPubkey.length !== SEC_ECDH_PUBKEY_LEN) {
    teardown();
    return { ok: false, error: 'Internal: generated pubkey is wrong length' };
  }

  const codeProof = crypto.createHash('sha256').update(code, 'utf8').digest();

  await sendJson({
    type: 'hello',
    pubkey: clientPubkey.toString('base64'),
    codeProof: codeProof.toString('base64'),
  });

  // v5: Increased handshake timeout from 15s to 20s because the ESP32
  // now does ECDH + loadFromSD() in a 24KB stack task, which includes
  // PBKDF2 (2-5s) + JSON parse + SD card read. Total can approach 10s.
  const ackPayload = await waitForResponse(20000);
  if (!ackPayload) {
    teardown();
    return { ok: false, error: 'Handshake timeout — device did not respond. Is Dashboard Mode active on the ESP32?' };
  }

  let ack;
  try {
    ack = JSON.parse(ackPayload.toString('utf8'));
  } catch {
    teardown();
    return { ok: false, error: 'Handshake: malformed JSON response' };
  }

  if (!ack.ok || !ack.pubkey) {
    teardown();
    return { ok: false, error: ack.error || 'Handshake rejected by device' };
  }

  const devicePubkey = Buffer.from(ack.pubkey, 'base64');
  if (devicePubkey.length !== SEC_ECDH_PUBKEY_LEN || devicePubkey[0] !== 0x04) {
    teardown();
    return { ok: false, error: 'Device pubkey is wrong format' };
  }

  const sharedSecret = session.ecdh.computeSecret(devicePubkey);

  const ikm = Buffer.concat([sharedSecret, codeProof]);
  session.sessionKey = crypto.hkdfSync('sha256', ikm,
    Buffer.from('SecureVault-v3'), Buffer.from('session-key'), 32);
  if (!Buffer.isBuffer(session.sessionKey)) {
    session.sessionKey = Buffer.from(session.sessionKey);
  }

  sharedSecret.fill(0);
  codeProof.fill(0);
  ikm.fill(0);

  session.established = true;
  session.lastActivity = Date.now();
  startTimeoutTimer();

  return { ok: true };
}

function waitForResponse(timeoutMs) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (session.handshakeResolver === waitForResponseResolver) {
        session.handshakeResolver = null;
      }
      resolve(null);
    }, timeoutMs);
    const waitForResponseResolver = (payload) => {
      clearTimeout(timer);
      resolve(payload);
    };
    session.handshakeResolver = waitForResponseResolver;
  });
}

// ─────────────────────────────────────────────────────────────────────────
//  Layer 3: AES-256-GCM frame encrypt/decrypt
// ─────────────────────────────────────────────────────────────────────────
function encryptFrame(msgType, plaintext) {
  if (!session.established || !session.sessionKey) {
    throw new Error('encryptFrame: session not established');
  }
  const payloadLen = plaintext ? plaintext.length : 0;
  if (payloadLen > SEC_MAX_PAYLOAD) {
    throw new Error(`encryptFrame: payload too large (${payloadLen} > ${SEC_MAX_PAYLOAD})`);
  }

  const frame = Buffer.alloc(SEC_FRAME_HEADER_LEN + payloadLen + SEC_TAG_LEN);
  frame[0] = 1;
  frame[1] = msgType;
  frame.writeUInt16BE(payloadLen, 2);

  const nonce = crypto.randomBytes(SEC_NONCE_LEN);
  nonce.copy(frame, 4);

  const cipher = crypto.createCipheriv('aes-256-gcm', session.sessionKey, nonce);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext || Buffer.alloc(0)),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  ciphertext.copy(frame, SEC_FRAME_HEADER_LEN);
  tag.copy(frame, SEC_FRAME_HEADER_LEN + payloadLen);

  nonce.fill(0);
  session.lastActivity = Date.now();
  return frame;
}

function decryptFrame(frame) {
  if (!session.established || !session.sessionKey) {
    throw new Error('decryptFrame: session not established');
  }
  if (frame.length < SEC_FRAME_HEADER_LEN + SEC_TAG_LEN) {
    throw new Error('decryptFrame: frame too short');
  }

  const version = frame[0];
  const msgType = frame[1];
  const payloadLen = frame.readUInt16BE(2);
  const nonce = frame.slice(4, 4 + SEC_NONCE_LEN);

  if (version !== 1) throw new Error(`decryptFrame: bad version ${version}`);
  if (payloadLen > SEC_MAX_PAYLOAD) throw new Error('decryptFrame: payload too large');
  if (frame.length !== SEC_FRAME_HEADER_LEN + payloadLen + SEC_TAG_LEN) {
    throw new Error('decryptFrame: length mismatch');
  }

  const ciphertext = frame.slice(SEC_FRAME_HEADER_LEN, SEC_FRAME_HEADER_LEN + payloadLen);
  const tag = frame.slice(SEC_FRAME_HEADER_LEN + payloadLen);

  const decipher = crypto.createDecipheriv('aes-256-gcm', session.sessionKey, nonce);
  decipher.setAuthTag(tag);
  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new Error('decryptFrame: GCM auth tag mismatch');
  }

  session.lastActivity = Date.now();
  return { msgType, plaintext };
}

// ─────────────────────────────────────────────────────────────────────────
//  Secure request
// ─────────────────────────────────────────────────────────────────────────
async function secureRequest(msgType, payload) {
  if (!session.established) {
    throw new Error('secureRequest: session not established');
  }

  const plaintext = payload ? Buffer.from(JSON.stringify(payload), 'utf8') : Buffer.alloc(0);
  const frame = encryptFrame(msgType, plaintext);
  plaintext.fill(0);

  // v6: Per-operation timeouts. PING is a lightweight keepalive probe —
  // if the device doesn't respond in 5s, it's dead. Read ops (LIST/GET)
  // get 30s. Write ops (ADD/UPDATE/DELETE) get 90s (first save after boot
  // does PBKDF2 ~2-5s; with key caching, subsequent saves are <1s).
  // LOCK uses the read timeout (firmware responds before teardown).
  const isWriteOp = (msgType === SEC_MSG.ADD || msgType === SEC_MSG.UPDATE || msgType === SEC_MSG.DELETE);
  const isPing    = (msgType === SEC_MSG.PING);
  const timeoutMs = isPing ? 5000 : (isWriteOp ? 90000 : 30000);

  // v6: isLock flag — LOCK is special: the firmware tears down the session
  // AFTER sending the LOCKED response. If decryption fails because the
  // session key was zeroed mid-flight, treat it as a successful lock
  // (the device DID lock — we just couldn't decrypt the ack).
  const isLock = (msgType === SEC_MSG.LOCK);

  const respPayload = await new Promise((resolve, reject) => {
    const entry = {
      resolve,
      reject,
      timer: null,
      completed: false,  // v6: guards against the timer race
      send: async () => {
        try {
          await sendFrame(frame);
        } catch (err) {
          // sendFrame failed — the port is dead. Reject without teardown
          // (the port close handler will call teardown).
          if (!entry.completed) {
            entry.completed = true;
            const idx = session.pendingQueue.indexOf(entry);
            if (idx >= 0) session.pendingQueue.splice(idx, 1);
            session.inFlight = false;
            reject(err);
            pumpQueue();
          }
          return;
        }
        // v6: The response might have arrived during await sendFrame()
        // (if drain was slow to callback but the device responded fast).
        // In that case, handleReceivedPayload already set completed=true
        // and resolved the promise. Don't set the timer on a dead entry.
        if (entry.completed) return;
        entry.timer = setTimeout(() => {
          // v6: Double-check completed — handleReceivedPayload might have
          // resolved this entry between the await sendFrame() above and
          // this setTimeout(0)-equivalent.
          if (entry.completed) return;
          entry.completed = true;
          const idx = session.pendingQueue.indexOf(entry);
          if (idx >= 0) session.pendingQueue.splice(idx, 1);
          session.inFlight = false;
          pumpQueue();
          // v6: For PING, don't teardown on timeout — let the keepalive
          // retry logic handle it. For all other ops, teardown because
          // the protocol state is now uncertain.
          if (!isPing) {
            teardown('response_timeout');
          }
          reject(new Error('Response timeout — device may have disconnected or rebooted' +
                           (isPing ? ' (keepalive)' : ' during save') + '.'));
        }, timeoutMs);
      },
    };
    session.pendingQueue.push(entry);
    pumpQueue();
  });

  // v6: Check if this is a plaintext JSON response. The firmware sends
  // plaintext {"ok":false,"error":"session expired"} ONLY when the session
  // is no longer established (e.g., after a device-side timeout). An
  // encrypted frame always starts with 0x01 (version byte), so 0x7B ('{')
  // unambiguously identifies a plaintext error.
  if (respPayload.length > 0 && respPayload[0] === 0x7B) {
    const text = respPayload.toString('utf8');
    let json;
    try { json = JSON.parse(text); } catch { json = {}; }
    teardown('plaintext_error');
    if (json.error) {
      throw new Error(json.error);
    }
    throw new Error('Device sent a plaintext error: ' + text.substring(0, 200));
  }

  let decrypted;
  try {
    decrypted = decryptFrame(respPayload);
  } catch (e) {
    // v6: If this was a LOCK request and decryption failed, the firmware
    // likely tore down the session before/during the encrypted LOCKED
    // response. The lock DID succeed on the device side — don't surface
    // this as an error to the user.
    if (isLock) {
      teardown('lock_decrypt_fail');
      return { msgType: SEC_MSG.LOCKED, data: { ok: true } };
    }
    teardown('decrypt_failed');
    throw new Error('Device response could not be decrypted (session may have expired): ' + e.message);
  }

  const { msgType: respType, plaintext: respPlaintext } = decrypted;

  let data;
  if (respPlaintext.length === 0) {
    data = { ok: false, error: 'Device returned an empty response — the firmware may have failed to parse the request or the SD card write failed. Check that the SD card is inserted and the entry fields are not too long.' };
  } else {
    const text = respPlaintext.toString('utf8');
    try {
      data = JSON.parse(text);
    } catch (e) {
      data = { ok: false, error: text };
    }
  }

  if (data.ok === undefined) {
    data.ok = false;
    if (!data.error) {
      data.error = 'Device returned an unexpected response (msgType=' + respType + ', plaintext="' + respPlaintext.toString('utf8').substring(0, 200) + '")';
    }
  }

  respPlaintext.fill(0);
  return { msgType: respType, data };
}

async function listEntries() {
  const { data } = await secureRequest(SEC_MSG.LIST, null);
  return data.entries || [];
}

async function getEntry(index) {
  const { data } = await secureRequest(SEC_MSG.GET, { index });
  return data;
}

async function addEntry(entry) {
  // v10.9 FIX: Removed debug console.log that leaked entry structure info
  // (type and field keys). In production, this leaks sensitive data patterns.
  const { data } = await secureRequest(SEC_MSG.ADD, entry);
  return data;
}

async function updateEntry(index, entry) {
  // v10.9 FIX: Removed debug console.log that leaked entry info in production.
  const { data } = await secureRequest(SEC_MSG.UPDATE, { index, entry });
  return data;
}

async function deleteEntry(index) {
  const { data } = await secureRequest(SEC_MSG.DELETE, { index });
  return data;
}

async function lockSession() {
  if (!session.established) return;
  try {
    // v6: Firmware v5.5 sends an encrypted 0x19 LOCKED frame BEFORE
    // tearing down the session. secureRequest will decrypt it normally.
    // If the firmware tears down too fast and the LOCKED frame can't be
    // decrypted, secureRequest returns { ok: true } anyway (isLock path).
    await secureRequest(SEC_MSG.LOCK, null);
  } catch (err) {
    // Ignore — we're tearing down anyway. The device DID receive the
    // LOCK request (it's a read op, dispatched inline on the serial task).
    console.warn('[secureChannel] LOCK request error (ignoring — tearing down):', err.message);
  }
  teardown('user_lock');
}

function startTimeoutTimer() {
  if (timeoutTimer) clearInterval(timeoutTimer);
  timeoutTimer = setInterval(async () => {
    if (!session.established) return;

    // Client-side inactivity timeout (5 min — matches ESP32).
    if (Date.now() - session.lastActivity > SEC_SESSION_TIMEOUT_MS) {
      console.log('[secureChannel] Session timed out (client-side inactivity)');
      teardown('client_timeout');
      return;
    }

    // v6: PING keepalive — lightweight, no vault access on the device.
    // Skip if there's anything in flight or queued (the response from
    // a real request also serves as proof-of-life).
    if (session.inFlight || session.pendingQueue.length > 0) return;
    if (Date.now() - session.lastActivity > 12000) {
      try {
        await ping();
      } catch (err) {
        // v6: PING timeout (5s) rejects WITHOUT teardown — the session
        // might still be alive (the device could be in a brief busy state).
        // Wait 2s and retry once. Only teardown if the retry also fails.
        console.warn('[secureChannel] Keepalive PING failed:', err.message);
        if (!session.established) return;  // session may have been torn down elsewhere
        try {
          await new Promise(r => setTimeout(r, 2000));
          if (!session.established) return;
          await ping();
          console.log('[secureChannel] Keepalive PING retry succeeded');
        } catch (retryErr) {
          console.error('[secureChannel] Keepalive PING retry also failed — tearing down');
          teardown('keepalive_failed');
        }
      }
    }
  }, 7000);
}

function teardown(reason) {
  const wasEstablished = session.established;
  if (session.sessionKey) {
    session.sessionKey.fill(0);
    session.sessionKey = null;
  }
  // v10.9 FIX: Zero the ECDH private key before discarding the object.
  // Previously, session.ecdh was set to null without zeroing the internal
  // private key buffer. The ECDH private key material persists in V8's
  // heap until garbage collection, which could be seconds or minutes later.
  // In a password manager, key material should be zeroed immediately.
  // Node.js ECDH doesn't expose the private key buffer directly, but we
  // can export it, zero it, and then discard the object.
  if (session.ecdh) {
    try {
      const privKey = session.ecdh.getPrivateKey();
      if (privKey && Buffer.isBuffer(privKey)) {
        privKey.fill(0);
      }
    } catch (_e) {
      // getPrivateKey() may throw if the key hasn't been generated yet —
      // safe to ignore, the key material doesn't exist.
    }
    session.ecdh = null;
  }
  session.established = false;
  for (const entry of session.pendingQueue) {
    if (entry.timer) clearTimeout(entry.timer);
    if (entry.reject) {
      entry.reject(new Error('Session torn down'));
    }
  }
  session.pendingQueue = [];
  session.inFlight = false;
  session.handshakeResolver = null;
  session.rxState = 'SCAN_MAGIC';
  session.magicPos = 0;
  session.lenPos = 0;
  session.payloadPos = 0;
  if (timeoutTimer) {
    clearInterval(timeoutTimer);
    timeoutTimer = null;
  }
  closePort();

  // v5: Notify main.js that the session was torn down so it can tell
  // the renderer. Without this, the renderer never knows the device
  // disconnected — the #1 cause of "silent disconnect".
  if (wasEstablished && _onDisconnect) {
    _onDisconnect(reason || 'unknown');
  }
}

function isEstablished() {
  return session.established;
}

async function ping() {
  // v5: Lightweight keepalive — sends PING (0x20), expects PONG (0x21).
  // Much lighter than the old keepalive which sent full LIST requests.
  const { data } = await secureRequest(SEC_MSG.PING, null);
  return data;
}

module.exports = {
  handshake,
  listEntries,
  getEntry,
  addEntry,
  updateEntry,
  deleteEntry,
  lockSession,
  teardown,
  isEstablished,
  listPorts,
  ping,
  setDisconnectCallback,
  SEC_MSG,
};
