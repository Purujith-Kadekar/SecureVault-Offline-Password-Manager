#include "vault_manager.h"
#include "crypto_utils.h"
#include "crypto_buffer.h"   // F9: largeAlloc/largeFree — PSRAM-first allocator
#include "board_config.h"
#include <string.h>
#include <new>          // std::nothrow for PSRAM allocations
#include <SD.h>
#include <SPI.h>
#include <ArduinoJson.h>
#include "sd_manager.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
// v5.3: Replaced yield() with vTaskDelay() throughout — yield() only yields
// to same-priority tasks, but vTaskDelay(1) allows the IDLE task (priority 0)
// to run and feed the Task WDT, preventing chip resets during long operations.

// ── DMA-safe crypto buffers ──────────────────────────────────────────
// All crypto buffers in this file are allocated via cryptoAlloc() from
// crypto_buffer.h — guaranteed internal SRAM + DMA-capable + 4-byte
// aligned. See crypto_buffer.h for the full rationale (ESP32-S3 AES-GCM
// hardware engine DMA path, PSRAM cache incoherency, etc.).


const char* VaultManager::DB_PATH = "/vault.db";
const char* VaultManager::DB_TMP_PATH = "/vault.db.tmp";
const char* VaultManager::DB_BAK_PATH = "/vault.db.bak";
const char* VaultManager::PREFS_NAMESPACE = "securevault";
const char* VaultManager::PREFS_KEY_PIN = "pin";
const char* VaultManager::PREFS_KEY_AUTOLOCK = "autolock_ms";
const char* VaultManager::PREFS_KEY_THEME = "theme_id";
const char* VaultManager::PREFS_KEY_PIN_FAILS = "pin_fails";
const char* VaultManager::PREFS_KEY_PIN_LOCK_UNTIL = "pin_lock_until";
// v10.7: Persisted KDF iteration count that last successfully unlocked the
// vault on THIS device. Lets subsequent unlocks skip the expensive
// "try 2000 iters, fail, retry with 20000 iters" path that adds 2-3s to
// every unlock of a v10.5-era vault. Reset to 0 by factory reset.
const char* VaultManager::PREFS_KEY_KDF_ITERS = "kdf_iters";
// F12: NVS key for the first-boot flag. When this key is absent or false,
// the device has never had a PIN set and the user must go through the
// mandatory first-boot PIN setup screen.
const char* VaultManager::PREFS_KEY_FIRST_BOOT = FIRST_BOOT_FLAG_KEY;

// ═══════════════════════════════════════════════════════════════════════════════
//  v10.0 — "SVR1" record-oriented on-disk format (replaces "SVL1")
// ═══════════════════════════════════════════════════════════════════════════════
// SVL1 encrypted the WHOLE vault as one JSON blob, so every ADD/UPDATE/DELETE
// had to re-serialize + re-encrypt all N entries and rewrite the entire file.
// At 256 entries that meant building a ~180KB JSON string on every keystroke
// of editing, which is what caused the PSRAM heap fragmentation / ADD-fails
// bug this format replaces.
//
// SVR1 instead stores each entry as its OWN small encrypted record, addressed
// through a fixed-size row table. ADD/UPDATE/DELETE only ever touch the ONE
// row + ONE record involved — never the other 255.
//
//   [0..3]     magic "SVR1"
//   [4]        format version (1)
//   [5..20]    PBKDF2 salt                    (VAULT_SALT_LEN = 16 bytes)
//   [21..24]   dataEnd   (uint32, big-endian)  -- next-append offset in the
//              data area; i.e. "end of file" from the writer's point of view
//   [25..26]   liveCount (uint16, big-endian)  -- informational only, NOT
//              authoritative (always re-derived by counting occupied rows
//              on load; a stale value here just means an interrupted write,
//              not a corrupt vault)
//   [27..]     ROW TABLE: exactly MAX_ENTRIES (256) fixed-size rows, back to
//              back, no gaps. Row i lives at a FIXED file offset regardless
//              of how many entries are actually in use -- that fixed-offset
//              property is what lets ADD/UPDATE patch a single row in place.
//     each row (37 bytes):
//       [0]      status        (0 = free/reusable, 1 = occupied)
//       [1..4]   dataOffset    (uint32 BE -- absolute file offset of this
//                               record's ciphertext, into the data area below)
//       [5..8]   dataLen       (uint32 BE -- ciphertext length in bytes;
//                               plaintext is the same length, GCM has no padding)
//       [9..20]  iv            (12 bytes -- GCM nonce for THIS record only;
//                               every record gets its own fresh IV, same
//                               master key)
//       [21..36] tag           (16 bytes -- GCM auth tag for THIS record)
//   [27 + 256*37 ..]  DATA AREA: each occupied row's ciphertext, appended
//              here as entries are added/updated. May contain "dead" bytes
//              belonging to no row (left behind by an UPDATE that grew a
//              record, or a purged/deleted row) -- reclaimed by compaction,
//              not read on normal load.
//
// Row table capacity is fixed at MAX_ENTRIES so it never needs to grow (a
// growing table would itself require shifting the data area -- exactly the
// bug we're avoiding). Free rows ARE reused by ADD before a new row is ever
// appended, so the table can never need more than MAX_ENTRIES live rows.
//
// Key derivation is UNCHANGED from SVL1: PBKDF2-HMAC-SHA256(pin, salt,
// VAULT_KDF_ITERATIONS) -> one 256-bit AES key, cached in SRAM after first
// unlock exactly as before. Every record is encrypted under that SAME key
// with its OWN random IV (standard/required for AES-GCM: unique IV per
// encryption under a given key, key itself never needs to change per-record).
//
// Per-entry plaintext is a single JSON object (not an array) with the same
// 25 fields _toJSON() used to emit per array element -- see _entryToJSON().
static const char DB_MAGIC[4] = { 'S', 'V', 'R', '1' };
static const uint8_t DB_VERSION = 1;
static const size_t DB_ROW_LEN =
    1 + 4 + 4 + VAULT_IV_LEN + VAULT_TAG_LEN; // 37
static const size_t DB_HEADER_LEN =
    sizeof(DB_MAGIC) + 1 + VAULT_SALT_LEN + 4 + 2; // 27
static const size_t DB_TABLE_OFFSET = DB_HEADER_LEN;                     // 27
static const size_t DB_TABLE_LEN = (size_t)VaultManager::MAX_ENTRIES * DB_ROW_LEN;
static const size_t DB_DATA_OFFSET = DB_TABLE_OFFSET + DB_TABLE_LEN;     // where record data begins

// Type serialization helpers (vaultTypeToStr / vaultStrToType) are defined
// inline in vault_types.h — no local copies needed here.

// ── PSRAM storage allocation ─────────────────────────────────────────
// All per-entry char[] arrays are heap-allocated so they land in PSRAM
// (CONFIG_SPIRAM_USE_MALLOC=y routes allocations >16KB to PSRAM
// automatically). This keeps the internal DRAM .bss segment small
// enough to link — the v9.10 per-type expansion added ~314KB of BSS
// at 256 entries, which overflowed dram0_0_seg by ~229KB.
//
// Each allocation is a flat char[MAX_ENTRIES * N] block, cast to
// char(*)[N] so it can be indexed as _site[i] (a char[N] array) —
// identical syntax to the old static 2D arrays, so no other code
// changes are needed.
//
// The `new (std::nothrow)` form returns nullptr on failure instead of
// throwing — we check and fall back to demo mode (empty vault) if
// PSRAM is unavailable.
// F9 FIX: Use largeAlloc() (PSRAM-first, internal SRAM fallback) instead of
// plain new (std::nothrow). On ESP32-S3 with OPI PSRAM, plain new routes
// through malloc() which depends on CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL.
// If PSRAM init fails silently or the threshold is wrong, new silently falls
// back to limited internal SRAM (~320KB) and the ~331KB vault storage fails.
// largeAlloc() explicitly tries MALLOC_CAP_SPIRAM first, providing guaranteed
// PSRAM routing and clear Serial error logging on failure.
#define SV_ALLOC_ARRAY_2D(NAME, N) \
  NAME = reinterpret_cast<char (*)[N]>(static_cast<char*>(largeAlloc(MAX_ENTRIES * N)))
#define SV_ALLOC_ARRAY_1D(NAME, TYPE) \
  NAME = static_cast<TYPE*>(largeAlloc(MAX_ENTRIES * sizeof(TYPE)))

void VaultManager::_allocStorage() {
  if (_storageAllocated) return;
  // ORIGINAL (login core)
  SV_ALLOC_ARRAY_2D(_site, 32);
  SV_ALLOC_ARRAY_2D(_user, 48);
  SV_ALLOC_ARRAY_2D(_pass, 48);
  SV_ALLOC_ARRAY_2D(_totp, 32);
  SV_ALLOC_ARRAY_1D(_type, uint8_t);
  SV_ALLOC_ARRAY_1D(_favorite, bool);
  SV_ALLOC_ARRAY_1D(_deleted, bool);
  // LOGIN extras
  SV_ALLOC_ARRAY_2D(_url, 64);
  SV_ALLOC_ARRAY_2D(_notes, 160);
  SV_ALLOC_ARRAY_2D(_folder, 24);
  // CARD extras
  SV_ALLOC_ARRAY_2D(_cardholder, 32);
  SV_ALLOC_ARRAY_2D(_cardNumber, 24);
  SV_ALLOC_ARRAY_2D(_exp, 8);
  SV_ALLOC_ARRAY_2D(_cvv, 5);
  // IDENTITY extras
  SV_ALLOC_ARRAY_2D(_firstName, 24);
  SV_ALLOC_ARRAY_2D(_lastName, 24);
  SV_ALLOC_ARRAY_2D(_email, 48);
  SV_ALLOC_ARRAY_2D(_phone, 20);
  SV_ALLOC_ARRAY_2D(_address, 48);
  SV_ALLOC_ARRAY_2D(_city, 24);
  SV_ALLOC_ARRAY_2D(_state, 24);
  SV_ALLOC_ARRAY_2D(_postal, 12);
  SV_ALLOC_ARRAY_2D(_country, 24);
  SV_ALLOC_ARRAY_2D(_ssn, 16);
  SV_ALLOC_ARRAY_2D(_passport, 24);
  SV_ALLOC_ARRAY_2D(_license, 24);
  // Views (also large: 256 × ~96 bytes = ~24KB) — use largeAlloc too
  _entrySite  = static_cast<const char**>(largeAlloc(MAX_ENTRIES * sizeof(const char*)));
  _entryUser  = static_cast<const char**>(largeAlloc(MAX_ENTRIES * sizeof(const char*)));
  _entryPass  = static_cast<const char**>(largeAlloc(MAX_ENTRIES * sizeof(const char*)));
  _entryTotp  = static_cast<const char**>(largeAlloc(MAX_ENTRIES * sizeof(const char*)));
  _views      = static_cast<VaultEntry*>(largeAlloc(MAX_ENTRIES * sizeof(VaultEntry)));

  // Verify all allocations succeeded
  if (!_site || !_user || !_pass || !_totp || !_type || !_favorite || !_deleted ||
      !_url || !_notes || !_folder ||
      !_cardholder || !_cardNumber || !_exp || !_cvv ||
      !_firstName || !_lastName || !_email || !_phone || !_address ||
      !_city || !_state || !_postal || !_country || !_ssn || !_passport || !_license ||
      !_entrySite || !_entryUser || !_entryPass || !_entryTotp || !_views) {
    Serial.println("[VaultManager] FATAL: PSRAM allocation failed! Vault disabled.");
    Serial.printf("[VaultManager]   Free PSRAM: %u bytes, Free internal: %u bytes\n",
                 (unsigned)ESP.getFreePsram(), (unsigned)ESP.getFreeHeap());
    _freeStorage();
    return;
  }
  _storageAllocated = true;
  Serial.printf("[VaultManager] PSRAM storage allocated OK — %d entries capacity\n", MAX_ENTRIES);
  // Zero everything so demo data and loadFromSD don't see stale heap bytes
  memset(_site, 0, MAX_ENTRIES * 32);
  memset(_user, 0, MAX_ENTRIES * 48);
  memset(_pass, 0, MAX_ENTRIES * 48);
  memset(_totp, 0, MAX_ENTRIES * 32);
  memset(_type, 0, MAX_ENTRIES);
  memset(_favorite, 0, MAX_ENTRIES);
  memset(_deleted, 0, MAX_ENTRIES);
  memset(_url, 0, MAX_ENTRIES * 64);
  memset(_notes, 0, MAX_ENTRIES * 160);
  memset(_folder, 0, MAX_ENTRIES * 24);
  memset(_cardholder, 0, MAX_ENTRIES * 32);
  memset(_cardNumber, 0, MAX_ENTRIES * 24);
  memset(_exp, 0, MAX_ENTRIES * 8);
  memset(_cvv, 0, MAX_ENTRIES * 5);
  memset(_firstName, 0, MAX_ENTRIES * 24);
  memset(_lastName, 0, MAX_ENTRIES * 24);
  memset(_email, 0, MAX_ENTRIES * 48);
  memset(_phone, 0, MAX_ENTRIES * 20);
  memset(_address, 0, MAX_ENTRIES * 48);
  memset(_city, 0, MAX_ENTRIES * 24);
  memset(_state, 0, MAX_ENTRIES * 24);
  memset(_postal, 0, MAX_ENTRIES * 12);
  memset(_country, 0, MAX_ENTRIES * 24);
  memset(_ssn, 0, MAX_ENTRIES * 16);
  memset(_passport, 0, MAX_ENTRIES * 24);
  memset(_license, 0, MAX_ENTRIES * 24);

  // ── SVR1 record-oriented state ──────────────────────────────────────
  // All rows start free; _diskSlot starts unassigned (-1) for every
  // entry until loadFromSD()/addEntry() give it a real row. These are
  // plain (non-PSRAM) members so no separate alloc/free is needed here —
  // just reset them alongside everything else.
  memset(_rowStatus, 0, sizeof(_rowStatus));
  memset(_rowOffset, 0, sizeof(_rowOffset));
  memset(_rowLen, 0, sizeof(_rowLen));
  memset(_rowIv, 0, sizeof(_rowIv));
  memset(_rowTag, 0, sizeof(_rowTag));
  for (int i = 0; i < MAX_ENTRIES; i++) _diskSlot[i] = -1;
  _dataEnd = 0;
}

void VaultManager::_freeStorage() {
  // Use largeFree() (matching largeAlloc from _allocStorage) — no delete[]
  largeFree(reinterpret_cast<char*>(_site));       _site = nullptr;
  largeFree(reinterpret_cast<char*>(_user));       _user = nullptr;
  largeFree(reinterpret_cast<char*>(_pass));       _pass = nullptr;
  largeFree(reinterpret_cast<char*>(_totp));       _totp = nullptr;
  largeFree(_type);        _type = nullptr;
  largeFree(_favorite);    _favorite = nullptr;
  largeFree(_deleted);     _deleted = nullptr;
  largeFree(reinterpret_cast<char*>(_url));        _url = nullptr;
  largeFree(reinterpret_cast<char*>(_notes));      _notes = nullptr;
  largeFree(reinterpret_cast<char*>(_folder));     _folder = nullptr;
  largeFree(reinterpret_cast<char*>(_cardholder)); _cardholder = nullptr;
  largeFree(reinterpret_cast<char*>(_cardNumber)); _cardNumber = nullptr;
  largeFree(reinterpret_cast<char*>(_exp));        _exp = nullptr;
  largeFree(reinterpret_cast<char*>(_cvv));        _cvv = nullptr;
  largeFree(reinterpret_cast<char*>(_firstName));  _firstName = nullptr;
  largeFree(reinterpret_cast<char*>(_lastName));   _lastName = nullptr;
  largeFree(reinterpret_cast<char*>(_email));      _email = nullptr;
  largeFree(reinterpret_cast<char*>(_phone));      _phone = nullptr;
  largeFree(reinterpret_cast<char*>(_address));    _address = nullptr;
  largeFree(reinterpret_cast<char*>(_city));       _city = nullptr;
  largeFree(reinterpret_cast<char*>(_state));      _state = nullptr;
  largeFree(reinterpret_cast<char*>(_postal));     _postal = nullptr;
  largeFree(reinterpret_cast<char*>(_country));    _country = nullptr;
  largeFree(reinterpret_cast<char*>(_ssn));        _ssn = nullptr;
  largeFree(reinterpret_cast<char*>(_passport));   _passport = nullptr;
  largeFree(reinterpret_cast<char*>(_license));    _license = nullptr;
  largeFree(_entrySite);   _entrySite = nullptr;
  largeFree(_entryUser);   _entryUser = nullptr;
  largeFree(_entryPass);   _entryPass = nullptr;
  largeFree(_entryTotp);   _entryTotp = nullptr;
  largeFree(_views);       _views = nullptr;
  _storageAllocated = false;
  _count = 0;
  _viewsBuilt = false;
}

VaultManager::~VaultManager() {
  clearCachedKey();
  _freeStorage();
  if (_mutex) {
    vSemaphoreDelete(_mutex);
    _mutex = nullptr;
  }
}

void VaultManager::begin() {
  // v5.4.7: H4 fix — create the mutex for thread-safe vault access.
  if (!_mutex) {
    _mutex = xSemaphoreCreateRecursiveMutex();
  }
  _allocStorage();
  if (_storageAllocated) {
    _loadDemo();
  }
}

// v5.4.7: H4 fix — lock/unlock the vault mutex.
// Uses a recursive mutex so the same task can lock multiple times
// (e.g. addEntry calls saveToSD internally — both need the lock).
void VaultManager::lock() {
  if (_mutex) xSemaphoreTakeRecursive(_mutex, portMAX_DELAY);
}
void VaultManager::unlock() {
  if (_mutex) xSemaphoreGiveRecursive(_mutex);
}

void VaultManager::beginWithPin(const char* pin) {
  _allocStorage();
  if (_storageAllocated && pin && strlen(pin) > 0) {
    loadFromSD(pin);
  }
  // If loadFromSD fails (no SD card, wrong PIN, corrupt file), the vault
  // stays empty — which is correct. The Electron app will show an empty
  // vault, and the user can add entries that get saved to SD.
}

void VaultManager::_buildViews() const {
  if (_viewsBuilt) return;
  for (int i = 0; i < _count; i++) {
    _entrySite[i] = _site[i];
    _entryUser[i] = _user[i];
    _entryPass[i] = _pass[i];
    _entryTotp[i] = _totp[i];
    _views[i] = {
      _entrySite[i], _entryUser[i], _entryPass[i], _entryTotp[i],
      _type[i], _favorite[i], _deleted[i],
      // LOGIN
      _url[i], _notes[i], _folder[i],
      // CARD
      _cardholder[i], _cardNumber[i], _exp[i], _cvv[i],
      // IDENTITY
      _firstName[i], _lastName[i], _email[i], _phone[i], _address[i],
      _city[i], _state[i], _postal[i], _country[i], _ssn[i],
      _passport[i], _license[i]
    };
  }
  _viewsBuilt = true;
}

VaultEntry VaultManager::entryAt(int idx) const {
  // All-empty default view — matches the full extended struct layout.
  // Field count: 4 (site,user,pass,totp) + 3 (type,fav,del) + 3 (url,notes,folder)
  // + 4 (cardholder,cardNumber,exp,cvv) + 12 (firstName,lastName,email,phone,
  // address,city,state,postal,country,ssn,passport,license) = 26 total.
  static VaultEntry empty = {
    "", "", "", "", 0, false, false,
    "", "", "",        // url, notes, folder           (3)
    "", "", "", "",    // cardholder, cardNumber, exp, cvv  (4)
    "", "", "", "", "", "", "", "", "", "", "", ""   // identity fields  (12)
  };
  // Guard: if PSRAM allocation failed in begin(), _site is null. Return
  // the empty entry instead of crashing on null-pointer dereference.
  if (!_storageAllocated || !_site) return empty;
  if (idx < 0 || idx >= _count) return empty;
  _buildViews();
  return _views[idx];
}

void VaultManager::_loadDemo() {
  // NOTE: _allocStorage() (called by begin() before this) already zeroed
  // every array, so we don't need to re-zero here. The old static-array
  // version used memset(..., 0, sizeof(...)) but that doesn't work on
  // heap-allocated pointer-to-array — sizeof(_site) would give 4 (pointer
  // size), not MAX_ENTRIES * 32. _allocStorage handles the zeroing.

  // ── Demo logins ────────────────────────────────────────────────────
  // Each row: { site, user, pass, totp, url }
  static const char* demoLogins[][5] = {
    { "Google",      "me@gmail.com",   "MyGoogle#Pass1",  "JBSWY3DPEHPK3PXP", "https://google.com"   },
    { "GitHub",      "purujith",       "GitHubSecret456", "JBSWY3DPEHPK3PXP", "https://github.com"   },
    { "IIT Madras",  "21f3002345",     "Iitm@Portal99",   "",                 "https://iitm.ac.in"   },
    { "Twitter/X",   "venom_handle",   "Tw!tterPass789",  "BASE32SECRETHERE", "https://x.com"        },
    { "Amazon",      "me@gmail.com",   "AmzSecure!2024",  "",                 "https://amazon.com"   },
    { "Netflix",     "venom_stream",   "NflxWatch#22",    "",                 "https://netflix.com"  },
    { "Spotify",     "venom_music",    "Sp0tify!Beats",   "",                 "https://spotify.com"  },
    { "LinkedIn",    "purujith.k",     "LinkedPro#99",    "JBSWY3DPEHPK3PXP", "https://linkedin.com" },
    { "Discord",     "venom#0420",     "DiscSecure!1",    "",                 "https://discord.com"  },
    { "Reddit",      "u_venom_dev",    "RedditPass#7",    "",                 "https://reddit.com"   },
    { "ProtonMail",  "venom@proton",   "Pr0tonSecure9",   "JBSWY3DPEHPK3PXP", "https://proton.me"    },
    { "Steam",       "venom_steam",    "SteamGame!42",    "",                 "https://steam.com"    },
    { "PayPal",      "me@gmail.com",   "PayPalSafe#3",    "BASE32SECRETHERE", "https://paypal.com"   },
    { "Dropbox",     "venom.files",    "DropSecure!5",    "",                 "https://dropbox.com"  },
    { "Notion",      "venom_notes",    "NotionPass#8",    "",                 "https://notion.so"    },
    { "Figma",       "venom_design",   "FigmaSecure!6",   "",                 "https://figma.com"    },
    { "Vercel",      "venom_dev",      "VercelDeploy#1",  "",                 "https://vercel.com"   },
    { "Cloudflare",  "venom_cf",       "CfSecure!2024",   "JBSWY3DPEHPK3PXP", "https://cloudflare.com" },
    { "DigitalOcean","venom_do",       "DoDroplet#9",     "",                 "https://digitalocean.com" },
    { "OpenAI",      "venom_ai",       "OpenAiKey#11",    "",                 "https://openai.com"   },
  };
  int nLogins = sizeof(demoLogins) / sizeof(demoLogins[0]);
  for (int i = 0; i < nLogins && i < MAX_ENTRIES; i++) {
    strncpy(_site[i], demoLogins[i][0], sizeof(_site[0]) - 1);
    strncpy(_user[i], demoLogins[i][1], sizeof(_user[0]) - 1);
    strncpy(_pass[i], demoLogins[i][2], sizeof(_pass[0]) - 1);
    strncpy(_totp[i], demoLogins[i][3], sizeof(_totp[0]) - 1);
    strncpy(_url[i],  demoLogins[i][4], sizeof(_url[0]) - 1);
    _type[i] = 0;  // login
    _favorite[i] = false;
    _deleted[i] = false;
  }

  // ── Demo cards ─────────────────────────────────────────────────────
  // { site, cardholder, cardNumber, exp, cvv }
  static const char* demoCards[][5] = {
    { "Visa - Primary",   "Purujith K",  "4111 1111 1111 1111", "08/27", "123" },
    { "Mastercard - Travel","P. Kumar",  "5555 5555 5555 4444", "11/26", "456" },
    { "Amex - Business",  "Purujith K",  "3782 822463 10005",   "03/28", "7890" },
  };
  int nCards = sizeof(demoCards) / sizeof(demoCards[0]);
  for (int i = 0; i < nCards && (nLogins + i) < MAX_ENTRIES; i++) {
    int idx = nLogins + i;
    strncpy(_site[idx],        demoCards[i][0], sizeof(_site[0]) - 1);
    strncpy(_cardholder[idx],  demoCards[i][1], sizeof(_cardholder[0]) - 1);
    strncpy(_cardNumber[idx],  demoCards[i][2], sizeof(_cardNumber[0]) - 1);
    strncpy(_exp[idx],         demoCards[i][3], sizeof(_exp[0]) - 1);
    strncpy(_cvv[idx],         demoCards[i][4], sizeof(_cvv[0]) - 1);
    _type[idx] = 1;  // card
    _favorite[idx] = (i == 0);  // pin the primary Visa
  }

  // ── Demo identities ────────────────────────────────────────────────
  // { site, firstName, lastName, email, phone, address, city, state, postal, country, ssn, passport, license }
  static const char* demoIds[][13] = {
    {
      "Personal ID",
      "Purujith", "Kumar",
      "purujith@example.com", "+91 98765 43210",
      "42 Sea View Rd, Apt 7B", "Chennai", "TN", "600020", "India",
      "123-45-6789", "P1234567", "TN0120230001234"
    },
    {
      "Work ID",
      "Purujith", "K",
      "purujith.k@iitm.ac.in", "+91 90000 11111",
      "IIT Madras Campus", "Chennai", "TN", "600036", "India",
      "987-65-4321", "P7654321", "TN0120190005678"
    },
  };
  int nIds = sizeof(demoIds) / sizeof(demoIds[0]);
  for (int i = 0; i < nIds && (nLogins + nCards + i) < MAX_ENTRIES; i++) {
    int idx = nLogins + nCards + i;
    strncpy(_site[idx],       demoIds[i][0],  sizeof(_site[0]) - 1);
    strncpy(_firstName[idx],  demoIds[i][1],  sizeof(_firstName[0]) - 1);
    strncpy(_lastName[idx],   demoIds[i][2],  sizeof(_lastName[0]) - 1);
    strncpy(_email[idx],      demoIds[i][3],  sizeof(_email[0]) - 1);
    strncpy(_phone[idx],      demoIds[i][4],  sizeof(_phone[0]) - 1);
    strncpy(_address[idx],    demoIds[i][5],  sizeof(_address[0]) - 1);
    strncpy(_city[idx],       demoIds[i][6],  sizeof(_city[0]) - 1);
    strncpy(_state[idx],      demoIds[i][7],  sizeof(_state[0]) - 1);
    strncpy(_postal[idx],     demoIds[i][8],  sizeof(_postal[0]) - 1);
    strncpy(_country[idx],    demoIds[i][9],  sizeof(_country[0]) - 1);
    strncpy(_ssn[idx],        demoIds[i][10], sizeof(_ssn[0]) - 1);
    strncpy(_passport[idx],   demoIds[i][11], sizeof(_passport[0]) - 1);
    strncpy(_license[idx],    demoIds[i][12], sizeof(_license[0]) - 1);
    _type[idx] = 2;  // identity
    _favorite[idx] = (i == 0);
  }

  // ── Demo notes ─────────────────────────────────────────────────────
  // { site, notes }
  static const char* demoNotes[][2] = {
    { "Wi-Fi Password",  "Home SSID: Venom_5G, WPA3 passphrase: Sp!derMan#2099" },
    { "Server Root Key", "ssh-ed25519 root@prod-01 — AAAAC3NzaC1lZDI1NTE5AAAAI..." },
    { "Luggage Combo",   "TSA lock: 7-2-9 (the same as my birthday reversed)" },
  };
  int nNotes = sizeof(demoNotes) / sizeof(demoNotes[0]);
  for (int i = 0; i < nNotes && (nLogins + nCards + nIds + i) < MAX_ENTRIES; i++) {
    int idx = nLogins + nCards + nIds + i;
    strncpy(_site[idx],  demoNotes[i][0], sizeof(_site[0]) - 1);
    strncpy(_notes[idx], demoNotes[i][1], sizeof(_notes[0]) - 1);
    _type[idx] = 3;  // note
  }

  _count = nLogins + nCards + nIds + nNotes;
  _viewsBuilt = false;
}

void VaultManager::_zeroEntrySlot(int i) {
  if (i < 0 || i >= MAX_ENTRIES) return;
  _site[i][0] = 0;
  _user[i][0] = 0;
  _pass[i][0] = 0;
  _totp[i][0] = 0;
  _url[i][0] = 0;
  _notes[i][0] = 0;
  _folder[i][0] = 0;
  _cardholder[i][0] = 0;
  _cardNumber[i][0] = 0;
  _exp[i][0] = 0;
  _cvv[i][0] = 0;
  _firstName[i][0] = 0;
  _lastName[i][0] = 0;
  _email[i][0] = 0;
  _phone[i][0] = 0;
  _address[i][0] = 0;
  _city[i][0] = 0;
  _state[i][0] = 0;
  _postal[i][0] = 0;
  _country[i][0] = 0;
  _ssn[i][0] = 0;
  _passport[i][0] = 0;
  _license[i][0] = 0;
}

void VaultManager::_appendCsvField(String& out, const char* field, bool last) {
  bool needsQuote = false;
  for (const char* p = field; *p; p++) {
    if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') { needsQuote = true; break; }
  }
  if (needsQuote) {
    out += '"';
    for (const char* p = field; *p; p++) {
      if (*p == '"') out += "\"\""; // RFC4180: escape " as ""
      else out += *p;
    }
    out += '"';
  } else {
    out += field;
  }
  out += last ? "\n" : ",";
}

bool VaultManager::_parseCsvLine(const String& line, String outFields[4]) {
  int field = 0;
  int i = 0;
  int len = line.length();
  while (field < 4) {
    String value;
    if (i < len && line[i] == '"') {
      // Quoted field -- scan until the closing quote, unescaping "" -> "
      i++;
      while (i < len) {
        if (line[i] == '"') {
          if (i + 1 < len && line[i + 1] == '"') { value += '"'; i += 2; }
          else { i++; break; } // closing quote
        } else {
          value += line[i++];
        }
      }
    } else {
      // Unquoted field -- read until the next comma or end of line
      while (i < len && line[i] != ',') value += line[i++];
    }
    outFields[field++] = value;
    if (i < len && line[i] == ',') { i++; continue; }
    break;
  }
  // Any fields not present in a short line are simply left empty --
  // matches how a spreadsheet would export a row with trailing blanks.
  for (; field < 4; field++) outFields[field] = "";
  return true;
}

String VaultManager::exportCSV() const {
  String out;
  out.reserve(256 + _count * 96);
  out += "site,user,pass,totp\n";
  for (int i = 0; i < _count; i++) {
    _appendCsvField(out, _site[i], false);
    _appendCsvField(out, _user[i], false);
    _appendCsvField(out, _pass[i], false);
    _appendCsvField(out, _totp[i], true);
  }
  return out;
}

bool VaultManager::importCSV(const String& csvText, const char* pin) {
  // Parse into a scratch buffer first -- don't touch _site/_user/_pass/
  // _totp until we know the whole file is valid, so a bad upload can't
  // half-overwrite the existing vault.
  //
  // NOTE: these are `static`, not stack locals. 64*(32+48+48+32) = 10240
  // bytes -- on their own, more than CONFIG_ARDUINO_LOOP_STACK_SIZE (8192
  // in sdkconfig.edgehax-s3-pro), before counting anything else in the
  // loopTask -> loop() -> ... -> importCSV() call chain. As stack locals
  // this reliably overflowed the task stack and corrupted heap metadata
  // sitting past it -- the actual crash didn't surface until the next
  // unrelated free() (see the identical issue fixed in _applyJSON below).
  //
  // v9.12.1: Converted from `static` (BSS) to heap-allocated (PSRAM) so
  // the v9.10 per-type expansion doesn't overflow dram0_0_seg. Same
  // single-task reentrancy guarantee — importCSV is only called from
  // the UI task, and the scratch is fully written before use.
  char (*newSite)[32] = reinterpret_cast<char (*)[32]>(static_cast<char*>(largeAlloc(MAX_ENTRIES * 32)));
  char (*newUser)[48] = reinterpret_cast<char (*)[48]>(static_cast<char*>(largeAlloc(MAX_ENTRIES * 48)));
  char (*newPass)[48] = reinterpret_cast<char (*)[48]>(static_cast<char*>(largeAlloc(MAX_ENTRIES * 48)));
  char (*newTotp)[32] = reinterpret_cast<char (*)[32]>(static_cast<char*>(largeAlloc(MAX_ENTRIES * 32)));
  if (!newSite || !newUser || !newPass || !newTotp) {
    Serial.println("[VaultManager] importCSV: scratch alloc failed (PSRAM?)");
    largeFree(reinterpret_cast<char*>(newSite));
    largeFree(reinterpret_cast<char*>(newUser));
    largeFree(reinterpret_cast<char*>(newPass));
    largeFree(reinterpret_cast<char*>(newTotp));
    return false;
  }
  memset(newSite, 0, MAX_ENTRIES * 32);
  memset(newUser, 0, MAX_ENTRIES * 48);
  memset(newPass, 0, MAX_ENTRIES * 48);
  memset(newTotp, 0, MAX_ENTRIES * 32);
  int newCount = 0;

  int pos = 0;
  int len = csvText.length();
  bool firstLine = true;
  while (pos < len && newCount < MAX_ENTRIES) {
    int nl = csvText.indexOf('\n', pos);
    String line = (nl == -1) ? csvText.substring(pos) : csvText.substring(pos, nl);
    pos = (nl == -1) ? len : nl + 1;
    line.trim(); // drop trailing \r from CRLF exports (Excel/Windows)
    if (line.length() == 0) continue;

    if (firstLine) {
      // Skip the "site,user,pass,totp" header row if present -- detect
      // by checking the first field isn't meant to be a real site name.
      firstLine = false;
      String lower = line; lower.toLowerCase();
      if (lower.startsWith("site,user,pass")) continue;
    }

    String fields[4];
    _parseCsvLine(line, fields);
    if (fields[0].length() == 0) continue; // skip rows with no site name

    strncpy(newSite[newCount], fields[0].c_str(), sizeof(newSite[0]) - 1);
    newSite[newCount][sizeof(newSite[0]) - 1] = 0;
    strncpy(newUser[newCount], fields[1].c_str(), sizeof(newUser[0]) - 1);
    newUser[newCount][sizeof(newUser[0]) - 1] = 0;
    strncpy(newPass[newCount], fields[2].c_str(), sizeof(newPass[0]) - 1);
    newPass[newCount][sizeof(newPass[0]) - 1] = 0;
    strncpy(newTotp[newCount], fields[3].c_str(), sizeof(newTotp[0]) - 1);
    newTotp[newCount][sizeof(newTotp[0]) - 1] = 0;
    newCount++;
  }

  if (newCount == 0) {
    largeFree(reinterpret_cast<char*>(newSite));
    largeFree(reinterpret_cast<char*>(newUser));
    largeFree(reinterpret_cast<char*>(newPass));
    largeFree(reinterpret_cast<char*>(newTotp));
    return false; // empty/unparseable upload -- leave vault untouched
  }

  // sizeof(_site) won't work (pointer now), so use explicit byte counts
  memcpy(_site, newSite, MAX_ENTRIES * 32);
  memcpy(_user, newUser, MAX_ENTRIES * 48);
  memcpy(_pass, newPass, MAX_ENTRIES * 48);
  memcpy(_totp, newTotp, MAX_ENTRIES * 32);
  // CSV import only fills the 4 core fields; zero all the per-type extras
  // so an import from CSV doesn't leave stale card/identity/note data
  // from a previous vault state.
  memset(_type, 0, MAX_ENTRIES);
  memset(_favorite, 0, MAX_ENTRIES);
  memset(_deleted, 0, MAX_ENTRIES);
  memset(_url, 0, MAX_ENTRIES * 64);
  memset(_notes, 0, MAX_ENTRIES * 160);
  memset(_folder, 0, MAX_ENTRIES * 24);
  memset(_cardholder, 0, MAX_ENTRIES * 32);
  memset(_cardNumber, 0, MAX_ENTRIES * 24);
  memset(_exp, 0, MAX_ENTRIES * 8);
  memset(_cvv, 0, MAX_ENTRIES * 5);
  memset(_firstName, 0, MAX_ENTRIES * 24);
  memset(_lastName, 0, MAX_ENTRIES * 24);
  memset(_email, 0, MAX_ENTRIES * 48);
  memset(_phone, 0, MAX_ENTRIES * 20);
  memset(_address, 0, MAX_ENTRIES * 48);
  memset(_city, 0, MAX_ENTRIES * 24);
  memset(_state, 0, MAX_ENTRIES * 24);
  memset(_postal, 0, MAX_ENTRIES * 12);
  memset(_country, 0, MAX_ENTRIES * 24);
  memset(_ssn, 0, MAX_ENTRIES * 16);
  memset(_passport, 0, MAX_ENTRIES * 24);
  memset(_license, 0, MAX_ENTRIES * 24);
  _count = newCount;
  _viewsBuilt = false;
  // v10.0: bulk replace invalidates every previous disk-slot assignment --
  // the upcoming saveToSD() (now a full rewrite) reassigns slot i == index i
  // for every entry, same as it does for any other full rewrite.
  for (int i = 0; i < MAX_ENTRIES; i++) _diskSlot[i] = -1;

  largeFree(reinterpret_cast<char*>(newSite));
  largeFree(reinterpret_cast<char*>(newUser));
  largeFree(reinterpret_cast<char*>(newPass));
  largeFree(reinterpret_cast<char*>(newTotp));

  saveToSD(pin);
  return true;
}

// ── Big-endian integer helpers ──────────────────────────────────────────
// Explicit byte order (not just memcpy of a uint32_t) so the on-disk
// format is portable and matches the JS-side reimplementation exactly
// (Buffer.readUInt32BE/writeUInt32BE), regardless of host endianness.
static void putU32BE(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint32_t getU32BE(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}
static void putU16BE(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}

// v10.0: Per-entry JSON serialization (replaces _toJSON's per-array-element
// body). Same 25 fields, just for ONE entry instead of the whole vault --
// this is the whole point: a single ADD/UPDATE only ever builds ~1KB of
// JSON, not ~180KB for a 256-entry vault.
size_t VaultManager::_entryToJSON(int i, char* out, size_t outCap) const {
  JsonDocument doc;
  JsonObject o = doc.to<JsonObject>();
  o["site"] = _site[i];
  o["user"] = _user[i];
  o["pass"] = _pass[i];
  o["totp"] = _totp[i];
  o["type"] = vaultTypeToStr(_type[i]);
  o["fav"]  = _favorite[i] ? 1 : 0;
  o["del"]  = _deleted[i]  ? 1 : 0;
  o["url"]        = _url[i];
  o["notes"]      = _notes[i];
  o["folder"]     = _folder[i];
  o["cardholder"] = _cardholder[i];
  o["cardNumber"] = _cardNumber[i];
  o["exp"]        = _exp[i];
  o["cvv"]        = _cvv[i];
  o["firstName"] = _firstName[i];
  o["lastName"]  = _lastName[i];
  o["email"]     = _email[i];
  o["phone"]     = _phone[i];
  o["address"]   = _address[i];
  o["city"]      = _city[i];
  o["state"]     = _state[i];
  o["postal"]    = _postal[i];
  o["country"]   = _country[i];
  o["ssn"]       = _ssn[i];
  o["passport"]  = _passport[i];
  o["license"]   = _license[i];
  // Writes directly into `out` (a stack buffer at every call site, never
  // heap) -- deliberately NOT returning a String here. A String's backing
  // buffer would be just another heap allocation whose PSRAM-vs-internal
  // placement we can't control, and this JSON is the plaintext source fed
  // straight into aesGcmEncrypt's DMA-based AES engine (see cryptoAlloc
  // above for why that placement matters).
  size_t len = serializeJson(doc, out, outCap);
  if (len >= outCap) len = outCap > 0 ? outCap - 1 : 0; // shouldn't happen (outCap is generous), but never overrun
  return len;
}

// v10.0: Parses ONE entry object (not an array) into the live storage
// arrays at destIdx. Mirrors _applyJSON's old per-element loop body.
// Returns false (and leaves destIdx's slot zeroed) on any parse problem
// -- callers treat that as "skip this one record" rather than failing
// the whole vault, since a corrupt/unreadable individual record should
// not cost the user every other entry.
bool VaultManager::_jsonToEntry(const char* json, size_t len, int destIdx) {
  if (destIdx < 0 || destIdx >= MAX_ENTRIES) return false;
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, json, len);
  if (err) return false;
  JsonObject o = doc.as<JsonObject>();
  if (o.isNull()) return false;
  const char* site = o["site"] | "";
  if (site[0] == '\0') return false; // same "site required" rule _applyJSON used

  auto copyStr = [](char* dst, size_t dstSize, const char* src) {
    if (dstSize == 0) return;
    if (src && src[0]) { strncpy(dst, src, dstSize - 1); dst[dstSize - 1] = 0; }
    else dst[0] = 0;
  };

  _zeroEntrySlot(destIdx);
  copyStr(_site[destIdx],  sizeof(_site[0]),  site);
  copyStr(_user[destIdx],  sizeof(_user[0]),  o["user"] | "");
  copyStr(_pass[destIdx],  sizeof(_pass[0]),  o["pass"] | "");
  copyStr(_totp[destIdx],  sizeof(_totp[0]),  o["totp"] | "");
  copyStr(_url[destIdx],        sizeof(_url[0]),        o["url"]        | "");
  copyStr(_notes[destIdx],      sizeof(_notes[0]),      o["notes"]      | "");
  copyStr(_folder[destIdx],     sizeof(_folder[0]),     o["folder"]     | "");
  copyStr(_cardholder[destIdx], sizeof(_cardholder[0]), o["cardholder"] | "");
  copyStr(_cardNumber[destIdx], sizeof(_cardNumber[0]), o["cardNumber"] | "");
  copyStr(_exp[destIdx],        sizeof(_exp[0]),        o["exp"]        | "");
  copyStr(_cvv[destIdx],        sizeof(_cvv[0]),        o["cvv"]        | "");
  copyStr(_firstName[destIdx], sizeof(_firstName[0]), o["firstName"] | "");
  copyStr(_lastName[destIdx],  sizeof(_lastName[0]),  o["lastName"]  | "");
  copyStr(_email[destIdx],     sizeof(_email[0]),     o["email"]     | "");
  copyStr(_phone[destIdx],     sizeof(_phone[0]),     o["phone"]     | "");
  copyStr(_address[destIdx],   sizeof(_address[0]),   o["address"]   | "");
  copyStr(_city[destIdx],      sizeof(_city[0]),      o["city"]      | "");
  copyStr(_state[destIdx],     sizeof(_state[0]),     o["state"]     | "");
  copyStr(_postal[destIdx],    sizeof(_postal[0]),    o["postal"]    | "");
  copyStr(_country[destIdx],   sizeof(_country[0]),   o["country"]   | "");
  copyStr(_ssn[destIdx],       sizeof(_ssn[0]),       o["ssn"]       | "");
  copyStr(_passport[destIdx],  sizeof(_passport[0]),  o["passport"]  | "");
  copyStr(_license[destIdx],   sizeof(_license[0]),   o["license"]   | "");

  bool fav = false, del = false;
  if (o["fav"].is<bool>()) fav = o["fav"].as<bool>();
  else if (o["fav"].is<int>()) fav = o["fav"].as<int>() != 0;
  if (o["del"].is<bool>()) del = o["del"].as<bool>();
  else if (o["del"].is<int>()) del = o["del"].as<int>() != 0;
  _favorite[destIdx] = fav;
  _deleted[destIdx]  = del;

  String typeRaw = o["type"].as<String>();
  _type[destIdx] = vaultStrToType(typeRaw.c_str());
  return true;
}

// ── Row table helpers (all fixed-offset seeks -- O(1) I/O) ─────────────
size_t VaultManager::_rowFileOffset(int slot) const {
  return DB_TABLE_OFFSET + (size_t)slot * DB_ROW_LEN;
}

bool VaultManager::_writeRowToFile(File& f, int slot) {
  if (slot < 0 || slot >= MAX_ENTRIES) return false;
  uint8_t buf[DB_ROW_LEN];
  buf[0] = _rowStatus[slot];
  putU32BE(buf + 1, _rowOffset[slot]);
  putU32BE(buf + 5, _rowLen[slot]);
  memcpy(buf + 9, _rowIv[slot], VAULT_IV_LEN);
  memcpy(buf + 9 + VAULT_IV_LEN, _rowTag[slot], VAULT_TAG_LEN);
  if (!f.seek(_rowFileOffset(slot))) return false;
  return f.write(buf, DB_ROW_LEN) == DB_ROW_LEN;
}

bool VaultManager::_writeDataEndToFile(File& f) {
  uint8_t buf[6];
  putU32BE(buf, _dataEnd);
  putU16BE(buf + 4, (uint16_t)_count);
  if (!f.seek(sizeof(DB_MAGIC) + 1 + VAULT_SALT_LEN)) return false; // offset 21
  return f.write(buf, 6) == 6;
}

// Reads dataEnd + the full 256-row table from `f` (already open,
// positioned anywhere -- this seeks explicitly) into the RAM mirror.
// Does NOT validate magic/version -- caller must do that first.
bool VaultManager::_readTableFromFile(File& f) {
  uint8_t hdrRest[6];
  if (!f.seek(sizeof(DB_MAGIC) + 1 + VAULT_SALT_LEN)) return false;
  if (f.read(hdrRest, 6) != 6) return false;
  _dataEnd = getU32BE(hdrRest);
  // hdrRest+4 (liveCount) is informational only -- _count is always
  // re-derived by counting occupied rows as they're loaded, below.

  if (!f.seek(DB_TABLE_OFFSET)) return false;
  for (int i = 0; i < MAX_ENTRIES; i++) {
    uint8_t buf[DB_ROW_LEN];
    if (f.read(buf, DB_ROW_LEN) != (int)DB_ROW_LEN) return false;
    _rowStatus[i] = buf[0];
    _rowOffset[i] = getU32BE(buf + 1);
    _rowLen[i]    = getU32BE(buf + 5);
    memcpy(_rowIv[i],  buf + 9, VAULT_IV_LEN);
    memcpy(_rowTag[i], buf + 9 + VAULT_IV_LEN, VAULT_TAG_LEN);
    if ((i & 0x3F) == 0x3F) vTaskDelay(pdMS_TO_TICKS(1)); // feed WDT
  }
  return true;
}

int VaultManager::_findFreeRow() const {
  for (int i = 0; i < MAX_ENTRIES; i++) if (_rowStatus[i] == 0) return i;
  return -1;
}

// Decrypts every occupied row from an already-open, header-validated
// file and populates the live in-memory arrays + _diskSlot[], exactly
// like _applyJSON used to do from one big blob -- just one small
// decrypt+parse per record instead of one giant one. A record that
// fails to decrypt or parse is SKIPPED (logged, not fatal) -- a
// resilience upgrade over SVL1, where any single corruption lost the
// entire vault.
//
// v10.7 PERF: Bulk-read the entire data area into PSRAM in ONE f.read()
// call, then decrypt/parse each entry from the in-memory buffer instead
// of doing f.seek()+f.read() PER ENTRY. The per-entry seek+read on FAT32
// SD cards costs ~15-25ms each (FAT cluster chain walk + SPI transfer
// setup), which for a 100-entry vault added ~2-4 SECONDS of pure SD
// I/O overhead to every unlock. With the bulk read:
//   - 1 SD read of ~20-100KB (typical vault): ~50-150ms total
//   - per-entry cost drops to just AES-GCM (~1-3ms) + JSON parse (~1-2ms)
//   - 100-entry vault: ~500ms total decrypt+parse vs ~3-5s before
//
// The bulk buffer is allocated from PSRAM (8MB available on the S3-PRO).
// Falls back to per-entry SD reads if the allocation fails (very low
// free PSRAM) or if the data area is implausibly large (>1MB cap, which
// would only happen with a corrupted _dataEnd field).
bool VaultManager::_loadRecordsFromOpenFile(File& f, const uint8_t* key) {
  if (!_readTableFromFile(f)) return false;
  _count = 0;

  // ── v10.7: Bulk-read the data area into PSRAM ──────────────────────
  uint32_t dataBytes = _dataEnd;
  uint8_t* dataBuf = nullptr;
  // Sanity cap at 1MB. _dataEnd is the next-append offset (high-water
  // mark of all live + dead data bytes). A real vault never approaches
  // 1MB -- 256 max-2048-byte records = 512KB absolute worst case, and
  // typical vaults are 10-100KB. A value over 1MB means _dataEnd is
  // corrupted (the self-heal below will fix it for next time, but we
  // don't want to attempt a 4GB malloc this pass).
  if (dataBytes > 0 && dataBytes <= 1024 * 1024) {
    dataBuf = (uint8_t*)largeAlloc(dataBytes);
    if (dataBuf) {
      if (!f.seek(DB_DATA_OFFSET) || f.read(dataBuf, dataBytes) != (int)dataBytes) {
        // Bulk read failed (rare — SD card glitch). Fall back to per-entry reads.
        largeFree(dataBuf);
        dataBuf = nullptr;
      }
    }
    // If heap_caps_malloc returned null (PSRAM exhausted), we silently
    // fall back to per-entry reads below -- still correct, just slower.
  }

  for (int slot = 0; slot < MAX_ENTRIES; slot++) {
    if (_rowStatus[slot] != 1) continue;
    if (_count >= MAX_ENTRIES) break;
    uint32_t clen = _rowLen[slot];
    if (clen == 0 || clen > MAX_RECORD_JSON_LEN) {
      Serial.printf("[VaultManager] SVR1 row %d has implausible length %u -- skipped\n", slot, clen);
      continue;
    }

    // plainBuf always needs its own DMA-capable allocation (it's the
    // AES engine's output destination, which must be internal SRAM).
    uint8_t* plainBuf  = (uint8_t*)cryptoAlloc(clen + 1);
    bool ok = (plainBuf != nullptr);

    // cipherBuf: either point into the bulk PSRAM buffer (fast path, no
    // per-entry SD I/O), or allocate a DMA-capable buffer and f.read()
    // into it (slow fallback). aesGcmDecrypt takes a const ciphertext
    // pointer so pointing into PSRAM is fine -- the AES DMA engine only
    // WRITES to plaintextOut, which is always in internal SRAM.
    uint8_t* cipherBuf = nullptr;
    bool ownsCipherBuf = false;  // true => we alloc'd it, must free it
    if (ok) {
      if (dataBuf && _rowOffset[slot] + clen <= dataBytes) {
        // Fast path: ciphertext already in PSRAM bulk buffer.
        cipherBuf = dataBuf + _rowOffset[slot];
      } else {
        // Slow fallback: per-entry SD seek+read.
        if (!f.seek(DB_DATA_OFFSET + _rowOffset[slot])) { ok = false; }
        if (ok) {
          cipherBuf = (uint8_t*)cryptoAlloc(clen);
          ownsCipherBuf = (cipherBuf != nullptr);
          ok = ownsCipherBuf && (f.read(cipherBuf, clen) == (int)clen);
        }
      }
    }

    if (ok) ok = aesGcmDecrypt(key, _rowIv[slot], VAULT_IV_LEN, cipherBuf, clen, _rowTag[slot], plainBuf);
    if (ok) {
      plainBuf[clen] = '\0';
      ok = _jsonToEntry(reinterpret_cast<const char*>(plainBuf), clen, _count);
    }
    if (ok) {
      _diskSlot[_count] = slot;
      _count++;
    } else {
      Serial.printf("[VaultManager] SVR1 row %d failed to decrypt/parse -- skipped\n", slot);
    }
    if (plainBuf) secureZero(plainBuf, clen + 1);
    cryptoFree(plainBuf);
    if (ownsCipherBuf) cryptoFree(cipherBuf);
    // Yield every 32 entries (was 16). With bulk-read the per-entry cost
    // is now ~3-5ms instead of ~25ms, so the loop runs ~5x faster and we
    // can afford to yield half as often without risking the Task WDT.
    if ((slot & 0x1F) == 0x1F) vTaskDelay(pdMS_TO_TICKS(1));
  }

  if (dataBuf) {
    // Best-effort wipe of any plaintext-adjacent bytes that the AES engine
    // may have left in the bulk buffer (it doesn't, but defense-in-depth).
    // Then free the PSRAM back to the pool before the caller transitions
    // to the VAULT screen (which does its own heap work for the UI).
    memset(dataBuf, 0, dataBytes);
    largeFree(dataBuf);
  }
  _viewsBuilt = false;

  // ── v-fix: self-heal a stale/inflated dataEnd header field ──────────
  // _dataEnd (read from the header in _readTableFromFile above) is meant
  // to be "one past the last used data byte" -- every ADD/UPDATE append
  // writes at exactly this offset. If an OLDER firmware build ever
  // truncated+re-patched this file (the pre-v10.2 FILE_WRITE("w+") bug)
  // or a write was interrupted mid-flight, this field can end up LARGER
  // than where any real row data actually sits. Every occupied row still
  // reads back fine here (each read seeks to its OWN offset+length,
  // independent of dataEnd), so handshake/LIST/GET all look completely
  // healthy -- but the NEXT append seeks to this bogus dataEnd and writes
  // there. On a FAT32 SD card, seeking+writing far past the actual file
  // size forces the driver to zero-fill every cluster in between, which
  // for a sufficiently inflated value can take tens of seconds to
  // minutes -- past any host-side serial timeout. That's the "ADD hangs
  // for ~60s then the port disconnects" symptom, and it can ONLY show up
  // on the first write after load, since reads never touch dataEnd.
  //
  // Fix: recompute the real high-water mark from the row table we just
  // loaded (max of offset+length over all occupied rows) instead of
  // blindly trusting the header field. Non-destructive and self-healing
  // -- no entry data is touched, this only corrects where the NEXT
  // append will land. The repaired value is written back to the header
  // automatically the next time any ADD/UPDATE/DELETE succeeds.
  uint32_t realDataEnd = 0;
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (_rowStatus[i] == 1) {
      uint32_t rowEnd = _rowOffset[i] + _rowLen[i];
      if (rowEnd > realDataEnd) realDataEnd = rowEnd;
    }
  }
  if (realDataEnd != _dataEnd) {
    Serial.printf("[VaultManager] REPAIR: header dataEnd=%u did not match actual row data "
                  "(true high-water mark=%u) -- correcting in memory to avoid a multi-minute "
                  "stall on the next write\n", (unsigned)_dataEnd, (unsigned)realDataEnd);
    _dataEnd = realDataEnd;
  }

  return true; // header/table read succeeded -- individual record misses don't fail the load
}

// Opens `path`, validates the SVR1 header, derives (or reuses) the key,
// and loads every record via _loadRecordsFromOpenFile(). Shared by the
// primary vault.db load and the vault.db.bak fallback in loadFromSD().
// `setLoadError`: the .bak fallback attempt intentionally does NOT
// clobber _lastLoadError -- it's an internal recovery attempt, and the
// error the user sees should describe the PRIMARY failure, matching the
// original SVL1 code's behavior.
bool VaultManager::_tryLoadFile(const char* path, const char* pin, bool setLoadError) {
  File f = SD.open(path, FILE_READ);
  if (!f) {
    if (setLoadError) _lastLoadError = LoadError::SD_FAILED;
    return false;
  }
  size_t fileLen = f.size();
  if (fileLen < DB_DATA_OFFSET) { // must at least hold header + full row table
    f.close();
    if (setLoadError) _lastLoadError = LoadError::BAD_FORMAT;
    return false;
  }
  uint8_t hdr[5];
  if (f.read(hdr, 5) != 5 || memcmp(hdr, DB_MAGIC, 4) != 0 || hdr[4] != DB_VERSION) {
    f.close();
    if (setLoadError) _lastLoadError = LoadError::BAD_FORMAT;
    return false;
  }
  uint8_t salt[VAULT_SALT_LEN];
  if (f.read(salt, VAULT_SALT_LEN) != (int)VAULT_SALT_LEN) {
    f.close();
    if (setLoadError) _lastLoadError = LoadError::SD_FAILED;
    return false;
  }
  uint8_t key[VAULT_KEY_LEN];
  // v10.5: Skip the PBKDF2 derivation when the key is already cached
  // AND the salt on disk matches the salt we cached. This is the normal
  // case after the first successful unlock — the key stays cached in SRAM
  // until clearCachedKey() is called (lock / disconnect / sleep). Without
  // this check, every re-unlock re-ran PBKDF2 even though the key was
  // already in memory, adding pure wasted work to every unlock.
  //
  // v10.6: VAULT_KDF_ITERATIONS was reduced 20000 → 2000 for ~10x faster
  // unlock. To avoid breaking existing v10.5 vaults (which were encrypted
  // with a 20000-iteration key), we retry with VAULT_KDF_ITERATIONS_LEGACY
  // if the new key fails to decrypt any row. The legacy-derived key is
  // then cached just like the new one, so subsequent unlocks of the SAME
  // legacy vault are still fast (cache hit, no PBKDF2 at all). To PERMANENTLY
  // migrate a legacy vault to the new 2000-iter key, the user changes their
  // PIN (setPin → saveToSD → _rewriteWholeVault uses the new iter count).
  //
  // v10.7: Try the NVS-cached iter count FIRST when the SRAM key cache is
  // cold (i.e., on every reboot — SRAM is volatile). After the first
  // successful unlock of a v10.5-era vault, the working iter count
  // (20000) is persisted to NVS, so every subsequent unlock derives the
  // right key on the first try instead of doing the wasteful
  // derive-2000 → fail → derive-20000 retry dance. That retry added
  // ~2-3s to EVERY unlock of a legacy vault (not just the first one),
  // because the SRAM key cache is wiped on every reboot.
  uint32_t itersTriedFirst = 0;       // 0 = none, used for NVS persistence
  bool     usedCachedIters  = false;  // disambiguates the source for the same purpose
  if (_keyCached && memcmp(salt, _cachedSalt, VAULT_SALT_LEN) == 0) {
    memcpy(key, _cachedKey, VAULT_KEY_LEN);
  } else {
    uint32_t cachedIters = _getCachedKdfIters();
    if (cachedIters > 0) {
      // v10.7: Skip the 2000-iter guess and the legacy retry. We've
      // unlocked this vault before with this iter count — just use it.
      deriveVaultKeyWithIters(pin, salt, VAULT_SALT_LEN, cachedIters, key);
      itersTriedFirst = cachedIters;
      usedCachedIters = true;
    } else {
      deriveVaultKey(pin, salt, VAULT_SALT_LEN, key);  // 2000 iters, ~0.3s on ESP32-S3
      itersTriedFirst = VAULT_KDF_ITERATIONS;
    }
    vTaskDelay(pdMS_TO_TICKS(1));
  }

  bool ok = _loadRecordsFromOpenFile(f, key);
  f.close();

  if (ok) {
    // A wrong PIN "succeeds" structurally (the row table itself isn't
    // encrypted) but fails to decrypt every occupied row, leaving
    // _count == 0. Distinguish that from a genuinely empty vault by
    // checking whether any row was actually occupied.
    bool anyOccupied = false;
    for (int i = 0; i < MAX_ENTRIES; i++) if (_rowStatus[i] == 1) { anyOccupied = true; break; }
    if (anyOccupied && _count == 0) {
      // v10.6: Decrypt failed with the new 2000-iter key. If the key
      // wasn't cached (i.e., we just derived it fresh), retry with the
      // LEGACY 20000-iter count — this is the path that lets v10.5
      // vaults keep loading after the firmware upgrade. The retry adds
      // ~2-3s to the FIRST unlock of a legacy vault (one-time cost);
      // after that, the legacy key is cached and subsequent unlocks
      // hit the cache (instant, no PBKDF2 at all).
      //
      // v10.7: This legacy-retry path is now hit ONLY when the NVS
      // iter cache is empty (first unlock ever of a v10.5 vault on
      // v10.7+ firmware) OR when the cached iter count turns out to be
      // wrong (e.g., the vault file was swapped in from another device
      // with a different iter count). In the normal reboot-unlock case,
      // the NVS cache makes us try the right iter count first and we
      // never reach here.
      bool canRetry = !_keyCached;  // can only retry if we derived fresh (not from SRAM cache)
      if (usedCachedIters) {
        // The NVS-cached iters failed. Try 2000 next, then 20000 as
        // the final fallback. This handles the vault-was-swapped case.
        Serial.println("[VaultManager] v10.7: NVS-cached iters failed; retrying with 2000...");
        deriveVaultKey(pin, salt, VAULT_SALT_LEN, key);
        itersTriedFirst = VAULT_KDF_ITERATIONS;
        vTaskDelay(pdMS_TO_TICKS(1));
        f = SD.open(path, FILE_READ);
        if (f) {
          ok = _loadRecordsFromOpenFile(f, key);
          f.close();
        } else {
          ok = false;
        }
        if (ok) {
          anyOccupied = false;
          for (int i = 0; i < MAX_ENTRIES; i++) if (_rowStatus[i] == 1) { anyOccupied = true; break; }
          if (anyOccupied && _count == 0) ok = false;
        }
        // If 2000 also failed, fall through to the 20000 legacy retry below.
      }
      if (!ok && canRetry) {
        Serial.println("[VaultManager] v10.6: 2000-iter key failed to decrypt; retrying with legacy 20000 iters...");
        deriveVaultKeyWithIters(pin, salt, VAULT_SALT_LEN, VAULT_KDF_ITERATIONS_LEGACY, key);
        itersTriedFirst = VAULT_KDF_ITERATIONS_LEGACY;
        vTaskDelay(pdMS_TO_TICKS(1));
        // Re-open the file and retry the load.
        f = SD.open(path, FILE_READ);
        if (f) {
          // Re-seek past header + salt (already consumed above) to the
          // start of the row table, then re-run _loadRecordsFromOpenFile.
          // _loadRecordsFromOpenFile calls _readTableFromFile which seeks
          // to offset 5+saltLen on its own, so we just need the file open.
          ok = _loadRecordsFromOpenFile(f, key);
          f.close();
          if (ok) {
            // Re-check the anyOccupied && _count == 0 condition.
            anyOccupied = false;
            for (int i = 0; i < MAX_ENTRIES; i++) if (_rowStatus[i] == 1) { anyOccupied = true; break; }
            if (anyOccupied && _count == 0) {
              ok = false;  // genuinely wrong PIN or corrupt vault
              if (setLoadError) _lastLoadError = LoadError::DECRYPT_FAILED;
            } else {
              Serial.println("[VaultManager] v10.6: legacy 20000-iter key worked — vault is v10.5-format. Cached for fast re-unlock.");
            }
          } else {
            if (setLoadError) _lastLoadError = LoadError::BAD_FORMAT;
          }
        } else {
          if (setLoadError) _lastLoadError = LoadError::SD_FAILED;
          ok = false;
        }
      } else if (!ok) {
        if (setLoadError) _lastLoadError = LoadError::DECRYPT_FAILED;
      }
    }
  } else {
    if (setLoadError) _lastLoadError = LoadError::BAD_FORMAT;
  }

  if (ok) {
    memcpy(_cachedKey, key, VAULT_KEY_LEN);
    memcpy(_cachedSalt, salt, VAULT_SALT_LEN);
    _keyCached = true;
    // v10.7: Persist the iter count that worked into NVS, so the NEXT
    // unlock (which has a cold SRAM cache after reboot) tries this iter
    // count first and skips the legacy retry path entirely.
    if (itersTriedFirst != 0) {
      uint32_t currentlyCached = _getCachedKdfIters();
      if (currentlyCached != itersTriedFirst) {
        _setCachedKdfIters(itersTriedFirst);
      }
    }
  }
  secureZero(key, sizeof(key));
  return ok;
}

void VaultManager::loadFromSD(const char* pin) {
  _lastLoadError = LoadError::NONE;
  if (!_storageAllocated) {
    Serial.println("[VaultManager] loadFromSD: storage not allocated (PSRAM failed?) -- cannot load");
    _lastLoadError = LoadError::NO_STORAGE;
    return;
  }
  if (!SD.exists(DB_PATH)) {
    Serial.println("[VaultManager] loadFromSD: /vault.db not found on SD card -- keeping demo vault");
    _lastLoadError = LoadError::NO_FILE;
    return;
  }
  Serial.printf("[VaultManager] loadFromSD: /vault.db found, loading with PIN (len=%d)...\n", pin ? (int)strlen(pin) : 0);

  bool ok = _tryLoadFile(DB_PATH, pin, /*setLoadError=*/true);

  // ── FALLBACK: if vault.db failed, try vault.db.bak ──────────────────
  // Same power-loss-during-write safety net as SVL1 had.
  if (!ok && SD.exists(DB_BAK_PATH)) {
    Serial.println("[VaultManager] loadFromSD: vault.db failed, trying vault.db.bak...");
    ok = _tryLoadFile(DB_BAK_PATH, pin, /*setLoadError=*/false);
    if (ok) {
      // Promote .bak -> vault.db via copy+delete (rename is unreliable
      // on this SD stack per the original SVL1 code's notes).
      SD.remove(DB_PATH);
      File bakSrc = SD.open(DB_BAK_PATH, FILE_READ);
      File bakDst = SD.open(DB_PATH, FILE_WRITE);
      if (bakSrc && bakDst) {
        uint8_t cbuf[512];
        while (true) {
          int n = bakSrc.read(cbuf, sizeof(cbuf));
          if (n <= 0) break;
          bakDst.write(cbuf, n);
        }
      }
      if (bakDst) bakDst.close();
      if (bakSrc) bakSrc.close();
    }
  }

  if (ok) {
    Serial.printf("[VaultManager] loadFromSD: SUCCESS -- loaded %d entries from SVR1 vault\n", _count);
    // v10.5: Removed _maybeAutoCompact(pin) from the load path. Running a
    // full vault rewrite (re-encrypt + re-write every entry, ~5-10s for a
    // 50-entry vault) on EVERY unlock was the primary cause of the
    // "2-3 second delay entering the vault" complaint. Auto-compaction
    // now runs only inside saveToSD() (after ADD/UPDATE/DELETE), where
    // the user already expects a brief save delay. Unlock itself now
    // does only: PBKDF2 (~0.5s on first unlock, 0ms after — key cached)
    // + per-entry SD read + AES-GCM decrypt (~10-20ms per entry).
    // _maybeAutoCompact(pin);
  }
  (void)ok; // demo vault already in place if this failed -- nothing else to do
}

const char* VaultManager::lastLoadErrorStr() const {
  switch (_lastLoadError) {
    case LoadError::NONE:           return "";
    case LoadError::NO_STORAGE:     return "Memory error";
    case LoadError::SD_FAILED:      return "SD card error";
    case LoadError::NO_FILE:        return "No vault found";
    case LoadError::BAD_FORMAT:     return "Vault format error";
    case LoadError::DECRYPT_FAILED: return "Wrong PIN or corrupt vault";
    case LoadError::BAD_JSON:       return "Vault data error";
    default:                        return "Unknown error";
  }
}

void VaultManager::_setError(const char* msg) {
  // F15: Log to the formal error framework instead of copying into _lastError[80].
  logError(ErrSeverity::ERROR, ErrCode::VAULT_SAVE_FAILED, ErrSubsystem::ERR_VAULT, msg);
}

const char* VaultManager::lastSaveError() const {
  // F15: Read from the VAULT subsystem's last error instead of _lastError[80].
  LastError err = getLastError(ErrSubsystem::ERR_VAULT);
  if (err.code == ErrCode::NONE) return "";
  return err.message;
}

// Heuristic auto-compaction, run once after every successful load. Dead
// space accumulates from UPDATEs that grew a record (old bytes orphaned)
// and permanent DELETEs (purged rows). Thresholds below are deliberately
// simple and conservative -- tune freely, or drop this call and wire
// compactVault() to a manual "Optimize Storage" UI action instead.
void VaultManager::_maybeAutoCompact(const char* pin) {
  uint32_t liveBytes = 0;
  for (int i = 0; i < MAX_ENTRIES; i++) if (_rowStatus[i] == 1) liveBytes += _rowLen[i];
  // Only compact once the data area is non-trivial in size AND more than
  // half of it is dead weight.
  if (_dataEnd > 20000 && liveBytes < _dataEnd / 2) {
    Serial.printf("[VaultManager] Auto-compacting vault: %u live / %u total data bytes\n",
                  (unsigned)liveBytes, (unsigned)_dataEnd);
    _rewriteWholeVault(pin);
  }
}

// Full rewrite: re-encrypts every LIVE entry (fresh IV each) and writes
// them contiguously, with a freshly-sized/renumbered row table (slot i
// == in-memory index i, for i < _count). This is used for:
//   - the very first save of a brand-new vault (no file/key yet)
//   - PIN change (needs a new key derivation for everything anyway)
//   - CSV import (bulk replace)
//   - periodic/manual compaction (this rewrite IS the GC pass -- it
//     naturally drops all dead space since it only ever writes live rows)
// This is the ONLY O(n) disk operation left in the whole file; routine
// ADD/UPDATE/DELETE never call it (see _appendRecordToSD/_updateRecordOnSD/
// _purgeRowOnSD below).
bool VaultManager::_rewriteWholeVault(const char* pin) {
  if (!_storageAllocated) {
    _setError("internal error — vault storage not allocated (PSRAM init failed)");
    return false;
  }

  // ── v10.3 STALL DIAGNOSTICS (same rationale as _appendRecordToSD) ────
  unsigned long _t0 = millis();
  #define SV_RW_LOG(tag) do { \
      Serial.printf("[VaultIO] rewrite  %-12s t=%lu ms\n", tag, (unsigned long)(millis() - _t0)); \
      Serial.flush(); \
    } while (0)
  SV_RW_LOG("entry");

  extern SdManager sd;
  if (!sd.isOK()) {
    SV_RW_LOG("sd not OK -> re-begin");
    if (!sd.begin()) {
      SV_RW_LOG("sd.begin() FAILED");
      _setError("SD card not detected — check it is fully inserted");
      return false;
    }
    SV_RW_LOG("sd.begin() OK");
  }

  uint8_t salt[VAULT_SALT_LEN];
  uint8_t key[VAULT_KEY_LEN];
  if (_keyCached) {
    SV_RW_LOG("key cached");
    memcpy(key, _cachedKey, VAULT_KEY_LEN);
    memcpy(salt, _cachedSalt, VAULT_SALT_LEN);
  } else {
    SV_RW_LOG("pre deriveVaultKey (PBKDF2, ~2-5s)");
    secureRandom(salt, sizeof(salt));
    vTaskDelay(pdMS_TO_TICKS(2));
    deriveVaultKey(pin, salt, sizeof(salt), key); // ~2-5s -- only on first-ever save
    vTaskDelay(pdMS_TO_TICKS(2));
    memcpy(_cachedKey, key, VAULT_KEY_LEN);
    memcpy(_cachedSalt, salt, VAULT_SALT_LEN);
    _keyCached = true;
    SV_RW_LOG("deriveVaultKey done");
  }

  // Only need to remember each entry's ciphertext LENGTH up front (to
  // build a correct row table before any data is written) -- GCM has no
  // padding, so ciphertext length always equals plaintext length. This
  // array is never touched by the DMA crypto engine, so a plain `new` is
  // fine for it regardless of size.
  int n = _count > 0 ? _count : 1;
  uint32_t* lens = static_cast<uint32_t*>(largeAlloc(n * sizeof(uint32_t)));
  if (!lens) {
    secureZero(key, sizeof(key));
    _setError("internal error — out of memory during vault rewrite");
    return false;
  }
  SV_RW_LOG("pre measure pass");
  {
    char jsonBuf[MAX_RECORD_JSON_LEN]; // stack -- reused, no heap
    for (int i = 0; i < _count; i++) {
      lens[i] = (uint32_t)_entryToJSON(i, jsonBuf, sizeof(jsonBuf));
      if ((i & 0x3F) == 0x3F) vTaskDelay(pdMS_TO_TICKS(1));
    }
  }
  SV_RW_LOG("measure pass done");
  uint32_t newDataEnd = 0;
  for (int i = 0; i < _count; i++) newDataEnd += lens[i];

  // Single reusable internal, DMA-capable buffer for ONE entry's
  // ciphertext at a time. Deliberately NOT one buffer per entry -- with
  // up to MAX_ENTRIES (256) entries, pre-encrypting everything up front
  // (as an earlier version of this function did) could ask for 200KB+ of
  // internal DMA-capable RAM simultaneously, which this board doesn't
  // have to spare (see crypto_buffer.h for why it must be
  // internal, not PSRAM, in the first place).
  uint8_t* cryptoBuf = (uint8_t*)cryptoAlloc(MAX_RECORD_JSON_LEN);
  if (!cryptoBuf) {
    largeFree(lens);
    secureZero(key, sizeof(key));
    _setError("internal error — out of internal DMA-capable memory during vault rewrite");
    return false;
  }

  // ── Backup-then-write dance (same pattern SVL1 used) ────────────────
  SV_RW_LOG("pre backup rename");
  if (SD.exists(DB_PATH)) {
    SD.remove(DB_BAK_PATH);
    SD.rename(DB_PATH, DB_BAK_PATH);
  }
  SV_RW_LOG("pre SD.open(FILE_WRITE)");
  File f = SD.open(DB_PATH, FILE_WRITE);
  SV_RW_LOG(f ? "SD.open(FILE_WRITE) OK" : "SD.open(FILE_WRITE) FAILED");
  if (!f) {
    if (SD.exists(DB_BAK_PATH)) SD.rename(DB_BAK_PATH, DB_PATH);
    cryptoFree(cryptoBuf);
    largeFree(lens);
    secureZero(key, sizeof(key));
    _setError("SD card write failed — card may be full, write-protected, or exFAT (needs FAT32)");
    return false;
  }

  uint8_t hdr[DB_HEADER_LEN];
  memcpy(hdr, DB_MAGIC, 4);
  hdr[4] = DB_VERSION;
  memcpy(hdr + 5, salt, VAULT_SALT_LEN);
  putU32BE(hdr + 5 + VAULT_SALT_LEN, newDataEnd);
  putU16BE(hdr + 5 + VAULT_SALT_LEN + 4, (uint16_t)_count);
  f.write(hdr, DB_HEADER_LEN);
  vTaskDelay(pdMS_TO_TICKS(1));

  // Pass 1 of the row table: write status/offset/length for every row
  // now (all known from the length-only pass above); iv/tag are still
  // zero here and get patched in below, per-row, as each record is
  // actually encrypted in pass 2.
  uint32_t offset = 0;
  for (int i = 0; i < MAX_ENTRIES; i++) {
    uint8_t rowBuf[DB_ROW_LEN];
    if (i < _count) {
      rowBuf[0] = 1;
      putU32BE(rowBuf + 1, offset);
      putU32BE(rowBuf + 5, lens[i]);
      memset(rowBuf + 9, 0, VAULT_IV_LEN + VAULT_TAG_LEN); // filled in during pass 2
      offset += lens[i];
    } else {
      memset(rowBuf, 0, DB_ROW_LEN); // status = 0 = free
    }
    f.write(rowBuf, DB_ROW_LEN);
    if ((i & 0x3F) == 0x3F) vTaskDelay(pdMS_TO_TICKS(1));
  }

  // Pass 2: encrypt + write ONE entry at a time (reusing cryptoBuf), then
  // patch just that row's iv/tag fields at their fixed offset -- same
  // small-fixed-offset-write technique the incremental functions use.
  bool writeOk = true;
  {
    char jsonBuf[MAX_RECORD_JSON_LEN]; // stack -- reused, no heap
    offset = 0;
    for (int i = 0; i < _count && writeOk; i++) {
      size_t len = _entryToJSON(i, jsonBuf, sizeof(jsonBuf));
      uint8_t iv[VAULT_IV_LEN], tag[VAULT_TAG_LEN];
      secureRandom(iv, sizeof(iv));
      writeOk = aesGcmEncrypt(key, iv, sizeof(iv),
                               reinterpret_cast<const uint8_t*>(jsonBuf), len,
                               cryptoBuf, tag);
      if (writeOk) writeOk = f.seek(DB_DATA_OFFSET + offset);
      if (writeOk) writeOk = (f.write(cryptoBuf, len) == len);
      if (writeOk) {
        uint8_t rowBuf[VAULT_IV_LEN + VAULT_TAG_LEN];
        memcpy(rowBuf, iv, VAULT_IV_LEN);
        memcpy(rowBuf + VAULT_IV_LEN, tag, VAULT_TAG_LEN);
        writeOk = f.seek(_rowFileOffset(i) + 9); // iv/tag start right after status+offset+len
        if (writeOk) writeOk = (f.write(rowBuf, sizeof(rowBuf)) == sizeof(rowBuf));
      }
      if (writeOk) {
        memcpy(_rowIv[i], iv, VAULT_IV_LEN);
        memcpy(_rowTag[i], tag, VAULT_TAG_LEN);
      }
      offset += len;
      if ((i & 0xF) == 0xF) vTaskDelay(pdMS_TO_TICKS(2));
    }
  }
  cryptoFree(cryptoBuf);

  if (!writeOk) {
    f.close();
    SD.remove(DB_PATH);
    if (SD.exists(DB_BAK_PATH)) SD.rename(DB_BAK_PATH, DB_PATH);
    largeFree(lens);
    secureZero(key, sizeof(key));
    _setError("SD card write failed partway through vault rewrite — restored from backup");
    return false;
  }
  f.flush();
  f.close();
  SV_RW_LOG("flush+close done");
  // v10.1 FIX: 2ms -> 10ms. This save runs inline on the same task that
  // owns the USB CDC port; a longer yield here gives the driver more room
  // to drain/service anything the host sent while the write was in flight.
  vTaskDelay(pdMS_TO_TICKS(10));

  SV_RW_LOG("pre verify open");
  File vf = SD.open(DB_PATH, FILE_READ);
  SV_RW_LOG(vf ? "verify open OK" : "verify open FAILED");
  bool verified = false;
  if (vf) {
    uint8_t vhdr[5];
    verified = (vf.read(vhdr, 5) == 5 && memcmp(vhdr, DB_MAGIC, 4) == 0 && vhdr[4] == DB_VERSION);
    vf.close();
  }
  SV_RW_LOG(verified ? "verify OK" : "verify FAILED");
  if (!verified) {
    SD.remove(DB_PATH);
    if (SD.exists(DB_BAK_PATH)) SD.rename(DB_BAK_PATH, DB_PATH);
    largeFree(lens);
    secureZero(key, sizeof(key));
    _setError("SD card write verification failed — restored from backup");
    return false;
  }

  // ── Update RAM mirror to match what's now on disk ───────────────────
  // (_rowIv/_rowTag were already updated per-row during pass 2 above.)
  _dataEnd = newDataEnd;
  uint32_t off2 = 0;
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (i < _count) {
      _rowStatus[i] = 1;
      _rowOffset[i] = off2;
      _rowLen[i] = lens[i];
      _diskSlot[i] = i;
      off2 += lens[i];
    } else {
      _rowStatus[i] = 0;
      _rowOffset[i] = 0;
      _rowLen[i] = 0;
    }
  }

  largeFree(lens);
  secureZero(key, sizeof(key));
  // F15: Clear last error on success — replaced _lastError[0]='\0' with clearLastError().
  clearLastError(ErrSubsystem::ERR_VAULT);
  return true;
}

// Kept as the public entry point (importCSV / setPin / factory bootstrap
// all already call saveToSD() -- no call sites need to change). It's now
// just the full-rewrite/compaction path under the hood.
bool VaultManager::saveToSD(const char* pin) {
  return _rewriteWholeVault(pin);
}

// ── Incremental single-record operations ────────────────────────────────
// These are the actual fix for the ADD-fails-under-heap-fragmentation bug:
// each does a handful of small, fixed-offset SD writes for the ONE entry
// involved, never touching the other 255.

bool VaultManager::_appendRecordToSD(int memIdx, const char* pin) {
  if (!_storageAllocated) {
    _setError("internal error — vault storage not allocated (PSRAM init failed)");
    return false;
  }

  // ── v10.3 STALL DIAGNOSTICS ─────────────────────────────────────────
  // The device was silently hanging for ~38s on the FIRST add after boot,
  // then the USB CDC port would drop. HeapMon still printed during the
  // stall (loop() was alive) but NO [SerialProto] RX/dispatch lines did —
  // meaning processPayload() was blocked, almost certainly inside one of
  // the SD calls below. The previous instrumentation only timed seek+write,
  // never the SD.open() itself. These Serial.printf + Serial.flush() pairs
  // force each step's log line out BEFORE the next SD call runs, so we can
  // see exactly which one never returns. (Serial.flush() is essential —
  // USB CDC buffers TX, and if the device dies mid-write the buffer dies
  // with it, taking the last log line with it.)
  unsigned long _t0 = millis();
  #define SV_IO_LOG(tag) do { \
      Serial.printf("[VaultIO] append %-12s t=%lu ms\n", tag, (unsigned long)(millis() - _t0)); \
      Serial.flush(); \
    } while (0)

  SV_IO_LOG("entry");

  // Bootstrap cases (no cached key yet, or vault.db doesn't exist yet)
  // still need a full write -- there's nothing to append to.
  if (!_keyCached) {
    SV_IO_LOG("key uncached -> full rewrite");
    return _rewriteWholeVault(pin);
  }
  SV_IO_LOG("pre SD.exists()");
  bool exists = SD.exists(DB_PATH);
  SV_IO_LOG(exists ? "SD.exists()=true" : "SD.exists()=false");
  if (!exists) {
    SV_IO_LOG("no file -> full rewrite");
    return _rewriteWholeVault(pin);
  }

  extern SdManager sd;
  if (!sd.isOK()) {
    SV_IO_LOG("sd not OK -> re-begin");
    if (!sd.begin()) {
      SV_IO_LOG("sd.begin() FAILED");
      _setError("SD card not detected — check it is fully inserted");
      return false;
    }
    SV_IO_LOG("sd.begin() OK");
  }

  int slot = _findFreeRow();
  if (slot < 0) {
    _setError("internal error — vault row table full");
    return false;
  }

  char jsonBuf[MAX_RECORD_JSON_LEN]; // stack -- always internal RAM, never PSRAM
  size_t len = _entryToJSON(memIdx, jsonBuf, sizeof(jsonBuf));
  uint8_t* cipher = (uint8_t*)cryptoAlloc(len > 0 ? len : 1); // feeds aesGcmEncrypt's DMA engine
  if (!cipher) {
    _setError("internal error — out of internal DMA-capable memory encrypting entry");
    return false;
  }
  uint8_t iv[VAULT_IV_LEN], tag[VAULT_TAG_LEN];
  secureRandom(iv, sizeof(iv));
  bool encOk = aesGcmEncrypt(_cachedKey, iv, sizeof(iv),
                              reinterpret_cast<const uint8_t*>(jsonBuf), len,
                              cipher, tag);
  if (!encOk) {
    cryptoFree(cipher);
    _setError("internal error — vault encryption failed");
    return false;
  }

  // v10.2 FIX (the real bug): FILE_WRITE on the Arduino-ESP32 core maps
  // to POSIX "w+", which TRUNCATES the file to 0 bytes on open. This
  // function only patches a handful of bytes afterward (the new record +
  // one row-table entry + the dataEnd field) — it relies on every OTHER
  // byte in the file (header, salt, the other N-1 entries) surviving the
  // open() untouched. With FILE_WRITE, they didn't: every ADD (and every
  // UPDATE/DELETE, which have the identical bug) was zeroing the entire
  // vault out from under itself before re-patching a tiny piece of it
  // back. "r+" opens for read/write on an EXISTING file WITHOUT
  // truncating — exactly what an in-place patch needs. (Safe here
  // specifically because the caller already guarantees SD.exists(DB_PATH)
  // via the bootstrap check a few lines up — "r+" fails if the file
  // doesn't exist, which _rewriteWholeVault's FILE_WRITE correctly still
  // handles for that case.)
  SV_IO_LOG("pre SD.open(r+)");
  File f = SD.open(DB_PATH, "r+");
  SV_IO_LOG(f ? "SD.open(r+) OK" : "SD.open(r+) FAILED");
  if (!f) {
    cryptoFree(cipher);
    _setError("SD card write failed — card may be full or write-protected");
    return false;
  }

  uint32_t offset = _dataEnd;
  SV_IO_LOG("pre seek+write");
  unsigned long _dbgWriteStart = millis();
  bool ok = f.seek(DB_DATA_OFFSET + offset);
  if (ok) ok = (f.write(cipher, len) == len);
  unsigned long _dbgWriteMs = millis() - _dbgWriteStart;
  SV_IO_LOG("seek+write done");
  if (_dbgWriteMs > 500) {
    Serial.printf("[VaultManager] SLOW SD WRITE (append): %lu ms to seek+write %u bytes at "
                  "offset %u (file-relative) — this is inside the raw SD call itself, not "
                  "app logic\n", _dbgWriteMs, (unsigned)len, (unsigned)(DB_DATA_OFFSET + offset));
    Serial.flush();
  }
  cryptoFree(cipher);

  if (ok) {
    _rowStatus[slot] = 1;
    _rowOffset[slot] = offset;
    _rowLen[slot] = (uint32_t)len;
    memcpy(_rowIv[slot], iv, sizeof(iv));
    memcpy(_rowTag[slot], tag, sizeof(tag));
    SV_IO_LOG("pre writeRowToFile");
    ok = _writeRowToFile(f, slot);
    SV_IO_LOG("writeRowToFile done");
  }
  if (ok) {
    _dataEnd = offset + (uint32_t)len;
    SV_IO_LOG("pre writeDataEndToFile");
    ok = _writeDataEndToFile(f);
    SV_IO_LOG("writeDataEndToFile done");
  }
  SV_IO_LOG("pre flush+close");
  f.flush();
  f.close();
  SV_IO_LOG("flush+close done");
  // v10.1 FIX: 2ms -> 10ms (see _rewriteWholeVault for rationale). This is
  // the ADD path specifically, so this is the fix that matters most for
  // the "adding an entry disconnects the ESP32" symptom.
  vTaskDelay(pdMS_TO_TICKS(10));

  if (!ok) {
    _rowStatus[slot] = 0; // don't believe this slot is occupied if the disk write didn't land
    _setError("SD card write failed while appending the new entry");
    SV_IO_LOG("FAILED");
    return false;
  }
  _diskSlot[memIdx] = slot;
  // F15: Clear last error on success
  clearLastError(ErrSubsystem::ERR_VAULT);
  SV_IO_LOG("OK");
  return true;
}

bool VaultManager::_updateRecordOnSD(int memIdx, const char* pin) {
  if (!_storageAllocated) {
    _setError("internal error — vault storage not allocated (PSRAM init failed)");
    return false;
  }
  if (!_keyCached || !SD.exists(DB_PATH)) return _rewriteWholeVault(pin);

  int slot = (memIdx >= 0 && memIdx < MAX_ENTRIES) ? _diskSlot[memIdx] : -1;
  if (slot < 0 || slot >= MAX_ENTRIES || _rowStatus[slot] != 1) {
    // Shouldn't happen, but fail safe with a full rewrite rather than
    // risk corrupting the row table on a bad index.
    return _rewriteWholeVault(pin);
  }

  extern SdManager sd;
  if (!sd.isOK() && !sd.begin()) {
    _setError("SD card not detected — check it is fully inserted");
    return false;
  }

  char jsonBuf[MAX_RECORD_JSON_LEN]; // stack -- always internal RAM, never PSRAM
  size_t len = _entryToJSON(memIdx, jsonBuf, sizeof(jsonBuf));
  uint8_t* cipher = (uint8_t*)cryptoAlloc(len > 0 ? len : 1); // feeds aesGcmEncrypt's DMA engine
  if (!cipher) {
    _setError("internal error — out of internal DMA-capable memory encrypting entry");
    return false;
  }
  uint8_t iv[VAULT_IV_LEN], tag[VAULT_TAG_LEN];
  secureRandom(iv, sizeof(iv));
  bool encOk = aesGcmEncrypt(_cachedKey, iv, sizeof(iv),
                              reinterpret_cast<const uint8_t*>(jsonBuf), len,
                              cipher, tag);
  if (!encOk) {
    cryptoFree(cipher);
    _setError("internal error — vault encryption failed");
    return false;
  }

  // v10.2 FIX: see the matching comment in _appendRecordToSD — FILE_WRITE
  // ("w+") truncates the whole vault before this function's in-place
  // patch runs. "r+" is required here for the same reason. This is the
  // one that made "move to trash" (an UPDATE) look like it "worked" only
  // by luck of timing/caching in earlier testing — it has the identical
  // truncation bug as ADD.
  File f = SD.open(DB_PATH, "r+");
  if (!f) {
    cryptoFree(cipher);
    _setError("SD card write failed — card may be full or write-protected");
    return false;
  }

  // Fits in the space this row already had? Overwrite in place (no
  // header change needed). Otherwise append at the end -- the old bytes
  // become dead space, reclaimed on the next compaction.
  bool fitsInPlace = (len <= _rowLen[slot]);
  uint32_t offset = fitsInPlace ? _rowOffset[slot] : _dataEnd;

  unsigned long _dbgWriteStart2 = millis();
  bool ok = f.seek(DB_DATA_OFFSET + offset);
  if (ok) ok = (f.write(cipher, len) == len);
  unsigned long _dbgWriteMs2 = millis() - _dbgWriteStart2;
  if (_dbgWriteMs2 > 500) {
    Serial.printf("[VaultManager] SLOW SD WRITE (update): %lu ms to seek+write %u bytes at "
                  "offset %u (file-relative, fitsInPlace=%d)\n", _dbgWriteMs2, (unsigned)len,
                  (unsigned)(DB_DATA_OFFSET + offset), (int)fitsInPlace);
  }
  cryptoFree(cipher);

  if (ok) {
    _rowOffset[slot] = offset;
    _rowLen[slot] = (uint32_t)len;
    memcpy(_rowIv[slot], iv, sizeof(iv));
    memcpy(_rowTag[slot], tag, sizeof(tag));
    ok = _writeRowToFile(f, slot);
  }
  if (ok && !fitsInPlace) {
    _dataEnd = offset + (uint32_t)len;
    ok = _writeDataEndToFile(f);
  }
  f.flush();
  f.close();
  // v10.1 FIX: 2ms -> 10ms, same rationale as _appendRecordToSD.
  vTaskDelay(pdMS_TO_TICKS(10));

  if (!ok) {
    _setError("SD card write failed while updating the entry");
    return false;
  }
  // F15: Clear last error on success — replaced _lastError[0]='\0' with clearLastError().
  clearLastError(ErrSubsystem::ERR_VAULT);
  return true;
}

bool VaultManager::_purgeRowOnSD(int slot) {
  if (slot < 0 || slot >= MAX_ENTRIES) return true;       // nothing to do
  if (!_keyCached || !SD.exists(DB_PATH)) return true;    // nothing persisted for this slot yet

  extern SdManager sd;
  if (!sd.isOK() && !sd.begin()) {
    _setError("SD card not detected — check it is fully inserted");
    return false;
  }

  // v10.2 FIX: same truncation bug as ADD/UPDATE — see _appendRecordToSD.
  File f = SD.open(DB_PATH, "r+");
  if (!f) {
    _setError("SD card write failed — card may be full or write-protected");
    return false;
  }
  uint8_t prevStatus = _rowStatus[slot];
  _rowStatus[slot] = 0;
  bool ok = _writeRowToFile(f, slot);
  f.flush();
  f.close();
  // v10.1 FIX: 2ms -> 10ms, same rationale as the other write paths.
  vTaskDelay(pdMS_TO_TICKS(10));

  if (!ok) {
    _rowStatus[slot] = prevStatus;
    _setError("SD card write failed while removing the entry");
    return false;
  }
  // F15: Clear last error on success — replaced _lastError[0]='\0' with clearLastError().
  clearLastError(ErrSubsystem::ERR_VAULT);
  return true;
}

// Helper: copies EVERY field from a VaultEntryRW into the manager's
// parallel arrays at a given index. Used by addEntry and updateEntry.
// (Kept as a macro so we can index the right arrays directly without a
// getter/setter layer.) Unchanged from SVL1 -- this only touches the
// in-memory representation, which didn't change in this redesign.
#define SV_COPY_ALL_FIELDS(DST_PREFIX, SRC, I) do {                       \
  strncpy(_site[I],        (SRC).site,        sizeof(_site[0]) - 1);      \
  _site[I][sizeof(_site[0]) - 1] = 0;                                    \
  strncpy(_user[I],        (SRC).user,        sizeof(_user[0]) - 1);      \
  _user[I][sizeof(_user[0]) - 1] = 0;                                    \
  strncpy(_pass[I],        (SRC).pass,        sizeof(_pass[0]) - 1);      \
  _pass[I][sizeof(_pass[0]) - 1] = 0;                                    \
  strncpy(_totp[I],        (SRC).totp,        sizeof(_totp[0]) - 1);      \
  _totp[I][sizeof(_totp[0]) - 1] = 0;                                    \
  /* LOGIN extras */                                                     \
  strncpy(_url[I],         (SRC).url,         sizeof(_url[0]) - 1);      \
  _url[I][sizeof(_url[0]) - 1] = 0;                                     \
  strncpy(_notes[I],       (SRC).notes,       sizeof(_notes[0]) - 1);     \
  _notes[I][sizeof(_notes[0]) - 1] = 0;                                 \
  strncpy(_folder[I],      (SRC).folder,      sizeof(_folder[0]) - 1);    \
  _folder[I][sizeof(_folder[0]) - 1] = 0;                              \
  /* CARD extras */                                                      \
  strncpy(_cardholder[I],  (SRC).cardholder,  sizeof(_cardholder[0]) - 1);\
  _cardholder[I][sizeof(_cardholder[0]) - 1] = 0;                      \
  strncpy(_cardNumber[I],  (SRC).cardNumber,  sizeof(_cardNumber[0]) - 1);\
  _cardNumber[I][sizeof(_cardNumber[0]) - 1] = 0;                      \
  strncpy(_exp[I],         (SRC).exp,         sizeof(_exp[0]) - 1);      \
  _exp[I][sizeof(_exp[0]) - 1] = 0;                                     \
  strncpy(_cvv[I],         (SRC).cvv,         sizeof(_cvv[0]) - 1);      \
  _cvv[I][sizeof(_cvv[0]) - 1] = 0;                                     \
  /* IDENTITY extras */                                                  \
  strncpy(_firstName[I],   (SRC).firstName,   sizeof(_firstName[0]) - 1);\
  _firstName[I][sizeof(_firstName[0]) - 1] = 0;                         \
  strncpy(_lastName[I],    (SRC).lastName,    sizeof(_lastName[0]) - 1);\
  _lastName[I][sizeof(_lastName[0]) - 1] = 0;                          \
  strncpy(_email[I],       (SRC).email,       sizeof(_email[0]) - 1);    \
  _email[I][sizeof(_email[0]) - 1] = 0;                                 \
  strncpy(_phone[I],       (SRC).phone,       sizeof(_phone[0]) - 1);    \
  _phone[I][sizeof(_phone[0]) - 1] = 0;                                 \
  strncpy(_address[I],     (SRC).address,     sizeof(_address[0]) - 1);  \
  _address[I][sizeof(_address[0]) - 1] = 0;                             \
  strncpy(_city[I],        (SRC).city,        sizeof(_city[0]) - 1);     \
  _city[I][sizeof(_city[0]) - 1] = 0;                                   \
  strncpy(_state[I],       (SRC).state,       sizeof(_state[0]) - 1);    \
  _state[I][sizeof(_state[0]) - 1] = 0;                                 \
  strncpy(_postal[I],      (SRC).postal,      sizeof(_postal[0]) - 1);   \
  _postal[I][sizeof(_postal[0]) - 1] = 0;                              \
  strncpy(_country[I],     (SRC).country,     sizeof(_country[0]) - 1);  \
  _country[I][sizeof(_country[0]) - 1] = 0;                            \
  strncpy(_ssn[I],         (SRC).ssn,         sizeof(_ssn[0]) - 1);      \
  _ssn[I][sizeof(_ssn[0]) - 1] = 0;                                     \
  strncpy(_passport[I],    (SRC).passport,    sizeof(_passport[0]) - 1); \
  _passport[I][sizeof(_passport[0]) - 1] = 0;                          \
  strncpy(_license[I],     (SRC).license,     sizeof(_license[0]) - 1);  \
  _license[I][sizeof(_license[0]) - 1] = 0;                            \
} while (0)

bool VaultManager::addEntry(const VaultEntryRW& e, const char* pin) {
  // v5.4.7: H4 fix — lock the vault for the duration of this operation.
  lock();
  if (!_storageAllocated) { unlock(); return false; }
  if (_count >= MAX_ENTRIES) { unlock(); return false; }
  // Zero the destination slot first so any field not present in `e`
  // (because it doesn't apply to this entry's type) starts as an
  // empty string rather than stale heap data.
  _zeroEntrySlot(_count);
  SV_COPY_ALL_FIELDS(_, e, _count);
  _type[_count]     = e.type;
  _favorite[_count] = e.favorite;
  _deleted[_count]  = e.deleted;
  _diskSlot[_count] = -1;
  _count++;
  _viewsBuilt = false;
  // The whole point of this redesign: append ONE small encrypted record
  // + patch ONE row, instead of re-serializing/re-encrypting all _count
  // entries. Falls back to a full rewrite only for bootstrap (no vault
  // file / no cached key yet).
  bool ok = _appendRecordToSD(_count - 1, pin);
  unlock();
  return ok;
}

bool VaultManager::updateEntry(int idx, const VaultEntryRW& e, const char* pin) {
  lock();
  if (!_storageAllocated) { unlock(); return false; }
  if (idx < 0 || idx >= _count) { unlock(); return false; }
  _zeroEntrySlot(idx);
  SV_COPY_ALL_FIELDS(_, e, idx);
  _type[idx]     = e.type;
  _favorite[idx] = e.favorite;
  _deleted[idx]  = e.deleted;
  _viewsBuilt = false;
  bool ok = _updateRecordOnSD(idx, pin);
  unlock();
  return ok;
}

bool VaultManager::deleteEntry(int idx, const char* pin) {
  lock();
  if (!_storageAllocated) { unlock(); return false; }
  if (idx < 0 || idx >= _count) { unlock(); return false; }
  int purgedSlot = _diskSlot[idx];

  // In-memory shift is unchanged from SVL1 -- cheap (small fixed arrays,
  // no disk I/O). What changed is what happens ON DISK: instead of
  // rewriting the whole vault, we patch exactly one row (below).
  int nTail = _count - idx - 1;
  if (nTail > 0) {
    memmove(_site[idx],        _site[idx + 1],        nTail * sizeof(_site[0]));
    memmove(_user[idx],        _user[idx + 1],        nTail * sizeof(_user[0]));
    memmove(_pass[idx],        _pass[idx + 1],        nTail * sizeof(_pass[0]));
    memmove(_totp[idx],        _totp[idx + 1],        nTail * sizeof(_totp[0]));
    memmove(_url[idx],         _url[idx + 1],         nTail * sizeof(_url[0]));
    memmove(_notes[idx],       _notes[idx + 1],       nTail * sizeof(_notes[0]));
    memmove(_folder[idx],      _folder[idx + 1],      nTail * sizeof(_folder[0]));
    memmove(_cardholder[idx],  _cardholder[idx + 1],  nTail * sizeof(_cardholder[0]));
    memmove(_cardNumber[idx],  _cardNumber[idx + 1],  nTail * sizeof(_cardNumber[0]));
    memmove(_exp[idx],         _exp[idx + 1],         nTail * sizeof(_exp[0]));
    memmove(_cvv[idx],         _cvv[idx + 1],         nTail * sizeof(_cvv[0]));
    memmove(_firstName[idx],   _firstName[idx + 1],   nTail * sizeof(_firstName[0]));
    memmove(_lastName[idx],    _lastName[idx + 1],    nTail * sizeof(_lastName[0]));
    memmove(_email[idx],       _email[idx + 1],       nTail * sizeof(_email[0]));
    memmove(_phone[idx],       _phone[idx + 1],       nTail * sizeof(_phone[0]));
    memmove(_address[idx],     _address[idx + 1],     nTail * sizeof(_address[0]));
    memmove(_city[idx],        _city[idx + 1],        nTail * sizeof(_city[0]));
    memmove(_state[idx],       _state[idx + 1],       nTail * sizeof(_state[0]));
    memmove(_postal[idx],      _postal[idx + 1],      nTail * sizeof(_postal[0]));
    memmove(_country[idx],     _country[idx + 1],     nTail * sizeof(_country[0]));
    memmove(_ssn[idx],         _ssn[idx + 1],         nTail * sizeof(_ssn[0]));
    memmove(_passport[idx],    _passport[idx + 1],    nTail * sizeof(_passport[0]));
    memmove(_license[idx],     _license[idx + 1],     nTail * sizeof(_license[0]));
    memmove(_diskSlot + idx,   _diskSlot + idx + 1,   nTail * sizeof(int));
    for (int i = idx; i < _count - 1; i++) {
      _type[i]     = _type[i + 1];
      _favorite[i] = _favorite[i + 1];
      _deleted[i]  = _deleted[i + 1];
    }
  }
  _zeroEntrySlot(_count - 1);
  _type[_count - 1]     = 0;
  _favorite[_count - 1] = false;
  _deleted[_count - 1]  = false;
  _diskSlot[_count - 1] = -1;
  _count--;
  _viewsBuilt = false;
  // O(1) on disk: mark the ONE purged row free. None of the other rows
  // (including the ones that just shifted in-memory) need to be touched
  // -- their physical disk slots didn't move.
  bool ok = _purgeRowOnSD(purgedSlot);
  unlock();
  return ok;
}
String VaultManager::getPin() const {
  _prefs.begin(PREFS_NAMESPACE, true);  // read-only
  // F12: On first boot, the PIN key doesn't exist yet — we return
  // FIRST_BOOT_PIN_SENTINEL instead of the old hard-coded "1234" default.
  // The sentinel value marks "no PIN has been set yet" so that:
  //   - verifyPin() always returns false (can't unlock with an unset PIN)
  //   - isFirstBoot() detects the first-boot condition
  //   - The UI shows the mandatory first-boot PIN setup screen
  // This eliminates the security vulnerability of a hard-coded default PIN.
  String pin;
  if (_prefs.isKey(PREFS_KEY_PIN)) {
    pin = _prefs.getString(PREFS_KEY_PIN, FIRST_BOOT_PIN_SENTINEL);
  } else {
    pin = FIRST_BOOT_PIN_SENTINEL;
  }
  _prefs.end();
  return pin;
}

bool VaultManager::verifyPin(const char* pin) const {
  String stored = getPin();
  // F12: If the stored PIN is the first-boot sentinel ("UNSET"), the
  // device has never had a PIN configured. In this state, verification
  // MUST fail — the user cannot unlock with a non-existent PIN. The
  // mandatory first-boot PIN setup screen must be completed first.
  if (stored == FIRST_BOOT_PIN_SENTINEL) return false;
  // True constant-time compare — no early exit on length mismatch.
  // Pad both to MAX_PIN_LEN and XOR-compare all bytes.
  char a[MAX_PIN_LEN + 1] = {0};
  char b[MAX_PIN_LEN + 1] = {0};
  strncpy(a, stored.c_str(), MAX_PIN_LEN);
  strncpy(b, pin ? pin : "", MAX_PIN_LEN);
  volatile uint8_t diff = 0;
  volatile uint8_t lenMatch = (stored.length() == (pin ? strlen(pin) : 0));
  for (int i = 0; i < MAX_PIN_LEN; i++) diff |= (uint8_t)(a[i] ^ b[i]);
  return (diff == 0) && (lenMatch != 0);
}

// ── First-boot PIN setup (F12) ──────────────────────────────────────────
// isFirstBoot(): Returns true if the device has never had a PIN set.
// This is determined by checking:
//   1. The NVS first-boot flag key (PREFS_KEY_FIRST_BOOT) — if absent or
//      false, the device hasn't completed first-boot setup.
//   2. As a fallback, whether the stored PIN equals FIRST_BOOT_PIN_SENTINEL.
// Both checks are needed because a factory reset clears NVS entirely,
// removing both the flag AND the PIN, so the sentinel check catches the
// case where the flag key doesn't exist yet.
bool VaultManager::isFirstBoot() const {
  _prefs.begin(PREFS_NAMESPACE, true);  // read-only
  bool firstBoot = true;  // default: assume first boot until proven otherwise
  if (_prefs.isKey(PREFS_KEY_FIRST_BOOT)) {
    // Key exists — read the bool value. true = PIN has been set, false = first boot.
    firstBoot = !_prefs.getBool(PREFS_KEY_FIRST_BOOT, false);
  }
  // If the flag says "not first boot" but the PIN is still the sentinel,
  // that's an inconsistent state (flag was set but PIN wasn't actually
  // written). Treat as first boot — the user must set a PIN.
  if (!firstBoot) {
    String pin = _prefs.getString(PREFS_KEY_PIN, FIRST_BOOT_PIN_SENTINEL);
    if (pin == FIRST_BOOT_PIN_SENTINEL) {
      firstBoot = true;
    }
  }
  _prefs.end();
  return firstBoot;
}

// completeFirstBoot(newPin): Sets the user-chosen PIN in NVS and marks
// the first-boot flag as complete. Called by the UI after the user
// successfully enters and confirms their new PIN on the first-boot
// setup screen.
//
// This writes the PIN directly (no old-PIN verification needed because
// there IS no old PIN on first boot — the sentinel "UNSET" is not a real
// PIN). The first-boot flag is set to true so subsequent boots skip
// the setup screen.
void VaultManager::completeFirstBoot(const char* newPin) {
  if (!newPin || strlen(newPin) < 4) return;  // minimum 4 digits
  _prefs.begin(PREFS_NAMESPACE, false);  // read-write
  _prefs.putString(PREFS_KEY_PIN, newPin);
  _prefs.putBool(PREFS_KEY_FIRST_BOOT, true);  // mark first boot as complete
  _prefs.end();
}

bool VaultManager::setPin(const char* oldPin, const char* newPin) {
  // F12: Allow setPin with FIRST_BOOT_PIN_SENTINEL as the old PIN during
  // first-boot setup. Normally verifyPin() rejects the sentinel, but the
  // first-boot PIN setup screen calls setPin(sentinel, newPin) after
  // completeFirstBoot() has already written the new PIN to NVS. This call
  // is needed to trigger saveToSD() and key derivation for the new PIN.
  // Since completeFirstBoot() just wrote the new PIN, the NVS PIN is
  // already the new one — but we still need the saveToSD side effect.
  // So: if oldPin equals the sentinel, skip verification (the new PIN
  // was just stored by completeFirstBoot, so it's already in NVS).
  String storedPin = getPin();
  if (strcmp(oldPin, FIRST_BOOT_PIN_SENTINEL) == 0) {
    // First-boot path: PIN was just written by completeFirstBoot().
    // Skip verification — the sentinel can't be verified (it's not a real PIN).
  } else {
    // Normal path: verify the old PIN before changing it.
    if (!verifyPin(oldPin)) return false;
  }
  if (!newPin || strlen(newPin) < 4) return false;
  // Clear cached key — new PIN means new key derivation needed
  clearCachedKey();
  // v10.7: Clear the NVS-cached iter count too. PIN change calls saveToSD
  // which calls _rewriteWholeVault, which always derives a fresh key with
  // VAULT_KDF_ITERATIONS (2000, the new count) and a fresh salt. So the
  // next unlock needs to try 2000 first, NOT the previously-cached count
  // (which might be 20000 from a legacy vault). Without this clear, the
  // first unlock after a PIN change would waste ~0.3-3s deriving with the
  // stale cached iters, failing, then retrying with 2000.
  _setCachedKdfIters(0);
  _prefs.begin(PREFS_NAMESPACE, false);  // read-write
  _prefs.putString(PREFS_KEY_PIN, newPin);
  _prefs.end();
  // Re-encrypt the vault on SD with the new PIN (if SD is present)
  // This will derive a new key with a new salt and cache it
  saveToSD(newPin);
  return true;
}

uint32_t VaultManager::getAutoLockMs() const {
  _prefs.begin(PREFS_NAMESPACE, true);
  uint32_t ms = _prefs.getUInt(PREFS_KEY_AUTOLOCK, AUTO_LOCK_MS);
  _prefs.end();
  return ms;
}

void VaultManager::setAutoLockMs(uint32_t ms) {
  _prefs.begin(PREFS_NAMESPACE, false);
  _prefs.putUInt(PREFS_KEY_AUTOLOCK, ms);
  _prefs.end();
}

void VaultManager::factoryReset() {
  // Wipe NVS settings — this also clears PREFS_KEY_FIRST_BOOT, which
  // means after factory reset the device will be back in first-boot
  // state and the user must set a PIN again (F12).
  _prefs.begin(PREFS_NAMESPACE, false);
  _prefs.clear();
  _prefs.end();
  // Wipe SD vault files
  SD.remove(DB_PATH);
  SD.remove(DB_BAK_PATH);
  SD.remove(DB_TMP_PATH);
  // Wipe cached vault key
  clearCachedKey();
  // Free + re-alloc PSRAM storage so all per-entry fields are guaranteed
  // zeroed. After factory reset the vault is empty — no demo data.
  _freeStorage();
  _allocStorage();
  // Vault stays empty after factory reset — user will set up fresh.
}

// ── Vault key cache management ─────────────────────────────────────────
void VaultManager::clearCachedKey() {
  if (_keyCached) {
    secureZero(_cachedKey, sizeof(_cachedKey));
    secureZero(_cachedSalt, sizeof(_cachedSalt));
    _keyCached = false;
    Serial.println("[VaultManager] Cached vault key ZEROED");
  }
}

uint8_t VaultManager::getThemeId() const {
  _prefs.begin(PREFS_NAMESPACE, true);
  uint8_t id = _prefs.getUChar(PREFS_KEY_THEME, 0);  // 0 = Air-Gapped (default)
  _prefs.end();
  return id;
}

void VaultManager::setThemeId(uint8_t id) {
  _prefs.begin(PREFS_NAMESPACE, false);
  _prefs.putUChar(PREFS_KEY_THEME, id);
  _prefs.end();
}

// ── v10.7: NVS-cached KDF iteration count ──────────────────────────────
// After the first successful vault unlock, the iter count that worked is
// persisted here. On subsequent unlocks we try the cached count FIRST,
// which lets us skip the "derive 2000, fail to decrypt, derive 20000"
// retry path entirely. That retry path added 2-3s to every unlock of a
// v10.5-era vault (created with 20000 iters) — a one-time cost on
// firmware upgrade that this cache eliminates on every unlock after.
//
// Returns 0 if no iter count has been cached yet (first boot, or after
// factory reset). Callers must handle 0 as "not cached".
uint32_t VaultManager::_getCachedKdfIters() const {
  _prefs.begin(PREFS_NAMESPACE, true);
  uint32_t iters = _prefs.getUInt(PREFS_KEY_KDF_ITERS, 0);
  _prefs.end();
  return iters;
}

void VaultManager::_setCachedKdfIters(uint32_t iters) {
  _prefs.begin(PREFS_NAMESPACE, false);
  _prefs.putUInt(PREFS_KEY_KDF_ITERS, iters);
  _prefs.end();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PIN lockout (NVS-backed, survives reboot)
// ═══════════════════════════════════════════════════════════════════════════════

uint8_t VaultManager::getPinFailCount() const {
  _prefs.begin(PREFS_NAMESPACE, true);
  uint8_t count = _prefs.getUChar(PREFS_KEY_PIN_FAILS, 0);
  _prefs.end();
  return count;
}

void VaultManager::incrementPinFailCount() {
  _prefs.begin(PREFS_NAMESPACE, false);
  uint8_t count = _prefs.getUChar(PREFS_KEY_PIN_FAILS, 0) + 1;
  _prefs.putUChar(PREFS_KEY_PIN_FAILS, count);

  // Escalating backoff: 3 fails → 30s, 4 → 60s, 5 → 2m, 6+ → 5m
  uint32_t lockMs = 0;
  if (count >= 6) lockMs = 300000;       // 5 minutes
  else if (count >= 5) lockMs = 120000;  // 2 minutes
  else if (count >= 4) lockMs = 60000;   // 60 seconds
  else if (count >= 3) lockMs = 30000;   // 30 seconds

  if (lockMs > 0) {
    _prefs.putUInt(PREFS_KEY_PIN_LOCK_UNTIL, millis() + lockMs);
  }
  _prefs.end();
}

void VaultManager::resetPinFailCount() {
  _prefs.begin(PREFS_NAMESPACE, false);
  _prefs.putUChar(PREFS_KEY_PIN_FAILS, 0);
  _prefs.putUInt(PREFS_KEY_PIN_LOCK_UNTIL, 0);
  _prefs.end();
}

uint32_t VaultManager::getPinLockUntil() const {
  _prefs.begin(PREFS_NAMESPACE, true);
  uint32_t until = _prefs.getUInt(PREFS_KEY_PIN_LOCK_UNTIL, 0);
  _prefs.end();
  return until;
}

void VaultManager::setPinLockUntil(uint32_t ms) {
  _prefs.begin(PREFS_NAMESPACE, false);
  _prefs.putUInt(PREFS_KEY_PIN_LOCK_UNTIL, ms);
  _prefs.end();
}

bool VaultManager::isPinLocked() const {
  uint32_t until = getPinLockUntil();
  if (until == 0) return false;
  // Handle millis() overflow (wraps every ~49 days)
  return (int32_t)(until - millis()) > 0;
}
                                                                                                          