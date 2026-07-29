# Contributing to SecureVault

Thanks for your interest! SecureVault is a hardware password manager project — issues, fixes, hardware ports, and docs are all welcome.

## Ground rules

- **Be kind.** Assume good intent.
- **One change per PR.** Small, focused PRs get merged fast.
- **The build must stay green.** CI compiles the firmware on every push (see `.github/workflows/build.yml`). If CI is red, the PR isn't ready.
- **Security-sensitive changes** (crypto, key lifecycle, session handling) must include a brief threat-model note in the PR description explaining what was changed and why it's safe.

## Dev setup

### Firmware

You need PlatformIO with the ESP32-S3 toolchain:

```bash
pip install platformio
cd firmware
pio run -t upload
```

The firmware uses dual-framework mode (`arduino` + `espidf`). See `firmware/platformio.ini` and `SETUP.md` for the exact build configuration.

### Electron app

```bash
cd electron
npm install
npm start
```

Requires Node.js 18+ and Electron 31+.

### Chrome extension

Load unpacked from `extension/` in Developer mode. No build step needed.

## Code style

### Firmware (C++)
- Match the surrounding code — comment density, naming (`camelCase` funcs, `C_*` colors, `Screen::XXX` enum values), and 2-space indent.
- New screens follow the `drawXxx()` / `handleXxxTouch()` pair pattern and register in the `UiController` dispatch.
- All sensitive buffers must use `secureZero()` instead of plain `memset` — the compiler may optimize away a regular memset on a buffer that's going out of scope.
- Touch zones must stay pixel-accurate — verify hit-testing against the 320×240 grid.

### Electron (JavaScript)
- Match the existing module style: `'use strict'` at top, JSDoc on exported functions.
- All crypto stays in the main process — renderer never sees keys or raw serial bytes.
- Sensitive `Buffer` objects must be `.fill(0)`'d before going out of scope.

### Extension (JavaScript)
- Manifest V3: use service workers, not persistent backgrounds.
- Shared modules (`vaultFileCrypto.js`, `breachCheck.js`) must stay API-compatible between Electron and Extension copies.

## Good first issues

- 📷 Add real device photos/GIFs to `docs/img/` and wire them into the README.
- 🔐 ESP32 Flash Encryption + Secure Boot v2 implementation guide.
- 🌍 More host keyboard layouts beyond the standard HID scancode map.
- 🧪 A host-side script to generate large test vaults for stress testing.
- 📱 iOS Safari autofill integration (extension side).
- 🎨 Dark/light theme toggle for the Electron renderer.

## Reporting bugs

Open an issue with:
- **Component**: firmware / electron / extension
- **Board revision** (for firmware issues)
- **Firmware version** (check the splash screen or serial log)
- **Electron/Extension version** (check package.json / manifest.json)
- **Steps to reproduce**
- **Expected vs actual behavior**
- Serial log output if you have it (firmware issues)

## Security vulnerabilities

If you find a security vulnerability, please **do not** open a public issue. Instead, email the maintainer directly or use GitHub's private vulnerability reporting feature. Include:
- The component affected
- The specific vulnerability (e.g., key not zeroed, nonce reused, session not invalidated)
- A proof-of-concept or reproduction steps
- Suggested fix if you have one

Security fixes are prioritized and merged as quickly as possible.
