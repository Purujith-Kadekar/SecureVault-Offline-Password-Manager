# GitHub Repository Setup Guide

This file contains the metadata you should configure on your GitHub repository after uploading.

## Repository Name
`SecureVault`

## Repository Description
Paste this into the GitHub "Description" field (Settings → General → Description):

```
Offline hardware password manager with 6-layer encryption — ESP32-S3 firmware + Electron desktop app + Chrome extension. ECDH P-256 + AES-256-GCM. No cloud, no accounts.
```

## Repository Topics (Tags)
Add these topics on GitHub (Settings → General → Topics):

```
esp32-s3
password-manager
hardware-wallet
e2ee
ecdh
aes-256-gcm
hkdf
ble-hid
usb-hid
platformio
esp-idf
electron
chrome-extension
manifest-v3
captive-portal
iot-security
offline-security
zero-knowledge
firmware
embedded
```

## Homepage URL
Set this to your flasher page (after enabling GitHub Pages):

```
https://shubhjaiswal408.github.io/SecureVault/
```

## GitHub Pages Setup
1. Go to Settings → Pages
2. Source: Deploy from branch
3. Branch: `main`
4. Folder: `/flasher`
5. Save — the flasher page will be live at the URL above within a few minutes

## How to Upload to GitHub

### Option 1: Create a new repository and push

```bash
# 1. Create a new repo on GitHub: https://github.com/new
#    Name: SecureVault
#    Description: (paste from above)
#    Public repository

# 2. Initialize git in the project directory
cd /path/to/SecureVault-github
git init
git add .
git commit -m "Initial commit: SecureVault firmware + Electron + Extension + Flasher"

# 3. Push to GitHub
git remote add origin https://github.com/Shubhjaiswal408/SecureVault.git
git branch -M main
git push -u origin main
```

### Option 2: Upload via GitHub web interface

If you don't want to use git CLI, you can:
1. Create the repo on GitHub
2. Drag and drop the files from `SecureVault-GitHub.zip` (extract first)
3. Or use the GitHub Desktop app

## After Upload

1. **Enable GitHub Pages** (Settings → Pages → `/flasher` folder) for the self-flasher
2. **Set repository description and topics** (paste from above)
3. **Add the Electron .exe** — since it's >75MB, you'll need to use a GitHub Release:
   - Go to Releases → Create a new release
   - Tag: `v5.4.9`
   - Title: `SecureVault v5.4.9 — Initial Release`
   - Upload the Electron .exe as a release asset (GitHub allows up to 2GB per release file)
   - Write the release notes from the CHANGELOG
4. **Add firmware binaries for the flasher** — also via Releases or CI:
   - The CI workflow will compile firmware on each push
   - Download the compiled `.bin` files from CI artifacts
   - Place them in `flasher/firmware/` and push
   - Or add a CI step that auto-deploys binaries to the flasher directory
5. **Star your own repo** to encourage others to star it too
