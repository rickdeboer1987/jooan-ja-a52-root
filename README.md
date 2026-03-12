# Jooan JA-A52 / S3U Root Exploit

Full root shell on **Jooan JA-A52** (A2RU) and **Jooan S3U** IP cameras. Three methods: OTA via SD card, OTA via web upload, or chip programmer SPI flash modification.

**The SD card and web upload OTA methods require NO hardware tools** — just a microSD card or a web browser. Both confirmed working.

## Device Info

| Field | Value |
|-------|-------|
| Models | Jooan JA-A52 (A2RU), Jooan S3U |
| SoC | Ingenic T23N |
| RAM | 46 MB |
| Flash | 8 MB SPI NOR (W25Q64) |
| Firmware | ja_version=01.23N.20251126.20 (A52), 05.02.31.29 (S3U) |
| Platform | QAIOT (jooancloud.com) |
| Web server | GoAhead (HTTPS :443) |
| RTSP | LIVE555 on :554 |
| Main process | jooanipc |

## How to Root (No Hardware Required)

### Method 1: SD Card OTA (confirmed working)

Tested on both JA-A52 and S3U. No tools needed — just a microSD card.

1. Download `jooan_ota_root.bin` from Releases (or build it yourself with `tools/build_ota_shell.py`)
2. Format a microSD card as FAT32
3. Copy `jooan_ota_root.bin` to the root of the SD card, renamed to `JOOAN_FW_PKG`
4. Insert the SD card into the camera
5. Power cycle the camera
6. Wait ~60 seconds for the camera to boot and apply the OTA
7. Connect: `telnet <camera-ip> 24`
8. Remove the SD card after confirming root (otherwise it re-applies every boot)

Or use `tools/prep_sd_ota.ps1` (Windows PowerShell) to automate steps 2-3.

### Method 2: Web Upload OTA (confirmed working)

Same OTA package, uploaded through the camera's web interface.

1. Download `jooan_ota_root.bin` from Releases (or build it yourself)
2. Open `https://<camera-ip>/` in a browser (accept the self-signed cert)
3. Log in with default credentials: `admin` / `admin123`
4. Navigate to the firmware upgrade page
5. Upload `jooan_ota_root.bin`
6. Wait for the camera to apply and reboot (~60 seconds)
7. Connect: `telnet <camera-ip> 24`

### Method 3: Chip Programmer (confirmed working)

Requires opening the camera. Use this if the OTA methods don't work for your firmware version.

**Hardware needed:**
- CH341A USB programmer (~$5 on AliExpress)
- SOIC-8 test clip (~$3) for in-circuit flashing without desoldering
- [CH341A drivers](https://github.com/nickvdl/CH341-driver) (Windows)

**Steps:**
1. Open the camera case (4 screws under the rubber pads on the base)
2. Locate the W25Q64 SPI flash chip (8-pin SOIC, near the edge of the PCB)
3. Attach the SOIC-8 clip to the flash chip — pin 1 aligns (dot on chip = red wire on clip)
4. **Read the stock firmware first** as backup: `flashrom -p ch341a_spi -r stock_backup.bin`
5. Verify the read: read twice and compare MD5 hashes — they must match
6. Flash the backdoored firmware: `flashrom -p ch341a_spi -w firmware/backdoored_v2.bin`
7. Verify the write: read back and compare CRC32 = `0x66E90B6B`
8. Remove clip, reassemble camera, power on
9. Wait ~60 seconds for boot, then connect: `telnet <camera-ip> 23`

## Access After Rooting

| Method | Command |
|--------|---------|
| Telnet | `telnet <IP> 24` or `telnet <IP> 2424` |
| Netcat shell | `nc <IP> 2323` |
| Root password | (none — direct `/bin/sh`) |

The OTA exploit runs `upgrade.sh` which starts telnetd and netcat listeners. It also writes persistence to `/opt/etc/local.rc` so the backdoor survives reboots.

## IronMan OTA Format (Fully Reversed)

The Jooan firmware update format ("IronMan") has three parts and is **completely unsigned** — no cryptographic signature, only MD5 integrity checks.

```
Plaintext Header (96 bytes)
  0x00  8B   Magic: "jooan\0\0\0"
  0x08  8B   Payload size (ASCII decimal) = sqfs_size + 96 (trailer)
  0x10  48B  Version string: "ver=X.X.X.X;ProductName=XXX"
  0x40  32B  MD5 hex of (sqfs + encrypted_trailer)

SquashFS Payload (variable size)
  Contains upgrade.sh (runs as root)
  Can also contain partition images, etc.

Encrypted Trailer (96 bytes)
  Encrypted with QAUpgradeEncV1, decrypts to:
  0x00  8B   Magic: "toolv\0\0\0"
  0x08  8B   SquashFS size (ASCII decimal)
  0x10  48B  Zeros
  0x40  32B  MD5 hex of sqfs only
```

### QAUpgradeDecV1 Encryption

The trailer uses a custom symmetric cipher (reversed from goahead MIPS binary at 0x43AED4):

**Decryption** (what the camera does):
1. Compute stride: `stride = ((buf[95] >> 2) & 0xF) + 1`
2. Byte-swap loop backwards by stride (positions start, start-stride, ..., stride — swap `[i]` and `[i+1]`)
3. 2-bit right circular rotation across all 96 bytes

**Encryption** (inverse — what we do to build the OTA):
1. 2-bit left circular rotation across all 96 bytes
2. Compute stride from the rotated buffer: `stride = ((buf[95] >> 2) & 0xF) + 1`
3. Byte-swap loop forwards by stride

### Validation Flow

1. **IronManPkgCheck**: Reads first 96 bytes, checks "jooan" magic, extracts payload size and MD5
2. **QAUpgradeDecV1**: Decrypts last 96 bytes of the payload
3. **IronManUpgrade**: Checks decrypted trailer for "toolv" magic, validates both MD5s
4. **SquashFS mount + upgrade.sh**: Mounts the SquashFS payload, executes `upgrade.sh` as root

### ProductName Gotcha

The camera strips the "JA-" prefix from its internal model name before comparing. So if your camera is "JA-A52", the OTA must say `ProductName=A52`. For S3U cameras, use `ProductName=A1A` (the internal model code). Using the wrong ProductName causes silent rejection.

## SPI Flash Layout

| Partition | Offset | Size | Filesystem |
|-----------|--------|------|------------|
| boot | 0x000000 | 256 KB | raw (U-Boot) |
| bootenv | 0x040000 | 32 KB | raw |
| kernel | 0x048000 | 1472 KB | raw (uImage) |
| rootfs | 0x1B8000 | 2880 KB | SquashFS (XZ) |
| appfs | 0x488000 | 3136 KB | SquashFS (XZ) |
| config | 0x798000 | 384 KB | JFFS2 |
| confbak | 0x7F8000 | 32 KB | JFFS2 |

### MTD Device Mapping (confirmed from live camera)

```
dev:    size   erasesize  name
mtd0: 00040000 00008000 "boot"
mtd1: 00008000 00008000 "bootenv"
mtd2: 00170000 00008000 "kernel"
mtd3: 002d0000 00008000 "rootfs"
mtd4: 00310000 00008000 "appfs"
mtd5: 00060000 00008000 "config"
mtd6: 00008000 00008000 "confbak"
```

## Firmware Files

### `firmware/stock_firmware_a2r.bin`

Original unmodified 8 MB SPI flash dump read from chip programmer.

- **Size**: 8,388,608 bytes
- **MD5**: `b5b93947e8589b369b6b89097e9ed62e`
- **Source**: Direct chip read via CH341A programmer + SOIC-8 clip
- **Contents**: Stock Jooan JA-A52 firmware, version 01.23N.20251126.20

### `firmware/backdoored_v2.bin`

Modified full SPI image with persistent root shell. For chip programmer flashing only.

- **Size**: 8,388,608 bytes
- **MD5**: `0fb24004cf4b397a52035eb3ebbacd9f`
- **CRC32**: `0x66E90B6B`

Modified partitions: rootfs (telnetd + nc in rcS, root password set), appfs (telnetd in startapp), config JFFS2 (persistence in local.rc). Boot and kernel untouched.

## Tools

### `tools/build_ota_shell.py`

Builds the IronMan OTA package that roots the camera. This is the main exploit tool.

- Constructs the 3-part OTA: plaintext header + SquashFS (containing upgrade.sh) + encrypted trailer
- Implements QAUpgradeEncV1 (inverse of the camera's decryption) with round-trip verification
- upgrade.sh starts telnetd on ports 24/2424, netcat shell on 2323, writes persistence to JFFS2

**Requirements**: Python 3.12, [squashfs-tools-ng](https://github.com/AgentD/squashfs-tools-ng) (Windows MinGW build — `tar2sqfs.exe`)

**Usage**:
```
python build_ota_shell.py
```

**Output**: `jooan_ota_root.bin` (~4 KB) — upload via web interface or copy to SD card as `JOOAN_FW_PKG`

### `tools/prep_sd_ota.ps1`

Windows PowerShell script that formats an SD card as FAT32 and copies the OTA package as `JOOAN_FW_PKG`. Automates SD card preparation.

### `tools/inject_backdoors_v2.py`

Builds the full 8 MB backdoored SPI image (`firmware/backdoored_v2.bin`) for chip programmer flashing. Handles SquashFS rebuild (preserving symlinks via in-memory tar stream), JFFS2 node injection with correct CRC32, and full image assembly.

**Requirements**: Python 3.12, [squashfs-tools-ng](https://github.com/AgentD/squashfs-tools-ng)

## Lessons Learned

### The OTA format has THREE parts, not two

Initial reverse engineering of the IronMan format only found the 96-byte plaintext header + SquashFS payload. The camera kept failing with `FwUpgradeFromMem! failed...rebooting`.

The missing piece: after `IronManPkgCheck` validates the header, the camera runs `QAUpgradeDecV1` on the **last 96 bytes** of the payload. Without a proper encrypted trailer containing the "toolv" magic, the decryption produces garbage and validation fails. The breakthrough came from examining an existing OTA file — decrypting its last 96 bytes revealed the "toolv" trailer format with its own MD5 field.

### Two different MD5 fields

The header MD5 and trailer MD5 hash different things:
- **Header MD5** = `md5(squashfs_data + encrypted_trailer)` — covers the entire payload
- **Trailer MD5** = `md5(squashfs_data)` — covers only the SquashFS

Getting these backwards causes silent validation failure.

### ProductName must match the camera's internal code

The camera strips "JA-" from its ProductName config before comparing with the OTA header. So "JA-A52" becomes "A52", "JA-A1A" becomes "A1A". Using the full model name (e.g., `ProductName=JA-A52`) causes the OTA to be silently rejected.

### QAUpgradeDecV1 is a custom symmetric cipher

Not standard encryption — it's a byte-rotation + stride-based swap scheme. Had to reverse it from MIPS disassembly (goahead binary at 0x43AED4) and implement the exact inverse to build valid OTA packages. The byte-swap direction matters: forward for encryption, backward for decryption.

### Windows tar destroys Unix symlinks

The rootfs contains 141 symlinks (`/bin/sh` -> `busybox`, `/sbin/init` -> `busybox`, etc.). Extracting a tar archive to Windows NTFS converts all symlinks to regular files. Re-packing creates a rootfs where the system cannot boot.

**Solution**: Modify the tar stream in Python memory using `tarfile` module. Never extract to Windows filesystem.

### JFFS2 CRC32 double-init

JFFS2 uses a non-standard CRC32 variant:
```python
crc = (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF
```
Standard `zlib.crc32(data) & 0xFFFFFFFF` produces wrong values. Both node_crc and data_crc must be correct.

### Camera stability

The Jooan cameras are fragile — 2-3 rapid connections can cause a boot loop requiring physical power cycle. Be gentle with connection attempts.

### Failed approaches

1. **Command injection via OTA flow** — All `system()` calls in goahead use hardcoded strings, no injection possible. But the OTA format itself is unsigned, so we craft our own `upgrade.sh` instead.
2. **Two-part OTA (header + sqfs only)** — Missing the encrypted "toolv" trailer. Camera rejects with "IronManUpgrade failed".
3. **Wrong ProductName** — Used "JA-A1A" instead of "A1A". Camera silently rejects the OTA.
4. **Encrypted header** — Tried encrypting the header too. Camera cannot find "jooan" magic. Header must be plaintext.
5. **JFFS2-only modification** — `local.rc` was not executed early enough. Needed rootfs + appfs changes.
6. **Windows tar extraction** — Destroyed all 141 busybox symlinks. Camera bricked (no `/bin/sh`).
7. **Wrong partition offset** — Accidentally wrote modified data at 0x1B0000 instead of 0x1B8000. Corrupted kernel.

## Docs

See `docs/jooan_security_analysis.md` for full security analysis including:
- Cloud API IDOR vulnerabilities
- APK secret extraction (AES keys, Alibaba credentials)
- TUTK P2P protocol analysis
- MQTT infrastructure
- Cross-brand token reuse

## Disclaimer

This research was performed on personally owned hardware for educational and security research purposes. Do not use these tools on devices you do not own.
