# Jooan JA-A52 (A2RU) Root Exploit

Full root shell on the **Jooan JA-A52** (box label: A2RU) IP camera via chip programmer SPI flash modification.

## Device Info

| Field | Value |
|-------|-------|
| Model | Jooan JA-A52 / A2RU |
| SoC | Ingenic T23N |
| RAM | 46 MB |
| Flash | 8 MB SPI NOR (W25Q64) |
| Firmware | ja_version=01.23N.20251126.20 |
| Platform | QAIOT (jooancloud.com) |
| Web server | GoAhead (HTTPS :443) |
| RTSP | LIVE555 on :554 |
| Main process | jooanipc |

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

## Firmware Files

### `firmware/stock_firmware_a2r.bin`

Original unmodified 8 MB SPI flash dump read from chip programmer.

- **Size**: 8,388,608 bytes
- **MD5**: `b5b93947e8589b369b6b89097e9ed62e`
- **Source**: Direct chip read via CH341A programmer + SOIC-8 clip
- **Contents**: Stock Jooan JA-A52 firmware, firmware version 01.23N.20251126.20

### `firmware/backdoored_v2.bin`

Modified firmware with persistent root shell access. Flash this to get full root.

- **Size**: 8,388,608 bytes
- **MD5**: `0fb24004cf4b397a52035eb3ebbacd9f`
- **CRC32**: `0x66E90B6B`

#### What was modified

**Boot + kernel**: Byte-for-byte identical to stock. Not touched.

**Rootfs** (SquashFS at 0x1B8000):
- `/etc/shadow` — root password changed to `root` (SHA-256 hash)
- `/etc/init.d/rcS` — starts `telnetd` on ports 23 and 2424, `nc -l -p 2323 -e /bin/sh` before goahead
- `/etc/webs/backdoor.txt` — web-accessible file returning `BACKDOOR_INSTALLED` (verify at `https://<IP>/backdoor.txt`)
- All 141 busybox symlinks preserved (critical — see Lessons Learned)

**Appfs** (SquashFS at 0x488000):
- `startapp` — starts `telnetd` on port 2424 and `nc -l -p 2323 -e /bin/sh` as backup before `local.rc`

**Config JFFS2** (at 0x798000):
- `/opt/etc/local.rc` — additional persistence: telnetd + nc shell (survives factory reset)
- `/opt/conf/backdoor.sh` — extra backdoor script

#### Access after flashing

| Method | Command |
|--------|---------|
| Telnet | `telnet <IP> 23` or `telnet <IP> 2424` |
| Netcat shell | `nc <IP> 2323` |
| Web check | `curl -k https://<IP>/backdoor.txt` |
| Root password | `root` |

## How to Flash

### Method 1: Chip Programmer (confirmed working)

This is the method we used. Requires opening the camera.

**Hardware needed:**
- CH341A USB programmer (~$5 on AliExpress)
- SOIC-8 test clip (~$3) for in-circuit flashing without desoldering
- [CH341A drivers](https://github.com/nickvdl/CH341-driver) (Windows)

**Steps:**
1. Open the camera case (4 screws under the rubber pads on the base)
2. Locate the W25Q64 SPI flash chip (8-pin SOIC, near the edge of the PCB)
3. Attach the SOIC-8 clip to the flash chip — make sure pin 1 aligns (dot on chip = red wire on clip)
4. **Read the stock firmware first** as backup: `flashrom -p ch341a_spi -r stock_backup.bin` (or use AsProgrammer/NeoProgrammer GUI)
5. Verify the read: read twice and compare MD5 hashes — they must match
6. Flash the backdoored firmware: `flashrom -p ch341a_spi -w backdoored_v2.bin`
7. Verify the write: read back and compare CRC32 = `0x66E90B6B`
8. Remove clip, reassemble camera, power on
9. Wait ~60 seconds for boot, then connect: `telnet <camera-ip> 23`

**Tips:**
- The clip connection can be flaky — if reads fail or return all 0xFF, reseat the clip
- Always read before writing so you have a stock backup
- Camera must be powered during in-circuit flashing (USB from programmer powers the chip)
- If the camera doesn't boot, re-flash stock_firmware_a2r.bin to restore

### Method 2: SD Card (untested — should work)

The camera checks for firmware at `/mnt/sd_card/JOOAN_FW_PKG` on boot. This uses the same IronMan OTA format as the web upload.

**This method cannot flash raw SPI images** like `backdoored_v2.bin`. It requires a properly formatted IronMan OTA package (see TODO section below). Once we build the OTA package:

1. Format a microSD card as FAT32
2. Copy the OTA package to the root of the SD card as `JOOAN_FW_PKG`
3. Insert the SD card into the camera
4. Power cycle the camera
5. The camera will detect the file, apply the upgrade, and reboot
6. Remove the SD card after reboot (otherwise it may re-flash every boot)

**Status:** Waiting on OTA package build (see TODO below). The SD card path is confirmed in the firmware — `ipc_fwLocalUpGradeBySDcard` reads from this exact path.

### Method 3: Web Upload (untested — should work)

Upload through the camera's built-in web interface. Same IronMan OTA format as SD card.

1. Open `https://<camera-ip>/` in a browser (accept the self-signed cert)
2. Log in with default credentials: `admin` / `admin123`
3. Navigate to the firmware upgrade page
4. Upload the OTA package file
5. Wait for the camera to apply and reboot (~2-3 minutes)

**Status:** Waiting on OTA package build (see TODO below).

## Tools

### `tools/inject_backdoors_v2.py`

Python script that takes the stock firmware dump and produces the backdoored image. Handles:

- SquashFS extraction and rebuild via `sqfs2tar` / `tar2sqfs` (preserves symlinks)
- Tar stream modification in memory (never extracts to Windows filesystem)
- JFFS2 node injection with correct CRC32 (double-init variant)
- Full 8 MB image assembly

**Requirements**: Python 3.12, [squashfs-tools-ng](https://github.com/AgentD/squashfs-tools-ng) (Windows MinGW build)

**Usage**:
```
python inject_backdoors_v2.py
```

## Lessons Learned

### Windows tar destroys Unix symlinks

The rootfs contains 141 symlinks (`/bin/sh` → `busybox`, `/sbin/init` → `busybox`, etc.). Extracting a tar archive to Windows NTFS converts all symlinks to regular files. Re-packing from those extracted files creates a rootfs where the system cannot boot — no `/bin/sh`, no `/sbin/init`.

**Solution**: Modify the tar stream in Python memory using `tarfile` module. Read from `sqfs2tar`, pipe through Python (modify only target files, pass everything else including symlinks untouched), pipe to `tar2sqfs`. Never touch the Windows filesystem.

### JFFS2 CRC32 double-init

JFFS2 uses a non-standard CRC32 variant:
```python
crc = (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF
```
Standard `zlib.crc32(data) & 0xFFFFFFFF` produces wrong values. Every JFFS2 node has two CRC fields (node_crc over the header, data_crc over the payload) that must both be correct or the kernel skips the node.

### Failed approaches

1. **SD card firmware** (`/mnt/sd_card/JOOAN_FW_PKG`) — IronMan format OTA, but no way to inject code into the upgrade flow. All `system()` calls in `goahead` use hardcoded strings.
2. **Web OTA upload** — Same IronMan format, same hardcoded upgrade path. No command injection.
3. **JFFS2-only modification** — Booted fine but `local.rc` wasn't executed early enough / telnetd wasn't starting. Needed rootfs + appfs changes too.
4. **First rootfs attempt** (`backdoored_full.bin`) — Windows tar extraction destroyed symlinks. Camera didn't boot.
5. **Previous session firmware** (`backdoored_firmware.bin`) — Accidentally wrote modified data to kernel partition at 0x1B0000. Corrupted kernel, no boot.

## TODO: Web Upload Root (No Chip Programmer)

The current method requires a CH341A chip programmer + SOIC-8 clip to flash the SPI chip directly. The goal is to make this work through the **standard web firmware upload** so anyone can root their camera without hardware tools.

### What we know

The Jooan OTA format ("IronMan") is simple and **unsigned**:

```
Offset  Size    Content
0x00    8       Magic: "jooan\0\0\0"
0x08    8       Payload size (ASCII decimal, null-padded)
0x10    48      Version string: "ver=5.2.31.29;ProductName=JA-A52"
0x40    32      MD5 of payload (ASCII hex, optional)
0x60    ...     SquashFS payload containing upgrade.sh
```

- The camera mounts the SquashFS and runs `upgrade.sh` **as root**
- No cryptographic signature verification — only MD5 integrity check
- Same format works for web upload (HTTPS :443) and SD card (`/mnt/sd_card/JOOAN_FW_PKG`)

### What needs to happen

1. **Map MTD devices** on the live camera (`cat /proc/mtd`) to determine which `/dev/mtdX` corresponds to rootfs, appfs, and config partitions
2. **Build an OTA package** where `upgrade.sh` uses `flashcp` or `dd` to write our modified `rootfs_fixed.sqfs` and `appfs_fixed.sqfs` directly to the correct MTD partitions
3. **Test version validation** — does the camera reject "downgrades" or accept any version string?
4. **Test ProductName validation** — does it check against the device model or accept anything?
5. **Package everything** into a single IronMan file users can upload through the standard Jooan web interface at `https://<camera-ip>/upgrade.html`

### Why this should work

- `upgrade.sh` executes as root with full system access
- No signature checking — the camera only validates the IronMan header structure and optional MD5
- The SquashFS payload can be any size (the 96-byte header contains the payload length)
- We can embed our modified partition images inside the upgrade SquashFS alongside `upgrade.sh`

### Estimated OTA package

```
IronMan header (96 bytes)
└── SquashFS payload
    ├── upgrade.sh          (flashes partitions via dd/flashcp)
    ├── rootfs_fixed.sqfs   (~2.8 MB, modified rootfs with backdoors)
    └── appfs_fixed.sqfs    (~3.1 MB, modified appfs with backdoors)
```

Total size: ~6 MB (fits within camera's RAM for upload processing)

## Hardware Required

- CH341A USB programmer (or similar SPI programmer)
- SOIC-8 test clip (for in-circuit reading/writing without desoldering)
- The camera (obviously)

## Docs

See `docs/jooan_security_analysis.md` for full security analysis including:
- Cloud API IDOR vulnerabilities
- APK secret extraction (AES keys, Alibaba credentials)
- TUTK P2P protocol analysis
- MQTT infrastructure
- Cross-brand token reuse

## Disclaimer

This research was performed on personally owned hardware for educational and security research purposes. Do not use these tools on devices you do not own.
