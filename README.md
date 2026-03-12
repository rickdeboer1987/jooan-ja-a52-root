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
