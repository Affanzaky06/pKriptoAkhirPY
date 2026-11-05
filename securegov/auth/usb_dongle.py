# securegov/auth/usb_dongle.py
"""
Real Hardware USB Dongle Verification Module
=============================================
Detects, registers, and verifies physical USB Flash Drives using hardware
identifiers (Volume Serial Number via ctypes/kernel32 and drive mountpoints via psutil).

Features:
  1. Real-time scanning of all connected physical drives using psutil and ctypes.
  2. Distinction between REMOVABLE (USB sticks) and FIXED drives.
  3. Secret key file (.securegov_dongle.key) deployment with cryptographic token.
  4. Volume Serial Number (VSN) verification against the local database and allow-list.
"""

import os
import sys
import string
import ctypes
from typing import Optional, List, Dict

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

from securegov.utils.config import DONGLE_SECRET_FILENAME, DONGLE_SECRET_VALUE
from securegov.utils.logger import get_logger

logger = get_logger(__name__)

# Path to file containing allowed VSNs
_ALLOWED_VSN_FILE = os.path.join("data", "allowed_vsns.txt")


# ---------------------------------------------------------------------------
# Hardware Drive Inspection Helpers
# ---------------------------------------------------------------------------

def get_volume_info(drive_mount: str) -> Dict[str, str]:
    """
    Query hardware volume information using Windows kernel32 API via ctypes.
    Returns:
      {
         'vol_name': str,
         'vsn': str (8-character HEX, e.g. '90ED188D'),
         'fs_type': str (e.g. 'FAT32', 'NTFS', 'exFAT'),
         'drive_type': str ('REMOVABLE', 'FIXED', 'CDROM', 'UNKNOWN')
      }
    """
    clean_drive = drive_mount if drive_mount.endswith("\\") else drive_mount + "\\"
    vol_name_buf = ctypes.create_unicode_buffer(260)
    fs_name_buf = ctypes.create_unicode_buffer(260)
    sn = ctypes.c_ulong()

    drive_type_str = "UNKNOWN"
    vsn_hex = "N/A"
    vol_name = "Local Disk"
    fs_type = "Unknown"

    if sys.platform == "win32":
        try:
            dtype = ctypes.windll.kernel32.GetDriveTypeW(clean_drive)
            if dtype == 2:
                drive_type_str = "REMOVABLE"
            elif dtype == 3:
                drive_type_str = "FIXED"
            elif dtype == 4:
                drive_type_str = "REMOTE"
            elif dtype == 5:
                drive_type_str = "CDROM"

            ret = ctypes.windll.kernel32.GetVolumeInformationW(
                clean_drive,
                vol_name_buf,
                260,
                ctypes.byref(sn),
                None,
                None,
                fs_name_buf,
                260
            )
            if ret != 0:
                vsn_hex = format(sn.value & 0xFFFFFFFF, "08X")
                vol_name = vol_name_buf.value or ("USB Drive" if drive_type_str == "REMOVABLE" else "Disk")
                fs_type = fs_name_buf.value or "FAT32"
        except Exception as exc:
            logger.debug("Hardware query failed for %s: %s", clean_drive, exc)

    return {
        "vol_name": vol_name,
        "vsn": vsn_hex,
        "fs_type": fs_type,
        "drive_type": drive_type_str
    }


def scan_physical_usb_drives() -> List[Dict]:
    """
    Scan all connected physical drives using psutil and Windows kernel32.
    Returns a list of structured dictionaries for every connected drive.
    """
    results = []
    allowed_vsns = load_allowed_vsns()

    candidate_mounts = []
    if _PSUTIL_AVAILABLE:
        try:
            for part in psutil.disk_partitions(all=True):
                if part.mountpoint:
                    candidate_mounts.append((part.mountpoint, part.opts, part.fstype))
        except Exception as exc:
            logger.warning("psutil disk_partitions query error: %s", exc)

    # Fallback if psutil is empty or unavailable
    if not candidate_mounts and sys.platform == "win32":
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                candidate_mounts.append((f"{letter}:\\", "", ""))
            bitmask >>= 1

    for mount, opts, fstype in candidate_mounts:
        vinfo = get_volume_info(mount)
        is_removable = (vinfo["drive_type"] == "REMOVABLE") or ("removable" in opts.lower())
        vsn = vinfo["vsn"]
        has_key = check_secret_file(mount)
        is_vsn_allowed = (vsn in allowed_vsns) if vsn != "N/A" else False

        usage_str = "N/A"
        if _PSUTIL_AVAILABLE:
            try:
                usage = psutil.disk_usage(mount)
                total_gb = usage.total / (1024 ** 3)
                free_gb = usage.free / (1024 ** 3)
                usage_str = f"{free_gb:.1f} GB free / {total_gb:.1f} GB"
            except Exception:
                pass

        results.append({
            "mount": mount,
            "vol_name": vinfo["vol_name"],
            "drive_type": "REMOVABLE (USB)" if is_removable else vinfo["drive_type"],
            "is_removable": is_removable,
            "vsn": vsn,
            "fs_type": vinfo["fs_type"] or fstype,
            "usage": usage_str,
            "has_key_file": has_key,
            "is_authorized_vsn": is_vsn_allowed,
            "is_valid_dongle": has_key or is_vsn_allowed
        })

    return results


# ---------------------------------------------------------------------------
# Key & VSN Management
# ---------------------------------------------------------------------------

def load_allowed_vsns() -> set[str]:
    """Load authorized VSNs from data/allowed_vsns.txt."""
    if not os.path.isfile(_ALLOWED_VSN_FILE):
        return set()
    with open(_ALLOWED_VSN_FILE, "r", encoding="utf-8") as f:
        return {line.strip().upper() for line in f if line.strip()}


def check_secret_file(drive_root: str) -> bool:
    """Check if the physical drive contains the secret dongle key."""
    key_path = os.path.join(drive_root, DONGLE_SECRET_FILENAME)
    if not os.path.isfile(key_path):
        return False
    try:
        with open(key_path, "rb") as f:
            content = f.read().strip()
        return content == DONGLE_SECRET_VALUE
    except OSError:
        return False


def register_usb_dongle(drive_root: str, username: str = "default") -> Dict:
    """
    Format and authorize a physical USB drive as an official SecureGov Dongle:
      1. Writes .securegov_dongle.key file to the drive root.
      2. Reads hardware VSN and appends to allowed_vsns.txt.
    """
    clean_drive = drive_root if drive_root.endswith("\\") else drive_root + "\\"
    vinfo = get_volume_info(clean_drive)
    vsn = vinfo["vsn"]

    # Write secret key file to the drive
    key_path = os.path.join(clean_drive, DONGLE_SECRET_FILENAME)
    with open(key_path, "wb") as f:
        f.write(DONGLE_SECRET_VALUE)

    # Set as hidden file on Windows
    if sys.platform == "win32":
        try:
            ctypes.windll.kernel32.SetFileAttributesW(key_path, 0x02) # FILE_ATTRIBUTE_HIDDEN
        except Exception:
            pass

    # Save VSN in allow-list
    if vsn and vsn != "N/A":
        os.makedirs(os.path.dirname(_ALLOWED_VSN_FILE) or ".", exist_ok=True)
        allowed = load_allowed_vsns()
        if vsn not in allowed:
            with open(_ALLOWED_VSN_FILE, "a", encoding="utf-8") as f:
                f.write(f"{vsn} # {username} - {vinfo['vol_name']}\n")

    logger.info("USB Dongle registered on %s (VSN: %s, User: %s)", clean_drive, vsn, username)
    return {
        "mount": clean_drive,
        "vsn": vsn,
        "vol_name": vinfo["vol_name"],
        "key_path": key_path,
        "status": "REGISTERED_OK"
    }


def verify_dongle_for_user(expected_vsn: Optional[str] = None) -> tuple[bool, str, Optional[Dict]]:
    """
    Scan all currently plugged-in USB drives and verify presence:
      - If expected_vsn is provided, requires matching that specific VSN.
      - Otherwise checks if any connected drive has a valid dongle key or registered VSN.

    Returns: (is_valid: bool, status_message: str, drive_info: dict | None)
    """
    drives = scan_physical_usb_drives()
    allowed_vsns = load_allowed_vsns()

    for d in drives:
        vsn = d["vsn"]
        has_key = d["has_key_file"]

        if expected_vsn and expected_vsn.strip():
            # Strict match against user's registered hardware VSN
            if vsn.upper() == expected_vsn.strip().upper() and has_key:
                msg = f"✓ Physical USB Dongle verified on {d['mount']} (VSN: {vsn}, '{d['vol_name']}')"
                logger.info(msg)
                return True, msg, d
            elif vsn.upper() == expected_vsn.strip().upper():
                msg = f"✓ USB Hardware VSN matched on {d['mount']} (VSN: {vsn})"
                logger.info(msg)
                return True, msg, d
        else:
            # General check: has secret key or VSN in allow-list
            if has_key and (vsn in allowed_vsns):
                msg = f"✓ USB Dongle verified on {d['mount']} (Key & VSN: {vsn})"
                return True, msg, d
            elif has_key:
                msg = f"✓ USB Dongle Key verified on {d['mount']}"
                return True, msg, d
            elif vsn in allowed_vsns:
                msg = f"✓ Registered Hardware VSN ({vsn}) verified on {d['mount']}"
                return True, msg, d

    return False, "✗ USB Dongle tidak ditemukan. Harap tancapkan USB Flash Drive terdaftar.", None


# Compatibility aliases for legacy tests
def verify_dongle(require_both: bool = False) -> bool:
    ok, _, _ = verify_dongle_for_user()
    return ok

def create_dongle_key_file(target_dir: str) -> None:
    path = os.path.join(target_dir, DONGLE_SECRET_FILENAME)
    with open(path, "wb") as f:
        f.write(DONGLE_SECRET_VALUE)

def register_vsn(drive_root: str) -> Optional[str]:
    vinfo = get_volume_info(drive_root)
    vsn = vinfo["vsn"]
    if vsn and vsn != "N/A":
        os.makedirs(os.path.dirname(_ALLOWED_VSN_FILE) or ".", exist_ok=True)
        with open(_ALLOWED_VSN_FILE, "a", encoding="utf-8") as f:
            f.write(vsn + "\n")
        return vsn
    return None

def setup_dongle(drive_root: str, register_volume_serial: bool = True) -> Dict:
    return register_usb_dongle(drive_root, "default")

def list_connected_drives() -> List[Dict]:
    return scan_physical_usb_drives()
