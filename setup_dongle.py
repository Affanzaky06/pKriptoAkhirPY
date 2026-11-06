# setup_dongle.py
"""
SecureGov USB Dongle Utility CLI
=================================
Utilitas praktis untuk mendeteksi flashdisk USB dan menginisialisasinya
menjadi USB Dongle resmi SecureGov.

Contoh Penggunaan:
------------------
  1. Memindai flashdisk/drive yang terpasang di komputer:
     python setup_dongle.py --scan

  2. Menginisialisasi Flashdisk (misal drive E:) menjadi USB Dongle:
     python setup_dongle.py E:

  3. Menguji verifikasi USB Dongle saat ini:
     python setup_dongle.py --verify
"""

import sys
import os
import argparse

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
from securegov.auth.usb_dongle import (
    list_connected_drives,
    setup_dongle,
    verify_dongle,
    load_allowed_vsns,
)


def cmd_scan():
    print("\n" + "=" * 65)
    print("  MEMINDAI PENYIMPANAN & USB DRIVE")
    print("=" * 65)
    drives = list_connected_drives()
    allowed_vsns = load_allowed_vsns()

    if not drives:
        print("  Tidak ada drive yang terdeteksi.")
        return

    for d in drives:
        drive_name = d.get('mount') or d.get('drive', 'Unknown')
        print(f"\n  [Drive {drive_name}]")
        print(f"    - Serial Volume (VSN)  : {d.get('vsn') or 'N/A'}")
        print(f"    - Terdaftar di VSN DB  : {'✓ YA' if d.get('is_authorized_vsn') else '✗ Tidak'}")
        print(f"    - File Kunci Rahasia   : {'✓ DITEMUKAN (.key)' if d.get('has_key_file') else '✗ Tidak ada'}")
        print(f"    - Status Dongle Valid  : {'✓ RESMI TERVERIFIKASI' if d.get('is_valid_dongle') else 'Bukan Dongle'}")

    print("\n" + "=" * 65)
    valid = verify_dongle()
    print(f"  Hasil Keseluruhan Sistem: {'✓ DONGLE AKTIF TERPASANG' if valid else '✗ DONGLE BELUM TERTANCAP'}\n")


def cmd_setup(drive_letter: str):
    drive = drive_letter.strip().upper()
    if not drive.endswith("\\"):
        drive = drive if drive.endswith(":") else drive + ":"
        drive += "\\"

    print("\n" + "=" * 65)
    print(f"  MENDAFTARKAN DRIVE '{drive}' SEBAGAI USB DONGLE RESMI")
    print("=" * 65)

    try:
        res = setup_dongle(drive, register_volume_serial=True)
        key_loc = res.get('key_path') or res.get('key_file', 'OK')
        print(f"  ✓ File kunci berhasil dibuat : {key_loc}")
        print(f"  ✓ Volume Serial Number (VSN) : {res['vsn'] or 'Berhasil didaftarkan'}")
        print(f"  ✓ Serial VSN disimpan ke     : data/allowed_vsns.txt")
        print(f"  ✓ STATUS: DRIVE {drive} KINI MENJADI DONGLE RESMI SECUREGOV!")
        print("=" * 65 + "\n")
    except Exception as e:
        print(f"  ✗ Gagal menyiapkan dongle pada {drive}: {e}\n")


def cmd_verify():
    print("\n" + "=" * 65)
    print("  VERIFIKASI FISIK USB DONGLE")
    print("=" * 65)
    ok = verify_dongle()
    if ok:
        print("  ✓ OTENTIKASI BERHASIL: USB Dongle fisik ditemukan dan valid.")
    else:
        print("  ✗ OTENTIKASI GAGAL: Tidak ada USB Dongle yang cocok tertancap.")
    print("=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(description="SecureGov USB Dongle Management CLI")
    parser.add_argument("drive", nargs="?", help="Huruf drive Flashdisk (contoh: E: atau F:)")
    parser.add_argument("--scan", action="store_true", help="Pindai semua drive yang terhubung")
    parser.add_argument("--verify", action="store_true", help="Verifikasi keberadaan USB Dongle")

    args = parser.parse_args()

    if args.scan:
        cmd_scan()
    elif args.verify:
        cmd_verify()
    elif args.drive:
        cmd_setup(args.drive)
    else:
        cmd_scan()


if __name__ == "__main__":
    main()
