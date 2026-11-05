# create_shortcut.py
"""
Script Otomatis untuk Membuat Shortcut Desktop Windows
======================================================
Membuat shortcut 'SecureGov DocVault' di Desktop Windows yang
menjalankan aplikasi secara langsung via pythonw.exe (tanpa terminal).
"""

import os
import sys
import subprocess

def create_desktop_shortcut():
    proj_dir = os.path.dirname(os.path.abspath(__file__))
    python_dir = os.path.dirname(sys.executable)
    pythonw_path = os.path.join(python_dir, "pythonw.exe")

    if not os.path.isfile(pythonw_path):
        pythonw_path = sys.executable

    ps_script = f"""
    $WshShell = New-Object -ComObject WScript.Shell
    $DesktopPath = [Environment]::GetFolderPath("Desktop")
    $Shortcut = $WshShell.CreateShortcut("$DesktopPath\\SecureGov DocVault.lnk")
    $Shortcut.TargetPath = "{pythonw_path}"
    $Shortcut.Arguments = "app.py"
    $Shortcut.WorkingDirectory = "{proj_dir}"
    $Shortcut.WindowStyle = 1
    $Shortcut.Description = "SecureGov Enterprise DocVault - Defense Cryptosystem"
    $Shortcut.IconLocation = "$env:SystemRoot\\System32\\shell32.dll,47"
    $Shortcut.Save()
    Write-Output "Shortcut created at: $DesktopPath\\SecureGov DocVault.lnk"
    """

    res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True)
    print(res.stdout)
    if res.stderr:
        print("Notice:", res.stderr)

if __name__ == "__main__":
    create_desktop_shortcut()

