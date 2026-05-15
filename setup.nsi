; VPN Setup Package — NSIS Installer
; Strategy (in order of reliability):
;   Python:          winget → PowerShell download → abort with instructions
;   pip packages:    bundled offline wheels (no internet required)
;   OpenVPN Connect: winget (non-fatal if unavailable) → show link in browser
;   YubiKey libs:    yubikit speaks Windows Smart Card directly — no extra install needed
;   libykcs11.dll:   copied from Yubico PIV Tool if already present (opportunistic)

Unicode true
SetCompressor /SOLID lzma

!define APP_NAME    "VPN Setup"
!define APP_VER     "1.0"
!define HELPER_DIR  "$LOCALAPPDATA\vpnweb"
!define REG_UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNSetup"
!define PYTHON_REG   "Software\Python\PythonCore"
!define OVPN_DIR     "$PROGRAMFILES64\OpenVPN Connect"
!define YUBIPIV_BIN  "$PROGRAMFILES64\Yubico\Yubico PIV Tool\bin"

; Python fallback download (only used if winget fails)
!define URL_PYTHON   "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"

Name "${APP_NAME} ${APP_VER}"
OutFile "VPNSetup.exe"
InstallDir "${HELPER_DIR}"
RequestExecutionLevel admin
ShowInstDetails show

; ---- Pages ----
Page instfiles

; ---- Helpers ----
!include "LogicLib.nsh"
!include "WinVer.nsh"
!include "FileFunc.nsh"

Var /GLOBAL PythonExe
Var /GLOBAL PythonwExe

; ---- Main install section ----
Section "Install" SEC_MAIN
  ; === Log — append so re-runs don't overwrite previous crash info ===
  nsExec::ExecToStack 'powershell -NoProfile -Command "Get-Date -Format ''yyyy-MM-dd HH:mm:ss''"'
  Pop $0  ; exit code
  Pop $1  ; timestamp string
  FileOpen $R0 "C:\Users\Public\vpnlog.txt" a
  FileWrite $R0 "$\r$\n=== VPN Setup Run: $1 ===$\r$\n"
  FileClose $R0

  SetOutPath "${HELPER_DIR}"

  ; --- vpnweb-helper.py and offline wheels ---
  File "vpnweb-helper.py"
  SetOutPath "${HELPER_DIR}\wheels"
  File "wheels\*.whl"
  SetOutPath "${HELPER_DIR}"

  ; === Step 1: Python ===
  DetailPrint "=== Step 1/4: Python ==="
  FileOpen $R0 "C:\Users\Public\vpnlog.txt" a
  FileWrite $R0 "Step 1: Finding Python$\r$\n"
  FileClose $R0
  Call FindPython
  ${If} $PythonExe != ""
    DetailPrint "Python already installed: $PythonExe"
    FileOpen $R0 "C:\Users\Public\vpnlog.txt" a
    FileWrite $R0 "Found Python: $PythonExe$\r$\n"
    FileClose $R0
    Goto python_ok
  ${EndIf}
  FileOpen $R0 "C:\Users\Public\vpnlog.txt" a
  FileWrite $R0 "Python not found in known locations, trying winget$\r$\n"
  FileClose $R0

  ; Try winget first (Windows 10 1709+ built-in)
  DetailPrint "Installing Python 3.12 via winget…"
  nsExec::ExecToLog 'winget install --id Python.Python.3.12 --source winget --silent --accept-package-agreements --accept-source-agreements'
  Pop $0
  FileOpen $R0 "C:\Users\Public\vpnlog.txt" a
  FileWrite $R0 "winget Python exit code: $0$\r$\n"
  FileClose $R0
  ; Accept 0 (success) and 3010 (success, reboot suggested) and -1978335212 (already installed)
  ${If} $0 == 0
  ${OrIf} $0 == 3010
  ${OrIf} $0 == 2316632084
    DetailPrint "winget Python succeeded (exit $0) — locating Python…"
    Call FindPython
    FileOpen $R0 "C:\Users\Public\vpnlog.txt" a
    FileWrite $R0 "FindPython after winget: $PythonExe$\r$\n"
    FileClose $R0
    ${If} $PythonExe != ""
      Goto python_ok
    ${EndIf}
  ${EndIf}

  ; Fallback: download from python.org
  DetailPrint "winget unavailable or failed — downloading Python 3.12 from python.org…"
  InitPluginsDir
  StrCpy $R1 "${URL_PYTHON}"
  StrCpy $R2 "$PLUGINSDIR\python-setup.exe"
  Call Download
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Could not install Python automatically.$\r$\n$\r$\nPlease install Python 3.12 manually:$\r$\nhttps://www.python.org/downloads/release/python-3124/$\r$\n$\r$\nThen re-run this installer."
    Abort
  ${EndIf}
  DetailPrint "Installing Python 3.12 (system-wide)…"
  ExecWait '"$PLUGINSDIR\python-setup.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_test=0' $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Python installer returned error $0.$\r$\nPlease install Python 3.12 manually from python.org."
    Abort
  ${EndIf}
  Call FindPython
  ${If} $PythonExe == ""
    MessageBox MB_ICONSTOP "Python was installed but could not be located.$\r$\nPlease re-run this installer."
    Abort
  ${EndIf}

  python_ok:
  DetailPrint "Using Python: $PythonExe"

  ; Verify Python responds
  nsExec::ExecToStack '"$PythonExe" -c "import sys; print(sys.version)"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Python is installed but not working correctly.$\r$\nTry rebooting, then re-run this installer."
    Abort
  ${EndIf}
  DetailPrint "Python OK: $1"

  ; === Step 2: Python packages (offline wheels — no internet needed) ===
  DetailPrint "=== Step 2/4: Python packages ==="
  DetailPrint "Installing from bundled wheels (no internet required)…"

  ; Write a small Python script that runs pip and captures full output to log
  FileOpen $R0 "C:\Users\Public\runpip.py" w
  FileWrite $R0 "import subprocess, sys$\r$\n"
  FileWrite $R0 "wheels = r'$LOCALAPPDATA\vpnweb\wheels'$\r$\n"
  FileWrite $R0 "pkgs = ['flask', 'yubikey-manager', 'requests', 'cryptography']$\r$\n"
  FileWrite $R0 "log = open(r'C:\Users\Public\vpnlog.txt', 'a')$\r$\n"
  FileWrite $R0 "$\r$\n"
  FileWrite $R0 "# First upgrade pip so it can handle modern wheel metadata (Metadata-Version 2.4)$\r$\n"
  FileWrite $R0 "r = subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', '--quiet', 'pip'], capture_output=True, text=True)$\r$\n"
  FileWrite $R0 "log.write('=== pip self-upgrade ===\n' + r.stdout + r.stderr + f'exit: {r.returncode}\n\n')$\r$\n"
  FileWrite $R0 "$\r$\n"
  FileWrite $R0 "# Attempt 1: offline-only (no PyPI) — clearest error if a wheel is missing$\r$\n"
  FileWrite $R0 "cmd1 = [sys.executable, '-m', 'pip', 'install', '--find-links', wheels, '--no-index'] + pkgs$\r$\n"
  FileWrite $R0 "r1 = subprocess.run(cmd1, capture_output=True, text=True)$\r$\n"
  FileWrite $R0 "log.write('=== pip attempt 1 (offline) ===\n' + r1.stdout + r1.stderr + f'exit: {r1.returncode}\n\n')$\r$\n"
  FileWrite $R0 "if r1.returncode == 0:$\r$\n"
  FileWrite $R0 "    log.close(); sys.exit(0)$\r$\n"
  FileWrite $R0 "$\r$\n"
  FileWrite $R0 "# Attempt 2: allow PyPI fallback in case a package needs to be downloaded$\r$\n"
  FileWrite $R0 "cmd2 = [sys.executable, '-m', 'pip', 'install', '--find-links', wheels] + pkgs$\r$\n"
  FileWrite $R0 "r2 = subprocess.run(cmd2, capture_output=True, text=True)$\r$\n"
  FileWrite $R0 "log.write('=== pip attempt 2 (PyPI fallback) ===\n' + r2.stdout + r2.stderr + f'exit: {r2.returncode}\n\n')$\r$\n"
  FileWrite $R0 "log.close()$\r$\n"
  FileWrite $R0 "sys.exit(r2.returncode)$\r$\n"
  FileClose $R0

  FileOpen $R0 "C:\Users\Public\vpnlog.txt" a
  FileWrite $R0 "Python exe: $PythonExe$\r$\n"
  FileClose $R0

  nsExec::ExecToStack '"$PythonExe" "C:\Users\Public\runpip.py"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Failed to install Python packages (exit $0).$\r$\n$\r$\nCheck: C:\Users\Public\vpnlog.txt$\r$\n$\r$\nSend that file to your administrator."
    Abort
  ${EndIf}
  DetailPrint "Python packages installed."

  ; === Step 3: OpenVPN Connect ===
  DetailPrint "=== Step 3/4: OpenVPN Connect ==="
  ${If} ${FileExists} "${OVPN_DIR}\OpenVPNConnect.exe"
    DetailPrint "OpenVPN Connect already installed."
    FileOpen $R0 "C:\Users\Public\vpnlog.txt" a
    FileWrite $R0 "OpenVPN Connect: already present at ${OVPN_DIR}$\r$\n"
    FileClose $R0
  ${Else}
    DetailPrint "Installing OpenVPN Connect via winget (this may take a minute)…"
    FileOpen $R0 "C:\Users\Public\vpnlog.txt" a
    FileWrite $R0 "OpenVPN Connect: not found, running winget...$\r$\n"
    FileClose $R0
    nsExec::ExecToLog 'winget install --id OpenVPNTechnologies.OpenVPNConnect --source winget --silent --accept-package-agreements --accept-source-agreements --override "/qn"'
    Pop $0
    FileOpen $R0 "C:\Users\Public\vpnlog.txt" a
    FileWrite $R0 "winget OpenVPN Connect exit code: $0$\r$\n"
    FileClose $R0
    ${If} $0 == 0
    ${OrIf} $0 == 3010
    ${OrIf} $0 == 2316632084
      DetailPrint "OpenVPN Connect installed."
    ${Else}
      DetailPrint "OpenVPN Connect could not be installed automatically (exit $0)."
      MessageBox MB_ICONEXCLAMATION "OpenVPN Connect could not be installed automatically.$\r$\n$\r$\nYour browser will now open the download page.$\r$\nInstall OpenVPN Connect, then click OK.$\r$\n$\r$\n(You can skip this for now — but you will need it to connect to the VPN.)"
      ExecShell "open" "https://openvpn.net/client/"
    ${EndIf}
  ${EndIf}

  ; === Step 4: libykcs11.dll (opportunistic — only if Yubico PIV Tool is already present) ===
  DetailPrint "=== Step 4/4: YubiKey PKCS#11 library ==="
  ${If} ${FileExists} "${YUBIPIV_BIN}\libykcs11.dll"
    ${If} ${FileExists} "${OVPN_DIR}\OpenVPNConnect.exe"
      CreateDirectory "${OVPN_DIR}\pkcs11_modules"
      CopyFiles /SILENT "${YUBIPIV_BIN}\libykcs11.dll" "${OVPN_DIR}\pkcs11_modules\libykcs11.dll"
      DetailPrint "Copied libykcs11.dll to OpenVPN Connect."
    ${EndIf}
  ${Else}
    DetailPrint "Yubico PIV Tool not found — skipping libykcs11.dll (not required for registration)."
  ${EndIf}

  ; === Allow port 7890 through Windows Firewall (loopback only) ===
  ; Without this, Windows Defender may block the browser's fetch to the helper.
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="VPN Web Helper (localhost)" \
    dir=in action=allow protocol=tcp localport=7890 \
    remoteip=127.0.0.1 profile=any'

  ; === Register vpnreg: URI scheme ===
  Call RegisterUriScheme

  ; === Uninstall entry ===
  WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayName"    "${APP_NAME}"
  WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayVersion"  "${APP_VER}"
  WriteRegStr HKLM "${REG_UNINSTALL}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${REG_UNINSTALL}" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "${REG_UNINSTALL}" "NoModify" 1
  WriteRegDWORD HKLM "${REG_UNINSTALL}" "NoRepair"  1
  WriteUninstaller "$INSTDIR\uninstall.exe"

  DetailPrint ""
  DetailPrint "VPN Setup installed successfully."

  ; === Add helper to Windows startup (auto-start on every login) ===
  ; Written to HKCU so it runs as the logged-in user, not SYSTEM.
  ${If} $PythonwExe != ""
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "VPNWebHelper" \
      '"$PythonwExe" "${HELPER_DIR}\vpnweb-helper.py"'
    DetailPrint "VPN helper added to startup."
  ${EndIf}

  ; === Kill any running helper before starting the new one ===
  DetailPrint "Stopping any running VPN helper…"
  nsExec::ExecToStack 'taskkill /F /IM pythonw.exe'
  Pop $0
  Pop $1  ; discard output — "not found" is expected and harmless
  Sleep 1000

  ; === Pre-start the helper right now (don't wait for reboot) ===
  ${If} $PythonwExe != ""
    DetailPrint "Starting VPN helper…"
    Exec '"$PythonwExe" "${HELPER_DIR}\vpnweb-helper.py"'
  ${EndIf}

  MessageBox MB_ICONINFORMATION "Installation complete!$\r$\n$\r$\nNow open your registration link from the email.$\r$\nInsert your YubiKey when prompted."

SectionEnd

; ---- Find Python (never uses PATH — avoids Windows Store stub) ----
; IMPORTANT: NSIS is a 32-bit process; without SetRegView 64 it reads the
; WOW6432Node hive, where Python 3.12 x64 is NOT registered.
Function FindPython
  StrCpy $PythonExe ""
  StrCpy $PythonwExe ""

  SetRegView 64  ; read 64-bit registry hive

  ; System-wide install via HKLM (InstallAllUsers=1)
  ReadRegStr $0 HKLM "${PYTHON_REG}\3.12\InstallPath" ""
  ${If} $0 != ""
    ${If} ${FileExists} "$0\python.exe"
      StrCpy $PythonExe  "$0\python.exe"
      StrCpy $PythonwExe "$0\pythonw.exe"
      SetRegView 32
      Return
    ${EndIf}
  ${EndIf}

  ; Per-user install (HKCU)
  ReadRegStr $0 HKCU "${PYTHON_REG}\3.12\InstallPath" ""
  ${If} $0 != ""
    ${If} ${FileExists} "$0\python.exe"
      StrCpy $PythonExe  "$0\python.exe"
      StrCpy $PythonwExe "$0\pythonw.exe"
      SetRegView 32
      Return
    ${EndIf}
  ${EndIf}

  SetRegView 32  ; restore before filesystem checks

  ; Common filesystem paths for system-wide install
  ${If} ${FileExists} "$PROGRAMFILES64\Python312\python.exe"
    StrCpy $PythonExe  "$PROGRAMFILES64\Python312\python.exe"
    StrCpy $PythonwExe "$PROGRAMFILES64\Python312\pythonw.exe"
    Return
  ${EndIf}
  ${If} ${FileExists} "$PROGRAMFILES\Python312\python.exe"
    StrCpy $PythonExe  "$PROGRAMFILES\Python312\python.exe"
    StrCpy $PythonwExe "$PROGRAMFILES\Python312\pythonw.exe"
    Return
  ${EndIf}
  ${If} ${FileExists} "$LOCALAPPDATA\Programs\Python\Python312\python.exe"
    StrCpy $PythonExe  "$LOCALAPPDATA\Programs\Python\Python312\python.exe"
    StrCpy $PythonwExe "$LOCALAPPDATA\Programs\Python\Python312\pythonw.exe"
    Return
  ${EndIf}
  ${If} ${FileExists} "$PROGRAMFILES64\Python\Python312\python.exe"
    StrCpy $PythonExe  "$PROGRAMFILES64\Python\Python312\python.exe"
    StrCpy $PythonwExe "$PROGRAMFILES64\Python\Python312\pythonw.exe"
    Return
  ${EndIf}
FunctionEnd

; ---- Download via PowerShell (supports TLS 1.2/1.3) ----
; In: $R1 = URL, $R2 = destination path. Out: $0 = exit code (0 = success).
Function Download
  DetailPrint "Downloading: $R1"
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri ''$R1'' -OutFile ''$R2'' -UseBasicParsing"'
  Pop $0
FunctionEnd

; ---- vpnreg: URI scheme ----
Function RegisterUriScheme
  WriteRegStr HKLM "Software\Classes\vpnreg"                    ""            "URL:VPN Registration Helper"
  WriteRegStr HKLM "Software\Classes\vpnreg"                    "URL Protocol" ""
  WriteRegStr HKLM "Software\Classes\vpnreg\DefaultIcon"        ""            "$PythonwExe,0"
  WriteRegStr HKLM "Software\Classes\vpnreg\shell\open\command" ""            '"$PythonwExe" "${HELPER_DIR}\vpnweb-helper.py" "%1"'
  DetailPrint "Registered vpnreg: URI scheme."
FunctionEnd

; ---- Uninstall ----
Section "Uninstall"
  ; Kill running helper before deleting files (Windows locks files of running processes)
  DetailPrint "Stopping VPN helper…"
  nsExec::ExecToStack 'taskkill /F /IM pythonw.exe'
  Pop $0
  Pop $1  ; discard — "not found" is expected
  Sleep 1000

  ; Remove helper files
  Delete "$INSTDIR\vpnweb-helper.py"
  RMDir  /r "$INSTDIR\wheels"
  Delete "$INSTDIR\uninstall.exe"
  RMDir  "$INSTDIR"

  ; Remove temp install files
  Delete "C:\Users\Public\vpnlog.txt"
  Delete "C:\Users\Public\runpip.py"

  ; Remove registry entries
  DeleteRegKey   HKLM "Software\Classes\vpnreg"
  DeleteRegKey   HKLM "${REG_UNINSTALL}"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "VPNWebHelper"

  ; Remove firewall rule
  nsExec::ExecToStack 'netsh advfirewall firewall delete rule name="VPN Web Helper (localhost)"'
  Pop $0
  Pop $1

  MessageBox MB_ICONINFORMATION "VPN Setup uninstalled.$\r$\n$\r$\nThe following were NOT removed:$\r$\n  - Python$\r$\n  - OpenVPN Connect$\r$\n  - YubiKey contents$\r$\n$\r$\nYou can now re-run VPNSetup.exe to install fresh."
SectionEnd
