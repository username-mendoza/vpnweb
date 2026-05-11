; VPN Setup Package — NSIS Installer
; Installs: Python 3, yubikey-manager + dependencies, Yubico PIV Tool,
;           OpenVPN Connect, vpnweb-helper.py, vpnreg: URI scheme.
; Copies libykcs11.dll to OpenVPN Connect's pkcs11_modules dir.

Unicode true
SetCompressor /SOLID lzma

!define APP_NAME    "VPN Setup"
!define APP_VER     "1.0"
!define HELPER_DIR  "$LOCALAPPDATA\vpnweb"
!define REG_UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNSetup"

; Download URLs (update to current stable versions as needed)
!define URL_PYTHON   "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
!define URL_YUBIPIV  "https://developers.yubico.com/yubico-piv-tool/Releases/yubico-piv-tool-2.5.2-win64.msi"
!define URL_OVPN     "https://openconnect.net/downloads/openvpn-connect/openvpn-connect-3-latest.msi"

!define PYTHON_REG   "Software\Python\PythonCore"
!define YUBIPIV_REG  "Software\Yubico\Yubico PIV Tool"
!define OVPN_DIR     "$PROGRAMFILES64\OpenVPN Connect"
!define YUBIPIV_BIN  "$PROGRAMFILES64\Yubico\Yubico PIV Tool\bin"

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
  SetOutPath "${HELPER_DIR}"

  ; --- vpnweb-helper.py ---
  File "vpnweb-helper.py"

  ; --- Locate or install Python ---
  Call FindPython
  ${If} $PythonExe == ""
    DetailPrint "Python not found — downloading installer…"
    Call DownloadAndInstallPython
    Call FindPython
    ${If} $PythonExe == ""
      MessageBox MB_ICONSTOP "Python installation failed. Please install Python 3.x manually from python.org and re-run this installer."
      Abort
    ${EndIf}
  ${Else}
    DetailPrint "Python found: $PythonExe"
  ${EndIf}

  ; --- Verify Python works ---
  nsExec::ExecToStack '"$PythonExe" --version'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Python not responding at:$\r$\n$PythonExe$\r$\n$\r$\nPlease install Python 3.x from python.org and re-run this installer."
    Abort
  ${EndIf}
  DetailPrint "Python OK: $1 ($PythonExe)"

  ; --- Install Python packages ---
  DetailPrint "Ensuring pip is available…"
  nsExec::ExecToLog '"$PythonExe" -m ensurepip --upgrade'
  Pop $0

  DetailPrint "Upgrading pip…"
  nsExec::ExecToLog '"$PythonExe" -m pip install --upgrade --quiet --prefer-binary pip'
  Pop $0

  DetailPrint "Installing required Python packages…"
  nsExec::ExecToStack '"$PythonExe" -m pip install --prefer-binary flask yubikey-manager requests cryptography'
  Pop $0
  Pop $1
  ${If} $0 != 0
    ; Retry with --trusted-host to work around SSL/proxy issues
    DetailPrint "Retrying with relaxed SSL settings…"
    nsExec::ExecToStack '"$PythonExe" -m pip install --prefer-binary --trusted-host pypi.org --trusted-host files.pythonhosted.org flask yubikey-manager requests cryptography'
    Pop $0
    Pop $1
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "Failed to install Python packages (exit $0).$\r$\nPython: $PythonExe$\r$\n$\r$\nError output:$\r$\n$1$\r$\n$\r$\nTo finish manually, open Command Prompt and run:$\r$\n  $\"$PythonExe$\" -m pip install flask yubikey-manager requests cryptography$\r$\n$\r$\nThen re-open your registration link."
      ; Non-fatal: rest of installer still runs so vpnreg: URI is registered
    ${EndIf}
  ${EndIf}

  ; --- Yubico PIV Tool ---
  ReadRegStr $0 HKLM "${YUBIPIV_REG}" "InstallDir"
  ${If} $0 == ""
    DetailPrint "Yubico PIV Tool not found — downloading…"
    Call DownloadAndInstallYubiPIV
  ${Else}
    DetailPrint "Yubico PIV Tool found: $0"
  ${EndIf}

  ; --- OpenVPN Connect ---
  ${If} ${FileExists} "${OVPN_DIR}\OpenVPNConnect.exe"
    DetailPrint "OpenVPN Connect already installed."
  ${Else}
    DetailPrint "OpenVPN Connect not found — downloading…"
    Call DownloadAndInstallOVPN
  ${EndIf}

  ; --- Copy libykcs11.dll to OpenVPN Connect pkcs11_modules ---
  ${If} ${FileExists} "${YUBIPIV_BIN}\libykcs11.dll"
    CreateDirectory "${OVPN_DIR}\pkcs11_modules"
    CopyFiles /SILENT "${YUBIPIV_BIN}\libykcs11.dll" "${OVPN_DIR}\pkcs11_modules\libykcs11.dll"
    DetailPrint "Copied libykcs11.dll to OpenVPN Connect."
  ${Else}
    DetailPrint "WARNING: libykcs11.dll not found — YubiKey detection in OpenVPN Connect may not work."
    DetailPrint "         Expected location: ${YUBIPIV_BIN}\libykcs11.dll"
  ${EndIf}

  ; --- Register vpnreg: URI scheme ---
  Call RegisterUriScheme

  ; --- Uninstall entry ---
  WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayName"    "${APP_NAME}"
  WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayVersion"  "${APP_VER}"
  WriteRegStr HKLM "${REG_UNINSTALL}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${REG_UNINSTALL}" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "${REG_UNINSTALL}" "NoModify" 1
  WriteRegDWORD HKLM "${REG_UNINSTALL}" "NoRepair"  1
  WriteUninstaller "$INSTDIR\uninstall.exe"

  DetailPrint ""
  DetailPrint "VPN Setup Package installed successfully."
  DetailPrint "Return to your registration email and click the registration link to continue."

  ; Pre-start the helper so it is ready when user clicks the registration link
  Call FindPython
  ${If} $PythonwExe != ""
    Exec '"$PythonwExe" "${HELPER_DIR}\vpnweb-helper.py"'
  ${EndIf}

  MessageBox MB_ICONINFORMATION "Installation complete!$\r$\n$\r$\nInsert your YubiKey, then open the registration link from your email.$\r$\nClick 'Program my YubiKey' — the rest is automatic."
SectionEnd

; ---- Find Python ----
Function FindPython
  StrCpy $PythonExe ""
  StrCpy $PythonwExe ""

  ; 1. System-wide install (InstallAllUsers=1) — most reliable from elevated context
  ReadRegStr $0 HKLM "${PYTHON_REG}\3.12\InstallPath" ""
  ${If} $0 != ""
    ${If} ${FileExists} "$0\python.exe"
      StrCpy $PythonExe  "$0\python.exe"
      StrCpy $PythonwExe "$0\pythonw.exe"
      Return
    ${EndIf}
  ${EndIf}

  ; 2. Common filesystem paths for system-wide install
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

  ; 3. Per-user install fallback (HKCU)
  ReadRegStr $0 HKCU "${PYTHON_REG}\3.12\InstallPath" ""
  ${If} $0 != ""
    ${If} ${FileExists} "$0\python.exe"
      StrCpy $PythonExe  "$0\python.exe"
      StrCpy $PythonwExe "$0\pythonw.exe"
      Return
    ${EndIf}
  ${EndIf}
  ${If} ${FileExists} "$LOCALAPPDATA\Programs\Python\Python312\python.exe"
    StrCpy $PythonExe  "$LOCALAPPDATA\Programs\Python\Python312\python.exe"
    StrCpy $PythonwExe "$LOCALAPPDATA\Programs\Python\Python312\pythonw.exe"
    Return
  ${EndIf}

  ; 4. Last resort: PATH lookup (strips trailing \r\n from where.exe output)
  nsExec::ExecToStack 'cmd /c where python'
  Pop $0
  Pop $1
  ${If} $0 == 0
    StrCpy $PythonExe $1 -2
    ${GetParent} $PythonExe $R0
    StrCpy $PythonwExe "$R0\pythonw.exe"
  ${EndIf}
FunctionEnd

; ---- Download helpers ----
Function DownloadAndInstallPython
  InitPluginsDir
  DetailPrint "Downloading Python 3.12…"
  NSISdl::download "${URL_PYTHON}" "$PLUGINSDIR\python-setup.exe"
  Pop $0
  ${If} $0 != "success"
    MessageBox MB_ICONSTOP "Failed to download Python: $0"
    Abort
  ${EndIf}
  DetailPrint "Installing Python 3.12 (system-wide, add to PATH)…"
  ExecWait '"$PLUGINSDIR\python-setup.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_test=0' $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Python installation returned error $0."
    Abort
  ${EndIf}
FunctionEnd

Function DownloadAndInstallYubiPIV
  InitPluginsDir
  DetailPrint "Downloading Yubico PIV Tool…"
  NSISdl::download "${URL_YUBIPIV}" "$PLUGINSDIR\yubipiv-setup.msi"
  Pop $0
  ${If} $0 != "success"
    DetailPrint "WARNING: Could not download Yubico PIV Tool: $0"
    DetailPrint "         libykcs11.dll may not be available."
    Return
  ${EndIf}
  DetailPrint "Installing Yubico PIV Tool…"
  ExecWait 'msiexec /i "$PLUGINSDIR\yubipiv-setup.msi" /quiet /norestart' $0
  ${If} $0 != 0
    DetailPrint "WARNING: Yubico PIV Tool installer returned $0."
  ${EndIf}
FunctionEnd

Function DownloadAndInstallOVPN
  InitPluginsDir
  DetailPrint "Downloading OpenVPN Connect…"
  NSISdl::download "${URL_OVPN}" "$PLUGINSDIR\openvpn-connect.msi"
  Pop $0
  ${If} $0 != "success"
    DetailPrint "WARNING: Could not download OpenVPN Connect: $0"
    Return
  ${EndIf}
  DetailPrint "Installing OpenVPN Connect…"
  ExecWait 'msiexec /i "$PLUGINSDIR\openvpn-connect.msi" /quiet /norestart' $0
  ${If} $0 != 0
    DetailPrint "WARNING: OpenVPN Connect installer returned $0."
  ${EndIf}
FunctionEnd

; ---- vpnreg: URI scheme ----
; vpnreg:// → launches pythonw.exe vpnweb-helper.py (window-less, no console)
Function RegisterUriScheme
  WriteRegStr HKLM "Software\Classes\vpnreg"                       ""                 "URL:VPN Registration Helper"
  WriteRegStr HKLM "Software\Classes\vpnreg"                       "URL Protocol"     ""
  WriteRegStr HKLM "Software\Classes\vpnreg\DefaultIcon"           ""                 "$PythonwExe,0"
  WriteRegStr HKLM "Software\Classes\vpnreg\shell\open\command"    ""                 '"$PythonwExe" "${HELPER_DIR}\vpnweb-helper.py" "%1"'
  DetailPrint "Registered vpnreg: URI scheme."
FunctionEnd

; ---- Uninstall ----
Section "Uninstall"
  Delete "$INSTDIR\vpnweb-helper.py"
  Delete "$INSTDIR\uninstall.exe"
  RMDir  "$INSTDIR"

  DeleteRegKey HKLM "Software\Classes\vpnreg"
  DeleteRegKey HKLM "${REG_UNINSTALL}"

  MessageBox MB_ICONINFORMATION "VPN Setup has been uninstalled.$\r$\nYour YubiKey, Python, and OpenVPN Connect were not affected."
SectionEnd

; ---- String replace macro (needed for pythonw path) ----
!macro _StrRep output input search replace
  Push "${input}"
  Push "${search}"
  Push "${replace}"
  Call StrRep
  Pop "${output}"
!macroend
!define StrRep "!insertmacro _StrRep"

Function StrRep
  Exch $R2  ; replace
  Exch 1
  Exch $R1  ; search
  Exch 2
  Exch $R0  ; input
  Push $R3
  Push $R4
  Push $R5
  Push $R6
  Push $R7
  Push $R8
  Push $R9
  StrCpy $R3 0
  StrLen $R4 $R1
  StrLen $R6 $R0
  StrLen $R7 $R2
  loop:
    StrCpy $R5 $R0 $R4 $R3
    ${If} $R5 == $R1
      StrCpy $R8 $R0 $R3
      StrCpy $R9 $R0 "" $R3
      StrCpy $R9 $R9 "" $R4
      StrCpy $R0 "$R8$R2$R9"
      IntOp $R6 $R6 - $R4
      IntOp $R6 $R6 + $R7
      IntOp $R3 $R3 + $R7
    ${Else}
      IntOp $R3 $R3 + 1
    ${EndIf}
    ${If} $R3 < $R6
      Goto loop
    ${EndIf}
  Pop $R9
  Pop $R8
  Pop $R7
  Pop $R6
  Pop $R5
  Pop $R4
  Pop $R3
  Push $R0
  Push $R1
  Pop $R1
  Pop $R0
  Pop $R2
  Exch $R0
FunctionEnd
