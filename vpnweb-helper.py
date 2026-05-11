#!/usr/bin/env python3
"""
vpnweb-helper — local HTTP bridge between the registration browser tab and YubiKey PIV.
Listens on 127.0.0.1:7890. Started by the browser via vpnreg: URI scheme,
exits automatically ~20 seconds after the browser tab is closed (heartbeat).
"""
import json, os, signal, socket, sys, threading, time

try:
    from flask import Flask, request, jsonify
except ImportError:
    sys.exit("Missing: pip install flask")

try:
    import requests as _http
except ImportError:
    sys.exit("Missing: pip install requests")

try:
    from yubikit.piv import (
        PivSession, SLOT, PIN_POLICY, TOUCH_POLICY,
        ManagementKeyAlgorithm, InvalidPinError,
    )
    from yubikit.core.smartcard import SmartCardConnection
    from ykman.device import list_all_devices
    from cryptography.hazmat.primitives.serialization import pkcs12 as _pkcs12
except ImportError:
    sys.exit("Missing: pip install yubikey-manager")

PORT = 7890

# Single-instance guard — exit silently if already running
_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
_probe.settimeout(0.3)
try:
    _probe.connect(("127.0.0.1", PORT))
    _probe.close()
    sys.exit(0)
except (ConnectionRefusedError, OSError):
    _probe.close()

# PIV defaults (factory YubiKey)
_MGMT_KEY   = bytes.fromhex("010203040506070801020304050607080102030405060708")
_DEFAULT_PIN = "123456"
_DEFAULT_PUK = "12345678"

app = Flask(__name__)

# CORS — open; security comes from token validation on the vpnweb server
@app.after_request
def _cors(r):
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return r

@app.route("/", defaults={"p": ""}, methods=["OPTIONS"])
@app.route("/<path:p>", methods=["OPTIONS"])
def _preflight(p):
    return "", 204

# --- Heartbeat (kills process ~20s after browser tab closes) ---
_last_beat = time.time()

def _watchdog():
    while True:
        time.sleep(5)
        if time.time() - _last_beat > 20:
            os.kill(os.getpid(), signal.SIGTERM)

threading.Thread(target=_watchdog, daemon=True).start()

@app.get("/heartbeat")
def heartbeat():
    global _last_beat
    _last_beat = time.time()
    return jsonify({"ok": True})

# --- Status ---
@app.get("/status")
def status():
    try:
        devices = list(list_all_devices())
        if not devices:
            return jsonify({"ok": True, "yubikey": False})
        _, info = devices[0]
        return jsonify({"ok": True, "yubikey": True, "serial": info.serial})
    except Exception as e:
        return jsonify({"ok": True, "yubikey": False, "error": str(e)})

# --- Setup: full YubiKey programming ---
@app.post("/setup")
def setup():
    data       = request.get_json(silent=True) or {}
    server_url = data.get("server_url", "").rstrip("/")
    token      = data.get("token", "")
    new_pin    = str(data.get("new_pin", ""))

    if not server_url or not token or not new_pin:
        return jsonify({"ok": False, "error": "Missing server_url, token or new_pin"}), 400
    if not new_pin.isdigit() or not (6 <= len(new_pin) <= 8):
        return jsonify({"ok": False, "error": "PIN must be 6–8 digits"}), 400

    # 1. Fetch .p12 from vpnweb server
    try:
        r = _http.get(f"{server_url}/api/register/{token}/p12-raw", timeout=15)
        if not r.ok:
            detail = r.json().get("detail", r.text) if r.headers.get("content-type","").startswith("application/json") else r.text
            return jsonify({"ok": False, "error": f"Could not fetch certificate: {detail}"}), 400
        p12_bytes = r.content
    except _http.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": "Cannot reach the VPN server — check your network connection"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": f"Server error: {e}"}), 500

    # 2. Fetch system PUK
    new_puk = _DEFAULT_PUK
    try:
        r = _http.get(f"{server_url}/api/register/{token}/puk", timeout=10)
        if r.ok:
            new_puk = r.json().get("puk") or _DEFAULT_PUK
    except Exception:
        pass

    # 3. Parse .p12
    try:
        private_key, certificate, _ = _pkcs12.load_key_and_certificates(p12_bytes, None)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid certificate file: {e}"}), 400

    # 4. YubiKey operations
    try:
        devices = list(list_all_devices())
    except Exception as e:
        return jsonify({"ok": False, "error": f"Cannot access smart card reader: {e}"}), 500

    if not devices:
        return jsonify({"ok": False, "error": "No YubiKey detected — insert it and try again"}), 400

    device, info = devices[0]
    try:
        with device.open_connection(SmartCardConnection) as conn:
            piv = PivSession(conn)

            try:
                piv.authenticate(ManagementKeyAlgorithm.TDES, _MGMT_KEY)
            except Exception:
                return jsonify({"ok": False,
                    "error": "Management key authentication failed. "
                             "This YubiKey may already be configured — contact your administrator."}), 400

            # Import private key and certificate into PIV slot 9A
            piv.put_key(SLOT.AUTHENTICATION, private_key, PIN_POLICY.ALWAYS, TOUCH_POLICY.NEVER)
            piv.put_certificate(SLOT.AUTHENTICATION, certificate)

            try:
                piv.change_pin(_DEFAULT_PIN, new_pin)
            except InvalidPinError:
                return jsonify({"ok": False,
                    "error": "Could not set PIN — YubiKey may already have a non-default PIN."}), 400

            try:
                piv.change_puk(_DEFAULT_PUK, new_puk)
            except Exception as e:
                return jsonify({"ok": False, "error": f"Could not set PUK: {e}"}), 400

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    serial = info.serial

    # 5. Notify server (mark token used, trigger PIN email)
    try:
        _http.post(f"{server_url}/api/register/{token}/complete",
                   json={"pin": new_pin, "serial": str(serial)}, timeout=10)
    except Exception:
        pass  # Best-effort; don't fail registration over a notification error

    # 6. Download .ovpn and import into OpenVPN Connect via file association
    ovpn_imported = False
    try:
        ovpn_r = _http.get(f"{server_url}/api/register/{token}/ovpn/connect", timeout=15)
        if ovpn_r.ok:
            import tempfile, os as _os
            suffix = f"_{serial}.ovpn"
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
                f.write(ovpn_r.content)
                ovpn_path = f.name
            _os.startfile(ovpn_path)  # Windows: opens with OpenVPN Connect via .ovpn association
            ovpn_imported = True
    except Exception:
        pass  # Non-fatal — user can download manually from the registration page

    pkcs11_id = (
        f"pkcs11:model=YubiKey%20YK5;"
        f"token=YubiKey%20PIV%20%23{serial};"
        f"manufacturer=Yubico%20%28www.yubico.com%29;"
        f"serial={serial};id=%01"
    )
    return jsonify({"ok": True, "serial": serial, "pkcs11_id": pkcs11_id,
                    "ovpn_imported": ovpn_imported})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
