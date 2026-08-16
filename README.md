# vpnweb

Web management UI for [SoftEther VPN](https://www.softethervpn.org/), built with FastAPI and vanilla JS. Single-page app served over HTTP, designed to run on the same host as the SoftEther server.

## Features

- **Hub management** — create, configure, and monitor virtual hubs
- **User management** — create/edit users with password or certificate authentication, built-in password generator (length, numbers, symbols)
- **YubiKey / PKCS#11 cert auth** — generate RSA certificates, download `.p12` for YubiKey import, generate `.ovpn` configs with `pkcs11-providers`
- **Self-service registration** — email an invite link; the user runs a Windows installer, inserts their YubiKey, and gets an OpenVPN profile auto-imported with no manual cert handling (see below)
- **Session monitoring** — view active sessions, disconnect users
- **Group management**
- **NAT / DHCP / SecureNAT** configuration
- **OpenVPN** enable/disable and port configuration
- **VPN Azure** (NAT-T relay) toggle
- **Cascade connections** and **Layer 3 switching**
- **Local bridge** management
- **Listener** (port) management
- Multiple connection profiles — direct TCP or via VPN Azure relay

## Requirements

- Python 3.10+
- SoftEther VPN server with JSON-RPC enabled (port 5555 by default)
- `vpncmd` at `/opt/vpnserver/vpncmd` (used as fallback for NAT-T relay connections)

## Quick install

```bash
sudo bash <(curl -sSL https://raw.githubusercontent.com/username-mendoza/vpnweb/main/install.sh)
```

The script clones the repo, installs Python dependencies, and optionally installs and starts a systemd service. It asks before doing anything non-trivial.

---

## Manual installation

### 1. Clone and install dependencies

```bash
git clone https://github.com/username-mendoza/vpnweb.git /opt/vpnweb
cd /opt/vpnweb
pip install fastapi "uvicorn[standard]" httpx cryptography pydantic
```

### 2. Configure

Edit the top of `main.py` to match your SoftEther server:

```python
SOFTETHER_HOST = "127.0.0.1"   # SoftEther JSON-RPC host
SOFTETHER_PORT = 5555           # SoftEther JSON-RPC port
VPNCMD        = "/opt/vpnserver/vpncmd"  # path to vpncmd binary
```

Copy the profiles example — connection profiles are then managed through the UI:

```bash
cp profiles.example.json profiles.json
```

### 3. Run as a systemd service

```bash
# Create a dedicated user (optional but recommended)
useradd -r -s /sbin/nologin vpnweb

# Install the service file
cp vpnweb.service /etc/systemd/system/
# Edit WorkingDirectory and User in the service file if needed
systemctl daemon-reload
systemctl enable --now vpnweb
```

The service file is included in the repo as `vpnweb.service`.

### 4. Open the UI

Navigate to `http://<server>:8080` and log in with your SoftEther server-admin password.

## Configuration

Connection profiles (server addresses and ports) are stored in `profiles.json` and managed through the UI — excluded from the repo, use `profiles.example.json` as a starting point.

Generated `.p12` certificates are stored in `generated_certs/` (also excluded from the repo).

## YubiKey cert auth workflow

1. **Create user** → set auth type to Certificate → Generate Certificate → fill in subject fields → click Create
2. Open the user → **Download .p12** → import into YubiKey:
   ```
   ykman piv certificates import 9a username.p12
   ```
3. **Download .ovpn** → paste the `pkcs11-id` from:
   ```
   openvpn --show-pkcs11-ids /path/to/libykcs11.so
   ```
4. Connect with OpenVPN community client or OpenVPN Connect v3.3+

> The YK1 patch for SoftEther is required on the server side. See [SoftEtherVPN-YK1](https://github.com/username-mendoza/SoftEtherVPN-YK1).

## Self-service registration (Windows installer)

Instead of generating and handing off a `.p12` manually, an admin can send the
end user a one-time registration link and let the installer do the rest:

1. **Create user** → set auth type to Certificate → check **Send registration
   link by email** → fill in the subject fields and email → **Create**.
   Requires SMTP to be configured (`config.json` → `smtp`, or via Settings in
   the UI). The link expires after `registration.token_expiry_hours` (default
   72h, configurable in `config.json`).
2. The user opens the link and downloads/runs `VPNSetup.exe` — an NSIS
   installer built from `setup.nsi`. It installs Python + bundled wheels (from
   `wheels/`, with a PyPI fallback), installs OpenVPN Connect silently via
   `winget`, opens a Windows Firewall rule for `127.0.0.1:7890`, and starts
   `vpnweb-helper.py` (registered to auto-start via the `HKCU\...\Run` key).
3. The registration page (`static/register.html`) polls the local helper on
   `127.0.0.1:7890` to detect it's running, then talks to it to drive the
   YubiKey: import the certificate onto PIV slot 9a, set a PIN, and read back
   the PUK.
4. The `.ovpn` profile is generated server-side and handed to the OS via
   `os.startfile()` for automatic import into OpenVPN Connect — no manual
   file handling by the end user.

`vpnweb-helper.py` only listens on `127.0.0.1` and exits automatically ~120s
after the browser tab closes (heartbeat watchdog), so it doesn't linger as a
background service between registrations.

## Notes

- Requires server-admin credentials to log in (hub-admin not supported)
- Sessions are in-memory — server restart requires re-login
- HTTPS is not handled by this app — put it behind a reverse proxy (nginx, Caddy) if exposing beyond localhost
- Admin login is rate-limited (10 attempts/IP/minute); session cookies are set `secure=True`
- `/api/debug/*` endpoints are restricted to localhost regardless of auth
- Registration tokens, generated certs, YubiKey PUK records, and admin credentials live in `registration_tokens.json`, `certs/`, `yubikey_registry.json`, and `config.json` — none of these are tracked in git (see `.gitignore`); back them up separately
