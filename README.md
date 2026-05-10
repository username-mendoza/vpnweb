# vpnweb

Web management UI for [SoftEther VPN](https://www.softethervpn.org/), built with FastAPI and vanilla JS. Single-page app served over HTTP, designed to run on the same host as the SoftEther server.

## Features

- **Hub management** — create, configure, and monitor virtual hubs
- **User management** — create/edit users with password or certificate authentication
- **YubiKey / PKCS#11 cert auth** — generate RSA certificates, download `.p12` for YubiKey import, generate `.ovpn` configs with `pkcs11-providers`
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
- `vpncmd` on PATH or at `/opt/vpnserver/vpncmd` (used as fallback for NAT-T relay connections)

```
pip install fastapi uvicorn[standard] httpx cryptography pydantic
```

## Running

```bash
uvicorn main:app --host 0.0.0.0 --port 8080
```

Or as a systemd service — see the example unit file below.

### systemd unit

```ini
[Unit]
Description=vpnweb
After=network.target

[Service]
WorkingDirectory=/opt/vpnweb
ExecStart=uvicorn main:app --host 0.0.0.0 --port 8080
Restart=always

[Install]
WantedBy=multi-user.target
```

## Configuration

Edit the top of `main.py`:

```python
SOFTETHER_HOST = "127.0.0.1"   # SoftEther JSON-RPC host
SOFTETHER_PORT = 5555           # SoftEther JSON-RPC port
VPNCMD        = "/opt/vpnserver/vpncmd"  # vpncmd path (NAT-T fallback)
```

Connection profiles (server addresses) are stored in `profiles.json` and managed through the UI — this file is excluded from the repo.

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
4. Connect with OpenVPN community client (not OpenVPN Connect — it lacks PKCS#11 support)

> The YK1 patch for SoftEther is required on the server side. See [SoftEtherVPN-YK1](https://github.com/username-mendoza/SoftEtherVPN-YK1).

## Notes

- Requires server-admin credentials to log in (hub-admin not supported)
- Sessions are in-memory — server restart requires re-login
- HTTPS is not handled by this app — put it behind a reverse proxy (nginx, Caddy) if exposing beyond localhost
