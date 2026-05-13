import asyncio
import json
import base64
import struct
import ssl
import tempfile
import csv as _csv
import io
import re
import time
import pathlib as _pl
from contextvars import ContextVar
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel
from typing import Optional
import secrets
import os
import httpx
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography import x509 as _x509
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization as _serialization
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.serialization import pkcs12 as _pkcs12
from cryptography.hazmat.backends import default_backend as _crypto_backend
import datetime as _dt

import shutil as _shutil
import subprocess as _subprocess

app = FastAPI()
app.add_middleware(GZipMiddleware, minimum_size=1000)

SOFTETHER_HOST = "127.0.0.1"
SOFTETHER_PORT = 5555
VPNCMD = "/opt/vpnserver/vpncmd"

CERTS_DIR = _pl.Path(__file__).parent / "generated_certs"
CERTS_DIR.mkdir(exist_ok=True)

CONFIG_FILE    = _pl.Path(__file__).parent / "config.json"
USER_META_FILE = _pl.Path(__file__).parent / "user_meta.json"
TOKENS_FILE    = _pl.Path(__file__).parent / "registration_tokens.json"
REGISTRY_FILE  = _pl.Path(__file__).parent / "yubikey_registry.json"

_config_lock   = asyncio.Lock()
_meta_lock     = asyncio.Lock()
_tokens_lock   = asyncio.Lock()
_registry_lock = asyncio.Lock()

def _load_json_file(path: _pl.Path, default):
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return default

def _save_json_file(path: _pl.Path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, 0o600)

def _load_config()   -> dict: return _load_json_file(CONFIG_FILE,    {})
def _load_meta()     -> dict: return _load_json_file(USER_META_FILE, {})
def _load_tokens()   -> dict: return _load_json_file(TOKENS_FILE,    {})
def _load_registry() -> dict: return _load_json_file(REGISTRY_FILE,  {})
def _meta_key(hub: str, username: str) -> str: return f"{hub}__{username}"

# Per-request RPC target injected by middleware
_rpc_host: ContextVar[str] = ContextVar("rpc_host", default=SOFTETHER_HOST)
_rpc_port: ContextVar[int] = ContextVar("rpc_port", default=SOFTETHER_PORT)

# Sessions: token → {password, host, port, profile_id, profile_name, last_seen}
sessions_data: dict[str, dict] = {}
SESSION_TIMEOUT = 30 * 60  # 30 minutes of inactivity

# --- Profiles ---

PROFILES_FILE = os.path.join(os.path.dirname(__file__), "profiles.json")

def load_profiles() -> list:
    if not os.path.exists(PROFILES_FILE):
        default = [{"id": secrets.token_hex(8), "name": "Local Server", "host": "127.0.0.1", "port": 5555}]
        save_profiles(default)
        return default
    with open(PROFILES_FILE) as f:
        return json.load(f)

def save_profiles(profiles: list):
    with open(PROFILES_FILE, "w") as f:
        json.dump(profiles, f, indent=2)

class ProfileModel(BaseModel):
    name: str
    host: str
    port: int = 5555
    host2: str = ""
    port2: int = 5555

@app.get("/api/profiles")
async def get_profiles():
    return load_profiles()

@app.post("/api/profiles")
async def create_profile(body: ProfileModel):
    profiles = load_profiles()
    profile = {"id": secrets.token_hex(8), "name": body.name,
               "host": body.host, "port": body.port,
               "host2": body.host2, "port2": body.port2}
    profiles.append(profile)
    save_profiles(profiles)
    return profile

@app.put("/api/profiles/{profile_id}")
async def update_profile(profile_id: str, body: ProfileModel):
    profiles = load_profiles()
    for p in profiles:
        if p["id"] == profile_id:
            p.update({"name": body.name, "host": body.host, "port": body.port,
                      "host2": body.host2, "port2": body.port2})
            save_profiles(profiles)
            return p
    raise HTTPException(status_code=404, detail="Profile not found")

@app.delete("/api/profiles/{profile_id}")
async def delete_profile(profile_id: str):
    profiles = load_profiles()
    remaining = [p for p in profiles if p["id"] != profile_id]
    if not remaining:
        raise HTTPException(status_code=400, detail="Cannot delete the last profile")
    save_profiles(remaining)
    return {"ok": True}


# --- Middleware: inject RPC target from session ---

@app.middleware("http")
async def inject_rpc_target(request: Request, call_next):
    token = request.cookies.get("vpnweb_sid")
    if token and token in sessions_data:
        d = sessions_data[token]
        if time.time() - d.get("last_seen", 0) > SESSION_TIMEOUT:
            sessions_data.pop(token, None)
        else:
            d["last_seen"] = time.time()
            _rpc_host.set(d.get("host", SOFTETHER_HOST))
            _rpc_port.set(d.get("port", SOFTETHER_PORT))
    return await call_next(request)


# ── JSON-RPC via httpx (direct TCP, no subprocess) ───────────────────────────

_http_client: httpx.AsyncClient | None = None

def _http() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(10.0),
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
    return _http_client

async def _rpc_direct(method: str, params: dict, host: str, port: int, password: str) -> dict:
    payload = {"jsonrpc": "2.0", "id": "1", "method": method, "params": params}
    # SoftEther reads the header as raw bytes; encode non-ASCII passwords as UTF-8
    pw_header = password.encode("utf-8").decode("latin-1")
    try:
        r = await _http().post(
            f"https://{host}:{port}/api/",
            json=payload,
            headers={"X-VPNADMIN-HUBNAME": "", "X-VPNADMIN-PASSWORD": pw_header},
        )
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot connect to {host}:{port}")
    except (httpx.TimeoutException, httpx.RemoteProtocolError):
        raise HTTPException(502, f"Connection timed out — cannot reach {host}:{port}")
    if r.status_code == 401:
        raise HTTPException(401, "Invalid password")
    try:
        data = r.json()
    except Exception:
        raise HTTPException(502, "Invalid response from VPN server")
    if "error" in data:
        raise HTTPException(400, data["error"].get("message", "RPC error"))
    return data.get("result", {})


# ── vpncmd (NAT-T capable fallback) ─────────────────────────────────────────

# Relay servers (vpnazure.net etc.) allow only a small number of simultaneous
# vpncmd connections. Cap concurrency to avoid silent partial-output failures.
_vpncmd_sem = asyncio.Semaphore(2)

async def _vc(host: str, port: int, password: str, *cmd_args: str) -> str:
    """Run one vpncmd /CMD command, return stdout."""
    async with _vpncmd_sem:
        proc = await asyncio.create_subprocess_exec(
            VPNCMD, f"{host}:{port}", "/SERVER",
            f"/PASSWORD:{password}", "/CSV", "/CMD", *cmd_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(input=b"\x04"), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            raise HTTPException(502, f"NAT-T connection timed out to {host}:{port}")
    text = stdout.decode(errors="replace")
    if "Access has been denied" in text:
        raise HTTPException(401, "Invalid password")
    return text


async def _vc_in(host: str, port: int, password: str, commands: list[str]) -> str:
    """Run multiple vpncmd commands via /IN:file, return stdout."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(commands) + "\n")
        tmpfile = f.name
    try:
        async with _vpncmd_sem:
            proc = await asyncio.create_subprocess_exec(
                VPNCMD, f"{host}:{port}", "/SERVER",
                f"/PASSWORD:{password}", "/CSV", f"/IN:{tmpfile}",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(input=b"\x04"), timeout=30)
            except asyncio.TimeoutError:
                proc.kill()
                raise HTTPException(502, f"NAT-T connection timed out to {host}:{port}")
    finally:
        os.unlink(tmpfile)
    text = stdout.decode(errors="replace")
    if "Access has been denied" in text:
        raise HTTPException(401, "Invalid password")
    return text


_VC_SKIP = {"item", "password:", "vpncmd command", "access has been denied",
            "connection failed", "error occurred"}

def _csv_rows(text: str) -> list[list[str]]:
    """Parse all valid CSV rows from vpncmd output, skipping banners/prompts."""
    rows = []
    for row in _csv.reader(io.StringIO(text)):
        if not row:
            continue
        first = row[0].strip().lower()
        if any(first.startswith(s) for s in _VC_SKIP):
            continue
        if len(row) >= 2:
            rows.append([c.strip() for c in row])
    return rows


def _vc_kv(text: str, _cmd: str = "") -> dict:
    """Parse 2-column Key,Value output (vpncmd CSV format — no prefix)."""
    d = {}
    rows = _csv_rows(text)
    for row in rows:
        if len(row) == 2:
            d[row[0]] = row[1]
    return d


def _vc_table(text: str, _cmd: str = "") -> list[dict]:
    """Parse multi-column table output. First qualifying row = headers."""
    rows = _csv_rows(text)
    # Find the first row with ≥2 cols that looks like a header (no digit-only fields)
    header_idx = None
    for i, row in enumerate(rows):
        if len(row) >= 2 and not all(c.isdigit() for c in row):
            header_idx = i
            break
    if header_idx is None:
        return []
    headers = rows[header_idx]
    result = []
    for row in rows[header_idx + 1:]:
        if len(row) >= 2:
            result.append(dict(zip(headers, row + [""] * max(0, len(headers) - len(row)))))
    return result


def _n(v) -> int:
    """Extract first integer from a value that may contain commas or units like '28,666 bytes'."""
    m = re.search(r'\d[\d,]*', str(v))
    if not m:
        return 0
    try:
        return int(m.group().replace(",", ""))
    except Exception:
        return 0


def _b(v) -> bool:
    s = str(v).strip().lower()
    return s in ("yes", "true", "online", "enabled", "1", "listening", "running") or s.startswith("enable")


def _pem_to_der(pem: str) -> bytes:
    lines = pem.strip().splitlines()
    b64 = ''.join(l for l in lines if not l.startswith('---'))
    return base64.b64decode(b64)

def _der_to_pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return '-----BEGIN CERTIFICATE-----\n' + '\n'.join(lines) + '\n-----END CERTIFICATE-----'

def _parse_cert_info(der_b64: str) -> dict:
    try:
        der = base64.b64decode(der_b64)
        cert = _x509.load_der_x509_certificate(der, _crypto_backend())

        _OID_LABELS = {
            _x509.oid.NameOID.COMMON_NAME:             "CN",
            _x509.oid.NameOID.ORGANIZATION_NAME:        "O",
            _x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            _x509.oid.NameOID.COUNTRY_NAME:             "C",
            _x509.oid.NameOID.STATE_OR_PROVINCE_NAME:   "ST",
            _x509.oid.NameOID.LOCALITY_NAME:            "L",
            _x509.oid.NameOID.EMAIL_ADDRESS:            "E",
            _x509.oid.NameOID.SERIAL_NUMBER:            "SN",
        }
        def _dn(name):
            return ", ".join(
                f"{_OID_LABELS.get(a.oid, a.oid.dotted_string)}={a.value}"
                for a in name
            ) or "(empty)"
        def _cn(name):
            a = name.get_attributes_for_oid(_x509.oid.NameOID.COMMON_NAME)
            return a[0].value if a else ''
        def _fmt_hex(n):
            h = format(n, 'X')
            return ':'.join(h[i:i+2] for i in range(0, len(h), 2))

        try:
            vf = cert.not_valid_before_utc
            vt = cert.not_valid_after_utc
        except AttributeError:
            vf = cert.not_valid_before
            vt = cert.not_valid_after

        fp256 = cert.fingerprint(_hashes.SHA256()).hex()
        fp1   = cert.fingerprint(_hashes.SHA1()).hex()

        pub = cert.public_key()
        key_alg  = "RSA" if "RSA" in type(pub).__name__.upper() else "EC" if "EC" in type(pub).__name__.upper() else type(pub).__name__
        key_bits = getattr(pub, "key_size", None)

        sig_alg = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "Unknown"

        # Extensions
        _EKU_NAMES = {
            "1.3.6.1.5.5.7.3.1": "Server Auth", "1.3.6.1.5.5.7.3.2": "Client Auth",
            "1.3.6.1.5.5.7.3.3": "Code Signing","1.3.6.1.5.5.7.3.4": "Email Protection",
        }
        ext_lines = []
        for ext in cert.extensions:
            try:
                v = ext.value
                if isinstance(v, _x509.BasicConstraints):
                    ext_lines.append(("Basic Constraints", f"CA: {v.ca}" + (f", pathLen: {v.path_length}" if v.path_length is not None else "")))
                elif isinstance(v, _x509.KeyUsage):
                    bits = [u.replace('_',' ').title() for u in
                            ['digital_signature','content_commitment','key_encipherment',
                             'data_encipherment','key_agreement','key_cert_sign','crl_sign']
                            if _ku_safe(v, u)]
                    if bits: ext_lines.append(("Key Usage", ", ".join(bits)))
                elif isinstance(v, _x509.ExtendedKeyUsage):
                    ekus = [_EKU_NAMES.get(o.dotted_string, o.dotted_string) for o in v]
                    ext_lines.append(("Extended Key Usage", ", ".join(ekus)))
                elif isinstance(v, _x509.SubjectAlternativeName):
                    sans = [str(n) for n in v]
                    if sans: ext_lines.append(("Subject Alt Names", ", ".join(sans)))
                elif isinstance(v, _x509.SubjectKeyIdentifier):
                    ext_lines.append(("Subject Key ID", v.digest.hex().upper()))
                elif isinstance(v, _x509.AuthorityKeyIdentifier):
                    if v.key_identifier:
                        ext_lines.append(("Authority Key ID", v.key_identifier.hex().upper()))
            except Exception:
                pass

        def _attr(name, oid):
            a = name.get_attributes_for_oid(oid)
            return a[0].value if a else ""
        _oid = _x509.oid.NameOID
        return {
            "cn":           _cn(cert.subject),
            "o":            _attr(cert.subject, _oid.ORGANIZATION_NAME),
            "ou":           _attr(cert.subject, _oid.ORGANIZATIONAL_UNIT_NAME),
            "c":            _attr(cert.subject, _oid.COUNTRY_NAME),
            "st":           _attr(cert.subject, _oid.STATE_OR_PROVINCE_NAME),
            "l":            _attr(cert.subject, _oid.LOCALITY_NAME),
            "issuer_cn":    _cn(cert.issuer),
            "subject":      _dn(cert.subject),
            "issuer":       _dn(cert.issuer),
            "self_signed":  cert.issuer == cert.subject,
            "version":      cert.version.value + 1,
            "serial":       str(cert.serial_number),
            "serial_hex":   _fmt_hex(cert.serial_number),
            "valid_from":   vf.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "valid_to":     vt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "key_algorithm": key_alg,
            "key_bits":     key_bits,
            "sig_algorithm": f"{key_alg}with{sig_alg}",
            "fingerprint":  ':'.join(fp256[i:i+2].upper() for i in range(0, len(fp256), 2)),
            "fingerprint_sha1": ':'.join(fp1[i:i+2].upper() for i in range(0, len(fp1), 2)),
            "extensions":   ext_lines,
        }
    except Exception:
        return {}

def _ku_safe(ku, attr):
    try:
        return bool(getattr(ku, attr, False))
    except ValueError:
        return False


# Column names that ONLY appear in table header rows (never as data values)
_TABLE_HEADERS = frozenset({
    "Virtual Hub Name", "VPN Hub Name",
    "Port Number", "TCP Port",
    "Network Adapter Name", "Network Adapter or Tap Device Name",
    "Layer 3 Switch Name",
    "User Name", "Full Name", "Group Name",
    "Session Name", "Source Host Name", "Transfer Packets", "Transfer Bytes",
    "Setting Name", "Cascade Connection Name", "Destination VPN Server",
    "MAC Address", "IP Address",
})

def _parse_tables(text: str) -> dict[str, list[dict]]:
    """Split combined vpncmd CSV output into named tables by detecting header rows."""
    def _identify(row: list[str]) -> str | None:
        cols = set(row)
        # Most-specific patterns first — longer/unique column names take priority
        if "Network Adapter or Tap Device Name" in cols:
            return "bridges"
        if "Layer 3 Switch Name" in cols:
            return "l3"
        if "MAC Address" in cols:
            return "mac"
        if "IP Address" in cols and "Session Name" in cols:
            return "ip"
        if "Session Name" in cols and len(row) >= 5:
            return "sessions"
        if any(c in ("Setting Name", "Cascade Connection Name") for c in cols):
            return "links"
        if any(c in ("Port Number", "TCP Port") for c in cols):
            return "listeners"
        if "Network Adapter Name" in cols:
            return "eth"
        # GroupList has "Group Name" + "Full Name" but NOT "User Name"
        # UserList has "User Name" + "Group Name" + "Full Name"
        if "Group Name" in cols and "User Name" not in cols and "Username" not in cols:
            return "groups"
        if any(c in ("User Name", "Username") for c in cols):
            return "users"
        # "Virtual Hub Name" last — it also appears in BridgeList header
        if "Virtual Hub Name" in cols or "VPN Hub Name" in cols:
            return "hubs"
        return None

    rows = _csv_rows(text)
    result: dict[str, list[dict]] = {}
    cur_name: str | None = None
    cur_hdr: list[str] | None = None
    cur_rows: list[list[str]] = []

    def _flush():
        if cur_name and cur_hdr:
            result[cur_name] = [
                dict(zip(cur_hdr, r + [""] * max(0, len(cur_hdr) - len(r))))
                for r in cur_rows if len(r) >= 2
            ]

    for row in rows:
        if len(row) < 2:
            continue
        if any(c in _TABLE_HEADERS for c in row):
            name = _identify(row)
            if name:
                _flush()
                cur_name, cur_hdr, cur_rows = name, row, []
                continue
        if cur_hdr:
            cur_rows.append(row)

    _flush()
    return result


async def _bulk_server_vpncmd(host: str, port: int, password: str) -> dict:
    """Fetch all server data in 2 vpncmd sessions instead of ~12."""
    kv_text, table_text = await asyncio.gather(
        _vc_in(host, port, password, [
            "ServerInfo", "ServerStatus", "DynamicDnsGetStatus",
            "VpnAzureGetStatus", "IPsecGet", "OpenVpnGet", "SyslogGet",
        ]),
        _vc_in(host, port, password, [
            "HubList", "ListenerList", "BridgeDeviceList", "BridgeList", "RouterList",
        ]),
    )
    kv = _vc_kv(kv_text)
    tables = _parse_tables(table_text)

    # Build DDNS
    ipv6 = kv.get("Global IPv6 Address", "")
    if "failed" in ipv6.lower() or "error" in ipv6.lower():
        ipv6 = ""
    azure_raw  = kv.get("Connection to VPN Azure Cloud Server is Established", kv.get("Azure Status", ""))
    azure_host = kv.get("Hostname of this VPN Server on VPN Azure Service", "")

    # Build hubs
    hubs = []
    for r in tables.get("hubs", []):
        name = r.get("Virtual Hub Name", r.get("VPN Hub Name", ""))
        if name:
            hubs.append({
                "HubName_str": name, "Online_bool": _b(r.get("Status", "")),
                "HubType_u32": 0, "NumUsers_u32": _n(r.get("Users", 0)),
                "NumGroups_u32": _n(r.get("Groups", 0)), "NumSessions_u32": _n(r.get("Sessions", 0)),
                "NumMacTables_u32": _n(r.get("MAC Tables", 0)), "NumIpTables_u32": _n(r.get("IP Tables", 0)),
                "NumLogin_u32": _n(r.get("Num Logins", 0)), "IsTrafficFilled_bool": False,
                "LastLoginTime_dt": 0, "LastCommTime_dt": 0, "CreatedTime_dt": 0,
            })

    # Build listeners
    listeners = []
    for r in tables.get("listeners", []):
        p = _n(r.get("Port Number", r.get("TCP Port", "0")))
        if p:
            listeners.append({"Ports_u32": p, "Enable_bool": _b(r.get("Status", "Listening"))})

    # Build bridges
    bridges = []
    for r in tables.get("bridges", []):
        bridges.append({
            "HubNameLB_str": r.get("Virtual Hub Name", ""),
            "DeviceName_str": r.get("Network Adapter or Tap Device Name", ""),
            "TapMode_bool": False,
            "Online_bool": _b(r.get("Status", "")),
        })

    # Build ethernet
    eth = [{"DeviceName_str": r.get("Network Adapter Name", "")}
           for r in tables.get("eth", []) if r.get("Network Adapter Name")]

    # Build L3
    l3 = []
    for r in tables.get("l3", []):
        name = r.get("Layer 3 Switch Name", "")
        if name:
            l3.append({
                "Name_str": name, "Running_bool": _b(r.get("Running Status", "Stop")),
                "NumIf_u32": _n(r.get("Interfaces", 0)), "NumTable_u32": _n(r.get("Routing Tables", 0)),
            })

    # Build IPsec
    ipsec = {
        "L2TP_Raw_bool":       _b(kv.get("Raw L2TP Server Function Enabled", "No")),
        "L2TP_IPsec_bool":     _b(kv.get("L2TP over IPsec Server Function Enabled", "No")),
        "EtherIP_IPsec_bool":  _b(kv.get("EtherIP / L2TPv3 over IPsec Server Function Enabled", "No")),
        "IPsec_Secret_str":    kv.get("IPsec Pre-Shared Key String", ""),
        "L2TP_DefaultHub_str": kv.get("Name of Default Virtual Hub", ""),
    }

    # Build OpenVPN
    ovpn = {
        "EnableOpenVPN_bool":  _b(kv.get("OpenVPN Clone Server Enabled", "No")),
        "OpenVPNPortList_str": kv.get("UDP Port List", "1194"),
        "EnableSSTP_bool":     False,
    }

    # Build syslog
    save_type_str = kv.get("Set the Use of syslog Send Function", "Disable")
    s = save_type_str.lower()
    save_type = 3 if ("server" in s and "hub" in s) else 2 if "hub" in s else 1 if "server" in s else 0
    syslog = {
        "SaveType_u32": save_type,
        "Hostname_str": kv.get("Syslog Server Hostname", kv.get("Hostname", "")),
        "Port_u32":     _n(kv.get("Syslog Server Port Number", 514)),
    }

    return {
        "info": {
            "ServerProductName_str":     kv.get("Product Name", "SoftEther VPN"),
            "ServerVersionString_str":   kv.get("Version", ""),
            "ServerBuildInfoString_str": kv.get("Build", ""),
            "ServerHostName_str":        kv.get("Host Name", ""),
            "OsSystemName_str":          kv.get("Type of Operating System", ""),
            "OsProductName_str":         kv.get("Product Name of Operating System", ""),
            "ServerType_u32": 0,
        },
        "status": {
            "NumTcpConnections_u32":          _n(kv.get("Number of Active Sockets", 0)),
            "NumHubTotal_u32":                _n(kv.get("Number of Virtual Hubs", 0)),
            "NumSessionsTotal_u32":           _n(kv.get("Number of Sessions", 0)),
            "NumSessionsLocal_u32":           _n(kv.get("Number of Sessions", 0)),
            "NumHubStandalone_u32":           _n(kv.get("Number of Virtual Hubs", 0)),
            "AssignedClientLicenseCount_u32": _n(kv.get("Using Client Connection Licenses (This Server)", 0)),
            "AssignedBridgeLicenseCount_u32": _n(kv.get("Using Bridge Connection Licenses (This Server)", 0)),
            "NumUsers_u32":                   _n(kv.get("Number of Users", 0)),
            "NumMacTables_u32":               _n(kv.get("Number of MAC Address Tables", 0)),
            "NumIpTables_u32":                _n(kv.get("Number of IP Address Tables", 0)),
            "NumHubStatic_u32": 0, "NumHubDynamic_u32": 0,
        },
        "ddns": {
            "DnsName_str":     kv.get("Assigned Dynamic DNS Hostname (Full)", ""),
            "DnsPrefix_str":   kv.get("Assigned Dynamic DNS Hostname (Hostname)", ""),
            "CurrentIPv4_str": kv.get("Global IPv4 Address", ""),
            "CurrentIPv6_str": ipv6,
            "AzureHostname_str":   azure_host,
            "AzureConnected_bool": _b(azure_raw),
        },
        "hubs":      hubs,
        "listeners": listeners,
        "ipsec":     ipsec,
        "openvpn":   ovpn,
        "syslog":    syslog,
        "bridges":   bridges,
        "ethernet":  eth,
        "l3":        l3,
    }


async def _bulk_hub_vpncmd(host: str, port: int, password: str, hub: str) -> dict:
    """Fetch all hub data in 2 vpncmd sessions instead of ~11."""
    kv_text = await _vc_in(host, port, password, [f"Hub {hub}", "StatusGet"])
    table_text = await _vc_in(host, port, password, [
        f"Hub {hub}", "UserList", "GroupList",
        "SessionList", "CascadeList", "MacTable", "IpTable",
    ])
    kv = _vc_kv(kv_text)
    tables = _parse_tables(table_text)

    status = {
        "HubName_str":      hub,
        "Online_bool":      _b(kv.get("Status", "")),
        "NumUsers_u32":     _n(kv.get("Users", 0)),
        "NumGroups_u32":    _n(kv.get("Groups", 0)),
        "NumSessions_u32":  _n(kv.get("Sessions", 0)),
        "NumMacTables_u32": _n(kv.get("MAC Tables", 0)),
        "NumIpTables_u32":  _n(kv.get("IP Tables", 0)),
        "NumLogin_u32":     _n(kv.get("Number of Logins", 0)),
        "HubType_u32": 0, "MaxSession_u32": 0, "NoEnum_bool": False,
        "IsTrafficFilled_bool": False, "AdminPasswordPlainText_str": "",
        "LastCommTime_dt": 0, "LastLoginTime_dt": 0, "CreatedTime_dt": 0,
    }

    users = []
    for r in tables.get("users", []):
        uname = r.get("User Name", r.get("Username", ""))
        if uname:
            users.append({
                "Name_str": uname, "RealName_utf": r.get("Full Name", ""),
                "Note_utf": r.get("Note", ""), "GroupName_str": r.get("Group Name", r.get("Group", "")),
                "AuthType_u32": 1,
                "NumLogin_u32": _n(r.get("Num Logins", r.get("Number of Logins", 0))),
                "LastLoginTime_dt": 0, "CreatedTime_dt": 0, "UpdatedTime_dt": 0,
            })

    groups = []
    for r in tables.get("groups", []):
        gname = r.get("Group Name", "")
        if gname:
            groups.append({
                "Name_str": gname, "Realname_utf": r.get("Real Name", r.get("Full Name", "")),
                "Note_utf": r.get("Note", ""),
                "NumUsers_u32": _n(r.get("Num Users", r.get("Users", 0))),
                "CreatedTime_dt": 0,
            })

    sessions = []
    for r in tables.get("sessions", []):
        name = r.get("Session Name", "")
        if name:
            sessions.append({
                "Name_str": name,
                "Username_str":       r.get("User Name", ""),
                "ClientIP_ip":        r.get("Source Host Name", ""),
                "ClientHostName_str": r.get("Source Host Name", ""),
                "NumTcp_u32":         _n(r.get("TCP Connections", 0)),
                "PacketSize_u64":     _n(r.get("Transfer Bytes", 0)),
                "PacketNum_u64":      _n(r.get("Transfer Packets", 0)),
                "CreatedTime_dt": 0, "LastCommTime_dt": 0,
                "LinkMode_bool": False, "BridgeMode_bool": False,
                "SecureNATMode_bool": False, "Layer3Mode_bool": False, "IsDormant_bool": False,
            })

    links = []
    for r in tables.get("links", []):
        lname = r.get("Setting Name", r.get("Cascade Connection Name", ""))
        if lname:
            links.append({
                "AccountName_utf": lname,
                "Online_bool":     _b(r.get("Status", "")),
                "ConnectedTime_dt": 0,
                "Hostname_str":    r.get("Destination VPN Server", ""),
                "HubName_str":     r.get("Virtual Hub", r.get("Virtual Hub Name", "")),
            })

    mac = [{"UniqueId_u32": 0, "SessionName_str": r.get("Session Name", ""),
            "MacAddress_bin": r.get("MAC Address", ""), "CreatedTime_dt": 0, "UpdatedTime_dt": 0}
           for r in tables.get("mac", [])]

    ip = [{"UniqueId_u32": 0, "SessionName_str": r.get("Session Name", ""),
           "IpAddress_ip": r.get("IP Address", ""),
           "DhcpAllocated_bool": _b(r.get("DHCP", "")), "CreatedTime_dt": 0, "UpdatedTime_dt": 0}
          for r in tables.get("ip", [])]

    return {
        "status": status, "config": status,
        "users": users, "groups": groups,
        "sessions": sessions, "links": links,
        "mac": mac, "ip": ip,
    }


async def _vpncmd_rpc(method: str, params: dict, host: str, port: int, password: str) -> dict:
    """Translate any JSON-RPC method call to vpncmd and return equivalent result."""
    hub = (params.get("HubName_str") or params.get("RpcHubName_str") or "").strip()

    # ── Connectivity test ────────────────────────────────────────────────────
    if method == "Test":
        await _vc(host, port, password, "About")
        return {}

    # ── Server-level reads ───────────────────────────────────────────────────
    if method == "GetServerInfo":
        kv = _vc_kv(await _vc(host, port, password, "ServerInfo"))
        return {
            "ServerProductName_str":     kv.get("Product Name", "SoftEther VPN"),
            "ServerVersionString_str":   kv.get("Version", ""),
            "ServerBuildInfoString_str": kv.get("Build", ""),
            "ServerHostName_str":        kv.get("Host Name", ""),
            "OsSystemName_str":          kv.get("Type of Operating System", ""),
            "OsProductName_str":         kv.get("Product Name of Operating System", ""),
            "ServerType_u32": 0,
        }

    if method == "GetServerStatus":
        kv = _vc_kv(await _vc(host, port, password, "ServerStatus"))
        return {
            "NumTcpConnections_u32":             _n(kv.get("Number of Active Sockets", 0)),
            "NumHubTotal_u32":                   _n(kv.get("Number of Virtual Hubs", 0)),
            "NumSessionsTotal_u32":              _n(kv.get("Number of Sessions", 0)),
            "NumSessionsLocal_u32":              _n(kv.get("Number of Sessions", 0)),
            "NumHubStandalone_u32":              _n(kv.get("Number of Virtual Hubs", 0)),
            "AssignedClientLicenseCount_u32":    _n(kv.get("Using Client Connection Licenses (This Server)", 0)),
            "AssignedBridgeLicenseCount_u32":    _n(kv.get("Using Bridge Connection Licenses (This Server)", 0)),
            "NumUsers_u32":                      _n(kv.get("Number of Users", 0)),
            "NumMacTables_u32":                  _n(kv.get("Number of MAC Address Tables", 0)),
            "NumIpTables_u32":                   _n(kv.get("Number of IP Address Tables", 0)),
            "TotalMemSize_u64":                  _n(kv.get("Total Logical Memory Size", 0)),
            "UsedMemSize_u64":                   _n(kv.get("Used Logical Memory Size", 0)),
            "FreeMemSize_u64":                   _n(kv.get("Free Logical Memory Size", 0)),
            "NumHubStatic_u32": 0, "NumHubDynamic_u32": 0,
            "CurrentTime_dt": 0, "StartTime_dt": 0,
        }

    if method == "GetDDnsClientStatus":
        kv = _vc_kv(await _vc(host, port, password, "DynamicDnsGetStatus"))
        ipv6 = kv.get("Global IPv6 Address", "")
        if "failed" in ipv6.lower() or "error" in ipv6.lower():
            ipv6 = ""
        return {
            "DnsServerHostname_str": kv.get("DNS Suffix", ""),
            "DnsName_str":           kv.get("Assigned Dynamic DNS Hostname (Full)", kv.get("FQDN", "")),
            "DnsPrefix_str":         kv.get("Assigned Dynamic DNS Hostname (Hostname)", kv.get("Hostname", "")),
            "CurrentIPv4_str":       kv.get("Global IPv4 Address", kv.get("IPv4 Address", "")),
            "CurrentIPv6_str":       ipv6,
        }

    if method == "GetVpnAzureClientStatus":
        try:
            kv = _vc_kv(await _vc(host, port, password, "VpnAzureGetStatus"))
            raw      = kv.get("Connection to VPN Azure Cloud Server is Established", kv.get("Azure Status", ""))
            hostname = kv.get("Hostname of this VPN Server on VPN Azure Service", "")
            return {
                "IsConnected_bool": _b(raw),
                "Hostname_str":     hostname,
            }
        except Exception:
            return {"IsConnected_bool": False, "Hostname_str": ""}

    # ── Hub enumeration & CRUD ───────────────────────────────────────────────
    if method == "EnumHub":
        rows = _vc_table(await _vc(host, port, password, "HubList"))
        hubs = []
        for r in rows:
            name = r.get("Virtual Hub Name", r.get("VPN Hub Name", r.get("Name", "")))
            if not name:
                continue
            hubs.append({
                "HubName_str":       name,
                "Online_bool":       _b(r.get("Status", "")),
                "HubType_u32":       0,
                "NumUsers_u32":      _n(r.get("Users", 0)),
                "NumGroups_u32":     _n(r.get("Groups", 0)),
                "NumSessions_u32":   _n(r.get("Sessions", 0)),
                "NumMacTables_u32":  _n(r.get("MAC Tables", 0)),
                "NumIpTables_u32":   _n(r.get("IP Tables", 0)),
                "NumLogin_u32":      _n(r.get("Num Logins", 0)),
                "LastLoginTime_dt":  0,
                "LastCommTime_dt":   0,
                "CreatedTime_dt":    0,
                "IsTrafficFilled_bool": False,
            })
        return {"HubList": hubs}

    if method in ("GetHubStatus", "GetHub"):
        kv = _vc_kv(await _vc_in(host, port, password, [f"Hub {hub}", "StatusGet"]))
        return {
            "HubName_str":      hub,
            "Online_bool":      _b(kv.get("Status", "")),
            "HubType_u32":      0,
            "NumUsers_u32":     _n(kv.get("Users", 0)),
            "NumGroups_u32":    _n(kv.get("Groups", 0)),
            "NumSessions_u32":  _n(kv.get("Sessions", 0)),
            "NumMacTables_u32": _n(kv.get("MAC Tables", 0)),
            "NumIpTables_u32":  _n(kv.get("IP Tables",  0)),
            "NumLogin_u32":     _n(kv.get("Number of Logins", 0)),
            "MaxSession_u32": 0, "NoEnum_bool": False,
            "LastCommTime_dt": 0, "LastLoginTime_dt": 0, "CreatedTime_dt": 0,
            "IsTrafficFilled_bool": False, "AdminPasswordPlainText_str": "",
        }

    if method == "SetHub":
        cmds = [f"Hub {hub}"]
        cmds.append("Online" if params.get("Online_bool", True) else "Offline")
        pw = params.get("AdminPasswordPlainText_str", "")
        if pw:
            cmds.append(f"SetHubPassword {pw}")
        await _vc_in(host, port, password, cmds)
        return {}

    if method == "CreateHub":
        name = params.get("HubName_str", "")
        hp = params.get("AdminPasswordPlainText_str", "")
        arg = f"/PASSWORD:{hp}" if hp else "/NOPASSWORD"
        await _vc(host, port, password, "HubCreate", name, arg)
        return {}

    if method == "DeleteHub":
        await _vc(host, port, password, "HubDelete", hub)
        return {}

    # ── Sessions ─────────────────────────────────────────────────────────────
    if method == "EnumSession":
        rows = _vc_table(await _vc_in(host, port, password, [f"Hub {hub}", "SessionList"]), "SessionList")
        sessions = []
        for r in rows:
            name = r.get("Session Name", r.get("Name", ""))
            if not name:
                continue
            sessions.append({
                "Name_str":           name,
                "Username_str":       r.get("User Name", r.get("Username", "")),
                "ClientIP_ip":        r.get("Source Host Name", r.get("Source IP", "")),
                "ClientHostName_str": r.get("Source Host Name", r.get("Hostname", "")),
                "NumTcp_u32":         _n(r.get("TCP Connections", r.get("TCP", 0))),
                "PacketSize_u64":     _n(r.get("Transfer Bytes", r.get("Bytes", 0))),
                "PacketNum_u64":      _n(r.get("Transfer Packets", r.get("Transfer Pkts", 0))),
                "CreatedTime_dt": 0, "LastCommTime_dt": 0,
                "LinkMode_bool": False, "BridgeMode_bool": False,
                "SecureNATMode_bool": False, "Layer3Mode_bool": False, "IsDormant_bool": False,
            })
        return {"SessionList": sessions}

    if method == "GetSessionStatus":
        session = params.get("Name_str", "")
        kv = _vc_kv(await _vc_in(host, port, password, [f"Hub {hub}", f"SessionGet {session}"]), "SessionGet")
        return {
            "Name_str":                     session,
            "Username_str":                 kv.get("User Name (Authentication)", kv.get("Username", "")),
            "ClientHostName_str":           kv.get("Client Host Name", kv.get("Hostname", "")),
            "ClientProductName_str":        kv.get("VPN Client Software", kv.get("Client Product", "")),
            "ClientOsName_str":             kv.get("Client OS", kv.get("Operating System", "")),
            "CipherName_str":               kv.get("Encryption Algorithm", kv.get("Cipher", "")),
            "UseEncrypt_bool":              True,
            "UseCompress_bool":             False,
            "IsUsingUdpAcceleration_bool":  False,
            "TotalSendSize_u64": 0, "TotalRecvSize_u64": 0,
            "Send.UnicastBytes_u64": 0, "Recv.UnicastBytes_u64": 0,
        }

    if method == "DeleteSession":
        session = params.get("Name_str", "")
        await _vc_in(host, port, password, [f"Hub {hub}", f"SessionDelete {session}"])
        return {}

    # ── MAC / IP tables ───────────────────────────────────────────────────────
    if method == "EnumMacTable":
        rows = _vc_table(await _vc_in(host, port, password, [f"Hub {hub}", "MacTable"]), "MacTable")
        return {"MacTable": [{
            "UniqueId_u32": 0,
            "SessionName_str": r.get("Session Name", ""),
            "MacAddress_bin":  r.get("MAC Address", ""),
            "CreatedTime_dt": 0, "UpdatedTime_dt": 0,
        } for r in rows]}

    if method == "EnumIpTable":
        rows = _vc_table(await _vc_in(host, port, password, [f"Hub {hub}", "IpTable"]), "IpTable")
        return {"IpTable": [{
            "UniqueId_u32": 0,
            "SessionName_str": r.get("Session Name", ""),
            "IpAddress_ip":    r.get("IP Address", ""),
            "DhcpAllocated_bool": _b(r.get("DHCP", "")),
            "CreatedTime_dt": 0, "UpdatedTime_dt": 0,
        } for r in rows]}

    # ── Users ─────────────────────────────────────────────────────────────────
    if method == "EnumUser":
        rows = _vc_table(await _vc_in(host, port, password, [f"Hub {hub}", "UserList"]), "UserList")
        users = []
        for r in rows:
            uname = r.get("Username", r.get("User Name", ""))
            if not uname:
                continue
            users.append({
                "Name_str":         uname,
                "RealName_utf":     r.get("Full Name", r.get("Real Name", "")),
                "Note_utf":         r.get("Note", r.get("Description", "")),
                "GroupName_str":    r.get("Group Name", r.get("Group", "")),
                "AuthType_u32":     1,
                "NumLogin_u32":     _n(r.get("Num Logins", r.get("Number of Logins", r.get("Num Login", 0)))),
                "LastLoginTime_dt": 0, "CreatedTime_dt": 0, "UpdatedTime_dt": 0,
            })
        return {"UserList": users}

    if method == "GetUser":
        uname = params.get("Name_str", "")
        kv = _vc_kv(await _vc_in(host, port, password, [f"Hub {hub}", f"UserGet {uname}"]), "UserGet")
        # Parse auth type from vpncmd text output
        auth_text = kv.get("Auth Type", kv.get("Authentication Method", kv.get("Authentication", ""))).lower()
        if "cert" in auth_text or "certificate" in auth_text or "x.509" in auth_text:
            auth_type = 2
        elif "radius" in auth_text:
            auth_type = 3
        elif "nt" in auth_text or "ntdomain" in auth_text:
            auth_type = 4
        else:
            auth_type = 1
        # Try to get cert data via direct JSON-RPC if auth type is cert
        cert_data = None
        if auth_type == 2:
            try:
                direct = await _rpc_direct(method, params, host, port, password)
                cert_data = (direct.get("UserX_bin") or
                             direct.get("Auth_UserCert_CertData_bin") or
                             direct.get("AuthUserCert_bin") or
                             direct.get("Auth_UserCert_bin"))
            except Exception:
                pass
        result = {
            "Name_str":            uname,
            "RealName_utf":        kv.get("Full Name", kv.get("Real Name", "")),
            "Note_utf":            kv.get("Note", ""),
            "GroupName_str":       kv.get("Group Name", kv.get("Group", "")),
            "AuthType_u32":        auth_type,
            "NumLogin_u32":        _n(kv.get("Number of Logins", 0)),
            "LastLoginTime_dt": 0, "CreatedTime_dt": 0, "UpdatedTime_dt": 0,
            "IsExpireDate_bool": False, "ExpireDate_dt": 0,
        }
        if cert_data:
            result["Auth_UserCert_CertData_bin"] = cert_data
        return result

    if method == "CreateUser":
        uname = params.get("Name_str", "")
        upw   = params.get("Auth_Password_str", "")
        group = params.get("GroupName_str", "")
        rname = params.get("RealName_utf", "")
        note  = params.get("Note_utf", "")
        cmds  = [f"Hub {hub}",
                 f"UserCreate {uname} /GROUP:{group} /REALNAME:{rname} /NOTE:{note}"]
        if upw:
            cmds.append(f"UserPasswordSet {uname} /PASSWORD:{upw}")
        await _vc_in(host, port, password, cmds)
        return {}

    if method == "SetUser":
        uname = params.get("Name_str", "")
        upw   = params.get("Auth_Password_str")
        group = params.get("GroupName_str", "")
        rname = params.get("RealName_utf", "")
        note  = params.get("Note_utf", "")
        cmds  = [f"Hub {hub}",
                 f"UserEdit {uname} /GROUP:{group} /REALNAME:{rname} /NOTE:{note}"]
        if upw:
            cmds.append(f"UserPasswordSet {uname} /PASSWORD:{upw}")
        await _vc_in(host, port, password, cmds)
        return {}

    if method == "DeleteUser":
        uname = params.get("Name_str", "")
        await _vc_in(host, port, password, [f"Hub {hub}", f"UserDelete {uname}"])
        return {}

    # ── Groups ────────────────────────────────────────────────────────────────
    if method == "EnumGroup":
        rows = _vc_table(await _vc_in(host, port, password, [f"Hub {hub}", "GroupList"]), "GroupList")
        groups = []
        for r in rows:
            gname = r.get("Group Name", r.get("Name", ""))
            if not gname:
                continue
            groups.append({
                "Name_str":      gname,
                "Realname_utf":  r.get("Real Name", r.get("Full Name", "")),
                "Note_utf":      r.get("Note", ""),
                "NumUsers_u32":  _n(r.get("Num Users", r.get("Users", 0))),
                "CreatedTime_dt": 0,
            })
        return {"GroupList": groups}

    if method == "CreateGroup":
        gname = params.get("Name_str", "")
        rname = params.get("Realname_utf", "")
        note  = params.get("Note_utf", "")
        await _vc_in(host, port, password,
                     [f"Hub {hub}", f"GroupCreate {gname} /REALNAME:{rname} /NOTE:{note}"])
        return {}

    if method == "DeleteGroup":
        gname = params.get("Name_str", "")
        await _vc_in(host, port, password, [f"Hub {hub}", f"GroupDelete {gname}"])
        return {}

    # ── Server listeners ─────────────────────────────────────────────────────
    if method == "EnumListener":
        rows = _vc_table(await _vc(host, port, password, "ListenerList"))
        listeners = []
        for r in rows:
            # "Port Number" column value looks like "TCP 443" — extract the number
            port_val = _n(r.get("Port Number", r.get("TCP Port", r.get("Port", "0"))))
            if not port_val:
                continue
            listeners.append({
                "Ports_u32":   port_val,
                "Enable_bool": _b(r.get("Status", "Listening")),
            })
        return {"ListenerList": listeners}

    if method == "CreateListener":
        await _vc(host, port, password, "ListenerCreate", str(params.get("Ports_u32", 0)))
        return {}

    if method == "DeleteListener":
        await _vc(host, port, password, "ListenerDelete", str(params.get("Ports_u32", 0)))
        return {}

    if method == "EnableListener":
        p = str(params.get("Ports_u32", 0))
        cmd = "ListenerEnable" if params.get("Enable_bool", True) else "ListenerDisable"
        await _vc(host, port, password, cmd, p)
        return {}

    # ── Ethernet / bridges ───────────────────────────────────────────────────
    if method == "EnumEthernet":
        rows = _vc_table(await _vc(host, port, password, "BridgeDeviceList"))
        return {"EthList": [{"DeviceName_str": r.get("Network Adapter Name", r.get("Name", ""))} for r in rows if r.get("Network Adapter Name", r.get("Name", ""))]}

    if method == "EnumLocalBridge":
        try:
            rows = _vc_table(await _vc(host, port, password, "BridgeList"))
            bridges = []
            for r in rows:
                bridges.append({
                    "HubNameLB_str":   r.get("Virtual Hub Name", ""),
                    "DeviceName_str":  r.get("Network Adapter or Tap Device Name", r.get("Network Adapter Name", "")),
                    "TapMode_bool":    False,
                    "Online_bool":     _b(r.get("Status", "")),
                })
            return {"LocalBridgeList": bridges}
        except Exception:
            return {"LocalBridgeList": []}

    if method == "AddLocalBridge":
        hub_lb  = params.get("HubNameLB_str", "")
        dev     = params.get("DeviceName_str", "")
        tap     = "/TAP" if params.get("TapMode_bool", False) else ""
        await _vc(host, port, password, "BridgeCreate", hub_lb, f"/DEVICE:{dev}", tap)
        return {}

    if method == "DeleteLocalBridge":
        hub_lb = params.get("HubNameLB_str", "")
        dev    = params.get("DeviceName_str", "")
        await _vc(host, port, password, "BridgeDelete", hub_lb, f"/DEVICE:{dev}")
        return {}

    # ── IPsec ────────────────────────────────────────────────────────────────
    if method == "GetIPsecServices":
        kv = _vc_kv(await _vc(host, port, password, "IPsecGet"))
        return {
            "L2TP_Raw_bool":       _b(kv.get("Raw L2TP Server Function Enabled", "No")),
            "L2TP_IPsec_bool":     _b(kv.get("L2TP over IPsec Server Function Enabled", "No")),
            "EtherIP_IPsec_bool":  _b(kv.get("EtherIP / L2TPv3 over IPsec Server Function Enabled", "No")),
            "IPsec_Secret_str":    kv.get("IPsec Pre-Shared Key String", ""),
            "L2TP_DefaultHub_str": kv.get("Name of Default Virtual Hub", ""),
        }

    if method == "SetIPsecServices":
        cmds = []
        if params.get("L2TP_Raw_bool") or params.get("L2TP_IPsec_bool") or params.get("EtherIP_IPsec_bool"):
            secret = params.get("IPsec_Secret_str", "")
            hub_d  = params.get("L2TP_DefaultHub_str", "")
            flags  = []
            if params.get("L2TP_Raw_bool"):    flags.append("/L2TP:yes")
            if params.get("L2TP_IPsec_bool"):  flags.append("/L2TPIPSEC:yes")
            if params.get("EtherIP_IPsec_bool"): flags.append("/ETHERIP:yes")
            cmds = [f"IPsecEnable {' '.join(flags)} /PSK:{secret} /DEFAULTHUB:{hub_d}"]
        else:
            cmds = ["IPsecDisable"]
        await _vc_in(host, port, password, cmds)
        return {}

    # ── OpenVPN / SSTP ───────────────────────────────────────────────────────
    if method == "GetOpenVpnSstpConfig":
        kv = _vc_kv(await _vc_in(host, port, password, ["OpenVpnGet", "SstpGet"]))
        return {
            "EnableOpenVPN_bool":  _b(kv.get("OpenVPN Clone Server Enabled", "No")),
            "OpenVPNPortList_str": kv.get("UDP Port List", "1194"),
            "EnableSSTP_bool":     _b(kv.get("SSTP VPN Function Enabled", kv.get("SSTP Clone Server Function Enabled", "No"))),
        }

    if method == "SetOpenVpnSstpConfig":
        ovpn_flag = "/ENABLE" if params.get("EnableOpenVPN_bool") else "/DISABLE"
        ports     = params.get("OpenVPNPortList_str", "1194")
        sstp_flag = "/ENABLE" if params.get("EnableSSTP_bool") else "/DISABLE"
        await _vc(host, port, password, "OpenVpnEnable", ovpn_flag, f"/PORTS:{ports}")
        await _vc(host, port, password, "SstpEnable",   sstp_flag)
        return {}

    # ── Syslog ───────────────────────────────────────────────────────────────
    if method == "GetSysLog":
        kv = _vc_kv(await _vc(host, port, password, "SyslogGet"))
        save_type_str = kv.get("Set the Use of syslog Send Function", "Disable Syslog Send Function")
        s = save_type_str.lower()
        if "server" in s and "hub" in s:
            save_type = 3
        elif "hub" in s:
            save_type = 2
        elif "server" in s:
            save_type = 1
        else:
            save_type = 0
        return {
            "SaveType_u32": save_type,
            "Hostname_str": kv.get("Syslog Server Hostname", kv.get("Hostname", "")),
            "Port_u32":     _n(kv.get("Syslog Server Port Number", kv.get("Port", 514))),
        }

    if method == "SetSysLog":
        save_type = params.get("SaveType_u32", 0)
        hostname  = params.get("Hostname_str", "")
        slog_port = params.get("Port_u32", 514)
        if save_type == 0:
            await _vc(host, port, password, "SyslogDisable")
        else:
            await _vc(host, port, password, "SyslogEnable",
                      f"/HOST:{hostname}", f"/PORT:{slog_port}", f"/TYPE:{save_type}")
        return {}

    # ── Server password ───────────────────────────────────────────────────────
    if method == "SetServerPassword":
        new_pw = params.get("PlainTextPassword_str", "")
        await _vc(host, port, password, "ServerPasswordSet", f"/PASSWORD:{new_pw}")
        return {}

    # ── Cascade links (read-only via vpncmd) ──────────────────────────────────
    if method == "EnumLink":
        rows = _vc_table(await _vc_in(host, port, password, [f"Hub {hub}", "CascadeList"]), "CascadeList")
        links = []
        for r in rows:
            lname = r.get("Setting Name", r.get("Cascade Connection Name", r.get("Name", "")))
            if not lname:
                continue
            links.append({
                "AccountName_utf":  lname,
                "Online_bool":      _b(r.get("Status", "")),
                "ConnectedTime_dt": 0,
                "Hostname_str":     r.get("Destination VPN Server", r.get("Hostname", "")),
                "HubName_str":      r.get("Virtual Hub", r.get("Virtual Hub Name", "")),
            })
        return {"LinkList": links}

    # ── Layer 3 switches ──────────────────────────────────────────────────────
    if method == "EnumL3Switch":
        rows = _vc_table(await _vc(host, port, password, "RouterList"))
        switches = []
        for r in rows:
            name = r.get("Layer 3 Switch Name", r.get("L3 Switch Name", r.get("Name", "")))
            if not name:
                continue
            switches.append({
                "Name_str":      name,
                "Running_bool":  _b(r.get("Running Status", r.get("Status", "Stop"))),
                "NumIf_u32":     _n(r.get("Interfaces", r.get("Number of Interfaces", 0))),
                "NumTable_u32":  _n(r.get("Routing Tables", r.get("Number of Routing Tables", 0))),
            })
        return {"L3SWList": switches}

    if method == "AddL3Switch":
        await _vc(host, port, password, "RouterAdd", params.get("Name_str", ""))
        return {}

    if method == "DelL3Switch":
        await _vc(host, port, password, "RouterDelete", params.get("Name_str", ""))
        return {}

    if method == "StartL3Switch":
        await _vc(host, port, password, "RouterStart", params.get("Name_str", ""))
        return {}

    if method == "StopL3Switch":
        await _vc(host, port, password, "RouterStop", params.get("Name_str", ""))
        return {}

    if method == "EnumL3If":
        name = params.get("Name_str", "")
        rows = _vc_table(await _vc(host, port, password, "RouterIfList", name))
        return {"L3IFList": [{
            "HubName_str":    r.get("Virtual Hub Name", r.get("Hub", r.get("Hub Name", ""))),
            "IpAddress_ip":   r.get("IP Address", r.get("IP", "")),
            "SubnetMask_ip":  r.get("Subnet Mask", r.get("Mask", "")),
        } for r in rows]}

    if method == "AddL3If":
        name = params.get("Name_str", "")
        await _vc(host, port, password, "RouterIfAdd", name,
                  f"/HUB:{params.get('HubName_str', '')}",
                  f"/IP:{params.get('IpAddress_ip', '')}",
                  f"/MASK:{params.get('SubnetMask_ip', '')}")
        return {}

    if method == "DelL3If":
        name = params.get("Name_str", "")
        await _vc(host, port, password, "RouterIfDel", name,
                  f"/HUB:{params.get('HubName_str', '')}",
                  f"/IP:{params.get('IpAddress_ip', '')}",
                  f"/MASK:{params.get('SubnetMask_ip', '')}")
        return {}

    if method == "EnumL3Table":
        name = params.get("Name_str", "")
        rows = _vc_table(await _vc(host, port, password, "RouterTableList", name))
        return {"L3Table": [{
            "NetworkAddress_ip": r.get("Network Address", r.get("Network", "")),
            "SubnetMask_ip":     r.get("Subnet Mask", r.get("Mask", "")),
            "GatewayAddress_ip": r.get("Gateway Address", r.get("Gateway", "")),
            "Metric_u32":        _n(r.get("Metric", 1)),
        } for r in rows]}

    if method == "AddL3Table":
        name = params.get("Name_str", "")
        await _vc(host, port, password, "RouterTableAdd", name,
                  f"/NETWORK:{params.get('NetworkAddress_ip', '')}",
                  f"/MASK:{params.get('SubnetMask_ip', '')}",
                  f"/GW:{params.get('GatewayAddress_ip', '')}",
                  f"/METRIC:{params.get('Metric_u32', 1)}")
        return {}

    if method == "DelL3Table":
        name = params.get("Name_str", "")
        await _vc(host, port, password, "RouterTableDel", name,
                  f"/NETWORK:{params.get('NetworkAddress_ip', '')}",
                  f"/MASK:{params.get('SubnetMask_ip', '')}",
                  f"/GW:{params.get('GatewayAddress_ip', '')}",
                  f"/METRIC:{params.get('Metric_u32', 1)}")
        return {}

    # ── VPN Azure toggle ─────────────────────────────────────────────────────
    if method == "SetVpnAzureClientStatus":
        cmd = "VpnAzureEnable" if params.get("IsEnabled_bool", True) else "VpnAzureDisable"
        await _vc(host, port, password, cmd)
        return {}

    # ── Keep-Alive ───────────────────────────────────────────────────────────
    if method == "GetKeepAlive":
        kv = _vc_kv(await _vc(host, port, password, "KeepGet"))
        proto_str = kv.get("Protocol Type", kv.get("Protocol", "TCP")).upper()
        return {
            "UseKeepConnect_bool":        _b(kv.get("Use Keep-Alive Internet Connection Function", kv.get("Keep-Alive", "No"))),
            "KeepConnectHost_str":        kv.get("Hostname of the Host Which is Used to Check Connection", kv.get("Hostname", kv.get("Host", "www.google.com"))),
            "KeepConnectPort_u32":        _n(kv.get("Port Number", kv.get("Port", 80))),
            "KeepConnectProtocol_u32":    1 if "UDP" in proto_str else 0,
            "KeepConnectInterval_u32":    _n(kv.get("Interval", kv.get("Interval (Seconds)", 50))),
        }

    if method == "SetKeepAlive":
        enabled = params.get("UseKeepConnect_bool", False)
        host_ka = params.get("KeepConnectHost_str", "www.google.com")
        port_ka = params.get("KeepConnectPort_u32", 80)
        proto   = "UDP" if params.get("KeepConnectProtocol_u32", 0) == 1 else "TCP"
        interval = params.get("KeepConnectInterval_u32", 50)
        if enabled:
            await _vc(host, port, password, "KeepEnable",
                      f"/HOST:{host_ka}", f"/PORT:{port_ka}",
                      f"/PROTO:{proto}", f"/INTERVAL:{interval}")
        else:
            await _vc(host, port, password, "KeepDisable")
        return {}

    # ── Access Control List ───────────────────────────────────────────────────
    if method == "EnumAccess":
        rows = _vc_table(await _vc_in(host, port, password, [f"Hub {hub}", "AccessList"]))
        rules = []
        for r in rows:
            ps = r.get("Protocol", "all").lower().strip()
            proto_map = {"all": 0, "icmp": 1, "tcp": 6, "udp": 17}
            proto = proto_map.get(ps, _n(ps))
            action = r.get("Action", r.get("Pass/Discard", "Pass")).lower()
            rules.append({
                "Id_u32":            _n(r.get("ID", r.get("Id", 0))),
                "Note_utf":          r.get("Note", r.get("Rule Name", r.get("Name", ""))),
                "Active_bool":       _b(r.get("Active", r.get("Enabled", "Yes"))),
                "Priority_u32":      _n(r.get("Priority", 100)),
                "Discard_bool":      "discard" in action or "deny" in action or "block" in action,
                "IsIPv6_bool":       False,
                "SrcIpAddress_ip":   r.get("Src IP", r.get("Source IP", "0.0.0.0")),
                "SrcSubnetMask_ip":  r.get("Src Mask", r.get("Source Mask", "0.0.0.0")),
                "DestIpAddress_ip":  r.get("Dst IP", r.get("Destination IP", "0.0.0.0")),
                "DestSubnetMask_ip": r.get("Dst Mask", r.get("Destination Mask", "0.0.0.0")),
                "Protocol_u32":      proto,
                "SrcPortStart_u32":  _n(r.get("Src Port Start", r.get("Source Port Start", 0))),
                "SrcPortEnd_u32":    _n(r.get("Src Port End", r.get("Source Port End", 65535))) or 65535,
                "DestPortStart_u32": _n(r.get("Dst Port Start", r.get("Destination Port Start", 0))),
                "DestPortEnd_u32":   _n(r.get("Dst Port End", r.get("Destination Port End", 65535))) or 65535,
                "SrcUsername_str":   r.get("Src User", r.get("Source User", "")),
                "DestUsername_str":  r.get("Dst User", r.get("Destination User", "")),
                "Delay_u32": 0, "Jitter_u32": 0, "Loss_u32": 0,
                "CheckSrcMac_bool": False, "CheckDstMac_bool": False,
                "CheckTcpState_bool": False, "Established_bool": False,
                "RedirectUrl_str": "",
            })
        return {"AccessList": rules}

    if method == "AddAccess":
        r = params.get("AccessListSingleElement", params)
        proto_map = {0: "all", 1: "icmp", 6: "tcp", 17: "udp"}
        proto_num = r.get("Protocol_u32", 0)
        proto     = proto_map.get(proto_num, str(proto_num))
        note      = (r.get("Note_utf", "") or "rule").replace(" ", "_")[:32]
        action    = "/DISCARD" if r.get("Discard_bool") else "/PASS"
        priority  = r.get("Priority_u32", 100)
        srcip     = r.get("SrcIpAddress_ip", "0.0.0.0")
        srcmask   = r.get("SrcSubnetMask_ip", "0.0.0.0")
        dstip     = r.get("DestIpAddress_ip", "0.0.0.0")
        dstmask   = r.get("DestSubnetMask_ip", "0.0.0.0")
        cmd = (f"AccessAdd {note} /PRIORITY:{priority} {action} /PROTO:{proto}"
               f" /SRCIP:{srcip} /SRCMASK:{srcmask} /DSTIP:{dstip} /DSTMASK:{dstmask}")
        if r.get("SrcUsername_str"):
            cmd += f" /SRCUSER:{r['SrcUsername_str']}"
        if r.get("DestUsername_str"):
            cmd += f" /DSTUSER:{r['DestUsername_str']}"
        if proto in ("tcp", "udp"):
            sp0, sp1 = r.get("SrcPortStart_u32", 0), r.get("SrcPortEnd_u32", 65535)
            dp0, dp1 = r.get("DestPortStart_u32", 0), r.get("DestPortEnd_u32", 65535)
            if sp0 or sp1 < 65535:
                cmd += f" /SRCPORT:{sp0},{sp1}"
            if dp0 or dp1 < 65535:
                cmd += f" /DSTPORT:{dp0},{dp1}"
        await _vc_in(host, port, password, [f"Hub {hub}", cmd])
        return {}

    if method == "DeleteAccess":
        rid = params.get("Id_u32", 0)
        # vpncmd AccessDelete takes rule name — enumerate to find it
        rows = _vc_table(await _vc_in(host, port, password, [f"Hub {hub}", "AccessList"]))
        for r in rows:
            if _n(r.get("ID", r.get("Id", -1))) == rid:
                name = r.get("Note", r.get("Rule Name", r.get("Name", str(rid))))
                await _vc_in(host, port, password, [f"Hub {hub}", f"AccessDelete {name}"])
                return {}
        return {}

    if method == "SetAccessList":
        rules = params.get("AccessList", [])
        # Enable/disable individual rules to match the active flags
        cmds = [f"Hub {hub}"]
        for r in rules:
            rid = r.get("Id_u32", 0)
            active = r.get("Active_bool", True)
            # Need name to enable/disable — skip for now, use SetAccessList for ordering
        # Simplest: re-create everything — delete all, re-add in order
        # Too destructive; just skip for vpncmd (rare operation)
        raise HTTPException(501, "SetAccessList (reorder) not supported via vpncmd relay")

    if method == "GetSecureNATOption":
        async def _hub_kv(cmd):
            return _vc_kv(await _vc_in(host, port, password, [f"Hub {hub}", cmd]))
        nat_raw, dhcp_raw = await asyncio.gather(
            _hub_kv("NatGet"),
            _hub_kv("DhcpGet"),
            return_exceptions=True,
        )
        nat_kv  = nat_raw  if not isinstance(nat_raw,  Exception) else {}
        dhcp_kv = dhcp_raw if not isinstance(dhcp_raw, Exception) else {}

        def _mac_to_b64(s: str) -> str:
            if not s: return ""
            parts = s.strip().split(":")
            if len(parts) != 6: return ""
            try:
                return base64.b64encode(bytes(int(x, 16) for x in parts)).decode()
            except Exception:
                return ""

        mac_raw = nat_kv.get("Virtual Host MAC Address", nat_kv.get("MAC Address", ""))
        return {
            "MacAddress_bin":         _mac_to_b64(mac_raw),
            "Ip_ip":                  nat_kv.get("Virtual Host IP Address", nat_kv.get("IP Address", "192.168.30.1")),
            "Mask_ip":                nat_kv.get("Virtual Host Subnet Mask", nat_kv.get("Subnet Mask", "255.255.255.0")),
            "UseNat_bool":            _b(nat_kv.get("Use Virtual NAT Function", nat_kv.get("Use NAT", "Yes"))),
            "Mtu_u32":                _n(nat_kv.get("MTU Value", nat_kv.get("MTU", 1500))),
            "NatTcpTimeout_u32":      _n(nat_kv.get("NAT TCP Session Timeout", nat_kv.get("NAT TCP Timeout", 60))),
            "NatUdpTimeout_u32":      _n(nat_kv.get("NAT UDP Session Timeout", nat_kv.get("NAT UDP Timeout", 30))),
            "UseDhcp_bool":           _b(dhcp_kv.get("Use Virtual DHCP Server", dhcp_kv.get("Use DHCP", "Yes"))),
            "DhcpLeaseIPStart_ip":    dhcp_kv.get("DHCP Leased IP From", dhcp_kv.get("Start IP", "192.168.30.10")),
            "DhcpLeaseIPEnd_ip":      dhcp_kv.get("DHCP Leased IP To",   dhcp_kv.get("End IP",   "192.168.30.200")),
            "DhcpSubnetMask_ip":      dhcp_kv.get("Subnet Mask", "255.255.255.0"),
            "DhcpGatewayAddress_ip":  dhcp_kv.get("Default Gateway", dhcp_kv.get("Gateway", "192.168.30.1")),
            "DhcpDnsServerAddress_ip":  dhcp_kv.get("DNS Server 1", dhcp_kv.get("Primary DNS", "8.8.8.8")),
            "DhcpDnsServerAddress2_ip": dhcp_kv.get("DNS Server 2", dhcp_kv.get("Secondary DNS", "8.8.4.4")),
            "DhcpDomainName_str":     dhcp_kv.get("Domain Name", ""),
            "DhcpExpireTimeSpan_u32": _n(dhcp_kv.get("DHCP Lease Expire", dhcp_kv.get("Lease Time", 7200))),
        }

    # ── Not implemented via vpncmd (write ops needing direct TCP) ────────────
    raise HTTPException(501, f"Method '{method}' requires a direct TCP connection to the server")


# ── Unified RPC dispatcher ────────────────────────────────────────────────────

async def rpc(method: str, params: dict, admin_password: str = "") -> dict:
    host = _rpc_host.get()
    port = _rpc_port.get()
    try:
        return await _rpc_direct(method, params, host, port, admin_password)
    except HTTPException as e:
        if e.status_code in (400, 401):
            raise  # auth error / bad RPC — don't retry
        # 502 = network unreachable → try NAT-T via vpncmd (full host/hint preserved)
        return await _vpncmd_rpc(method, params, host, port, admin_password)


# --- Auth ---

class LoginRequest(BaseModel):
    password: str
    profile_id: str = ""

async def _probe_host(host: str, port: int, password: str) -> bool:
    """Return True if the server at host:port accepts our password."""
    _rpc_host.set(host)
    _rpc_port.set(port)
    try:
        await rpc("Test", {}, admin_password=password)
        return True
    except HTTPException as e:
        if e.status_code == 401:
            raise  # bad password — don't try further
        return False

@app.post("/api/login")
async def login(body: LoginRequest):
    profiles = load_profiles()
    profile = next((p for p in profiles if p["id"] == body.profile_id), None)
    if not profile and profiles:
        profile = profiles[0]

    candidates = []
    if profile:
        candidates.append((profile["host"], profile["port"]))
        h2 = profile.get("host2", "").strip()
        p2 = profile.get("port2") or 5555
        if h2:
            candidates.append((h2, p2))
    else:
        candidates.append((SOFTETHER_HOST, SOFTETHER_PORT))

    host, port = None, None
    last_exc = None
    for h, p in candidates:
        try:
            if await _probe_host(h, p, body.password):
                host, port = h, p
                break
        except HTTPException as e:
            last_exc = e
            if e.status_code == 401:
                raise HTTPException(status_code=401, detail="Invalid password")

    if host is None:
        raise last_exc or HTTPException(status_code=502, detail="Could not reach server on any configured address")

    token = secrets.token_hex(32)
    sessions_data[token] = {
        "password": body.password,
        "host": host,
        "port": port,
        "profile_id": profile["id"] if profile else "",
        "profile_name": profile["name"] if profile else "Local Server",
        "last_seen": time.time(),
    }
    resp = JSONResponse({"ok": True, "profile_name": profile["name"] if profile else "Local Server",
                         "connected_host": host, "connected_port": port})
    resp.set_cookie("vpnweb_sid", token, httponly=True, samesite="strict", secure=False, path="/")
    return resp

@app.post("/api/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("vpnweb_sid")
    if token:
        sessions_data.pop(token, None)
    response.delete_cookie("vpnweb_sid")
    return {"ok": True}

def get_password(request: Request) -> str:
    token = request.cookies.get("vpnweb_sid")
    if not token or token not in sessions_data:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return sessions_data[token]["password"]

@app.get("/api/session/info")
async def session_info(request: Request):
    token = request.cookies.get("vpnweb_sid")
    if not token or token not in sessions_data:
        return {"authenticated": False}
    d = sessions_data[token]
    return {"authenticated": True, "profile_name": d.get("profile_name", ""), "profile_id": d.get("profile_id", ""), "host": d.get("host", ""), "port": d.get("port", 0)}


# --- Server ---

@app.get("/api/server/info")
async def server_info(pw: str = Depends(get_password)):
    return await rpc("GetServerInfo", {}, admin_password=pw)

async def _get_ddns_azure(host: str, port: int, pw: str) -> dict:
    """Get DDNS + VPN Azure data: try JSON-RPC first, fall back to vpncmd."""
    ddns_r, azure_r = await asyncio.gather(
        _rpc_direct("GetDDnsClientStatus",    {}, host, port, pw),
        _rpc_direct("GetVpnAzureClientStatus",{}, host, port, pw),
        return_exceptions=True,
    )
    ddns  = ddns_r  if not isinstance(ddns_r, Exception)  else {}
    azure = azure_r if not isinstance(azure_r, Exception) else {}

    # JSON-RPC GetDDnsClientStatus uses CurrentFqdn_str, not DnsName_str — normalize
    if ddns and not ddns.get("DnsName_str"):
        ddns["DnsName_str"]   = ddns.get("CurrentFqdn_str", "")
        ddns["DnsPrefix_str"] = ddns.get("CurrentHostName_str", "")

    # Run vpncmd if DDNS still empty OR Azure unsupported (GetVpnAzureClientStatus often returns error 33)
    if not ddns.get("DnsName_str") or isinstance(azure_r, Exception):
        try:
            fa_kv = _vc_kv(await _vc_in(host, port, pw, ["DynamicDnsGetStatus", "VpnAzureGetStatus"]))
            ipv6 = fa_kv.get("Global IPv6 Address", "")
            if "failed" in ipv6.lower() or "error" in ipv6.lower():
                ipv6 = ""
            # Only overwrite DDNS if it's still missing
            if not ddns.get("DnsName_str") and fa_kv.get("Assigned Dynamic DNS Hostname (Full)"):
                ddns = {
                    "DnsName_str":     fa_kv.get("Assigned Dynamic DNS Hostname (Full)", ""),
                    "DnsPrefix_str":   fa_kv.get("Assigned Dynamic DNS Hostname (Hostname)", ""),
                    "CurrentIPv4_str": fa_kv.get("Global IPv4 Address", ""),
                    "CurrentIPv6_str": ipv6,
                }
            # Always get Azure from vpncmd (JSON-RPC is unsupported on most servers)
            azure = {
                "IsEnabled_bool":   _b(fa_kv.get("VPN Azure Function is Enabled", "No")),
                "IsConnected_bool": _b(fa_kv.get("Connection to VPN Azure Cloud Server is Established", "No")),
                "Hostname_str":     fa_kv.get("Hostname of this VPN Server on VPN Azure Service", ""),
            }
        except Exception:
            pass

    return {
        **ddns,
        "AzureHostname_str":   azure.get("Hostname_str", ""),
        "AzureConnected_bool": azure.get("IsConnected_bool", False),
        "AzureEnabled_bool":   azure.get("IsEnabled_bool", False),
    }


@app.get("/api/server/ddns")
async def server_ddns(pw: str = Depends(get_password)):
    host = _rpc_host.get()
    port = _rpc_port.get()
    return await _get_ddns_azure(host, port, pw)


@app.get("/api/server/all")
async def server_all(pw: str = Depends(get_password)):
    host = _rpc_host.get()
    port = _rpc_port.get()

    # Try all via direct JSON-RPC in parallel (fast for direct connections)
    # DDNS/Azure are fetched separately via _get_ddns_azure (has its own vpncmd fallback)
    results, ddns_merged = await asyncio.gather(
        asyncio.gather(
            _rpc_direct("GetServerInfo",        {}, host, port, pw),
            _rpc_direct("GetServerStatus",      {}, host, port, pw),
            _rpc_direct("EnumHub",              {}, host, port, pw),
            _rpc_direct("EnumListener",         {}, host, port, pw),
            _rpc_direct("GetIPsecServices",     {}, host, port, pw),
            _rpc_direct("GetOpenVpnSstpConfig", {}, host, port, pw),
            _rpc_direct("GetSysLog",            {}, host, port, pw),
            _rpc_direct("EnumLocalBridge",      {}, host, port, pw),
            _rpc_direct("EnumEthernet",         {}, host, port, pw),
            _rpc_direct("EnumL3Switch",         {}, host, port, pw),
            return_exceptions=True,
        ),
        _get_ddns_azure(host, port, pw),
    )

    # If network unreachable (all 502s), use batched vpncmd (full host with hint)
    net_errors = sum(1 for r in results if isinstance(r, HTTPException) and r.status_code >= 500)
    if net_errors >= 3:
        return await _bulk_server_vpncmd(host, port, pw)

    # Check for auth error
    for r in results:
        if isinstance(r, HTTPException) and r.status_code == 401:
            raise HTTPException(401, "Invalid password")

    def _ok(r, default):
        return r if not isinstance(r, Exception) else default

    info, status, hubs_r, listeners_r, ipsec, ovpn, syslog, bridges_r, eth_r, l3_r = results
    info = _ok(info, {}); status = _ok(status, {})
    ipsec = _ok(ipsec, {}); ovpn = _ok(ovpn, {}); syslog = _ok(syslog, {})

    return {
        "info":      info,
        "status":    status,
        "ddns":      ddns_merged,
        "hubs":      _ok(hubs_r, {}).get("HubList", []),
        "listeners": _ok(listeners_r, {}).get("ListenerList", []),
        "ipsec":     ipsec,
        "openvpn":   ovpn,
        "syslog":    syslog,
        "bridges":   _ok(bridges_r, {}).get("LocalBridgeList", []),
        "ethernet":  _ok(eth_r, {}).get("EthList", []),
        "l3":        _ok(l3_r, {}).get("L3SWList", []),
    }


@app.get("/api/hubs/{hub}/all")
async def hub_all(hub: str, pw: str = Depends(get_password)):
    host = _rpc_host.get()
    port = _rpc_port.get()

    results = await asyncio.gather(
        _rpc_direct("GetHubStatus",         {"HubName_str": hub}, host, port, pw),
        _rpc_direct("GetHub",               {"HubName_str": hub}, host, port, pw),
        _rpc_direct("EnumUser",             {"HubName_str": hub}, host, port, pw),
        _rpc_direct("EnumGroup",            {"HubName_str": hub}, host, port, pw),
        _rpc_direct("EnumSession",          {"HubName_str": hub}, host, port, pw),
        _rpc_direct("EnumLink",             {"HubName_str": hub}, host, port, pw),
        _rpc_direct("EnumMacTable",         {"HubName_str": hub}, host, port, pw),
        _rpc_direct("EnumIpTable",          {"HubName_str": hub}, host, port, pw),
        _rpc_direct("GetHubLog",            {"HubName_str": hub}, host, port, pw),
        _rpc_direct("GetHubRadius",         {"HubName_str": hub}, host, port, pw),
        _rpc_direct("GetSecureNATOption",   {"RpcHubName_str": hub}, host, port, pw),
        return_exceptions=True,
    )

    net_errors = sum(1 for r in results if isinstance(r, HTTPException) and r.status_code >= 500)
    if net_errors >= 3:
        data = await _bulk_hub_vpncmd(host, port, pw, hub)
        log, radius, snat = await asyncio.gather(
            _vpncmd_rpc("GetHubLog",          {"HubName_str": hub}, host, port, pw),
            _vpncmd_rpc("GetHubRadius",       {"HubName_str": hub}, host, port, pw),
            _vpncmd_rpc("GetSecureNATOption", {"RpcHubName_str": hub}, host, port, pw),
            return_exceptions=True,
        )
        data["log"]       = log if not isinstance(log, Exception) else {}
        data["radius"]    = radius if not isinstance(radius, Exception) else {}
        data["securenat"] = snat if not isinstance(snat, Exception) else {}
        return data

    for r in results:
        if isinstance(r, HTTPException) and r.status_code == 401:
            raise HTTPException(401, "Invalid password")

    def _ok(r, default):
        return r if not isinstance(r, Exception) else default

    status_r, config_r, users_r, groups_r, sessions_r, links_r, mac_r, ip_r, log_r, radius_r, snat_r = results

    # For any call that failed (including 400 errors from relay quirks), retry via vpncmd
    vc_fallbacks = [
        ("EnumUser",           {"HubName_str": hub},      isinstance(users_r,    Exception)),
        ("EnumGroup",          {"HubName_str": hub},      isinstance(groups_r,   Exception)),
        ("EnumSession",        {"HubName_str": hub},      isinstance(sessions_r, Exception)),
        ("EnumLink",           {"HubName_str": hub},      isinstance(links_r,    Exception)),
        ("EnumMacTable",       {"HubName_str": hub},      isinstance(mac_r,      Exception)),
        ("EnumIpTable",        {"HubName_str": hub},      isinstance(ip_r,       Exception)),
        ("GetHubLog",          {"HubName_str": hub},      isinstance(log_r,      Exception)),
        ("GetHubRadius",       {"HubName_str": hub},      isinstance(radius_r,   Exception)),
        ("GetSecureNATOption", {"RpcHubName_str": hub},   isinstance(snat_r,     Exception)),
    ]
    if any(needed for _, _, needed in vc_fallbacks):
        vc_results = await asyncio.gather(
            *[_vpncmd_rpc(m, p, host, port, pw) if needed else asyncio.sleep(0, result=None)
              for m, p, needed in vc_fallbacks],
            return_exceptions=True,
        )
        (users_vc, groups_vc, sessions_vc, links_vc, mac_vc, ip_vc, log_vc, radius_vc, snat_vc) = vc_results
        if isinstance(users_r,    Exception) and not isinstance(users_vc,    Exception): users_r    = users_vc
        if isinstance(groups_r,   Exception) and not isinstance(groups_vc,   Exception): groups_r   = groups_vc
        if isinstance(sessions_r, Exception) and not isinstance(sessions_vc, Exception): sessions_r = sessions_vc
        if isinstance(links_r,    Exception) and not isinstance(links_vc,    Exception): links_r    = links_vc
        if isinstance(mac_r,      Exception) and not isinstance(mac_vc,      Exception): mac_r      = mac_vc
        if isinstance(ip_r,       Exception) and not isinstance(ip_vc,       Exception): ip_r       = ip_vc
        if isinstance(log_r,      Exception) and not isinstance(log_vc,      Exception): log_r      = log_vc
        if isinstance(radius_r,   Exception) and not isinstance(radius_vc,   Exception): radius_r   = radius_vc
        if isinstance(snat_r,     Exception) and not isinstance(snat_vc,     Exception): snat_r     = snat_vc

    return {
        "status":    _ok(status_r, {}),
        "config":    _ok(config_r, {}),
        "users":     _ok(users_r, {}).get("UserList", []),
        "groups":    _ok(groups_r, {}).get("GroupList", []),
        "sessions":  _ok(sessions_r, {}).get("SessionList", []),
        "links":     _ok(links_r, {}).get("LinkList", []),
        "mac":       _ok(mac_r, {}).get("MacTable", []),
        "ip":        _ok(ip_r, {}).get("IpTable", []),
        "log":       _ok(log_r, {}),
        "radius":    _ok(radius_r, {}),
        "securenat": _ok(snat_r, {}),
    }

@app.get("/api/server/status")
async def server_status(pw: str = Depends(get_password)):
    return await rpc("GetServerStatus", {}, admin_password=pw)


# --- Hubs ---

@app.get("/api/hubs")
async def list_hubs(pw: str = Depends(get_password)):
    result = await rpc("EnumHub", {}, admin_password=pw)
    return result.get("HubList", [])

class HubCreate(BaseModel):
    name: str
    password: str = ""

@app.post("/api/hubs")
async def create_hub(body: HubCreate, pw: str = Depends(get_password)):
    return await rpc("CreateHub", {
        "HubName_str": body.name,
        "AdminPasswordPlainText_str": body.password,
        "HubType_u32": 0,
        "Online_bool": True,
    }, admin_password=pw)

@app.delete("/api/hubs/{hub}")
async def delete_hub(hub: str, pw: str = Depends(get_password)):
    return await rpc("DeleteHub", {"HubName_str": hub}, admin_password=pw)

@app.get("/api/hubs/{hub}/status")
async def hub_status(hub: str, pw: str = Depends(get_password)):
    return await rpc("GetHubStatus", {"HubName_str": hub}, admin_password=pw)

@app.get("/api/hubs/{hub}/config")
async def hub_config(hub: str, pw: str = Depends(get_password)):
    return await rpc("GetHub", {"HubName_str": hub}, admin_password=pw)

class HubConfig(BaseModel):
    online: bool
    max_session: int = 0
    no_enum: bool = False
    password: str = ""

@app.put("/api/hubs/{hub}/config")
async def set_hub_config(hub: str, body: HubConfig, pw: str = Depends(get_password)):
    params: dict = {
        "HubName_str": hub,
        "Online_bool": body.online,
        "MaxSession_u32": body.max_session,
        "NoEnum_bool": body.no_enum,
    }
    if body.password:
        params["AdminPasswordPlainText_str"] = body.password
    return await rpc("SetHub", params, admin_password=pw)

@app.get("/api/hubs/{hub}/log")
async def hub_log(hub: str, pw: str = Depends(get_password)):
    return await rpc("GetHubLog", {"HubName_str": hub}, admin_password=pw)

class HubLogConfig(BaseModel):
    save_security_log: bool = True
    security_log_switch_type: int = 4
    save_packet_log: bool = False
    packet_log_switch_type: int = 4

@app.put("/api/hubs/{hub}/log")
async def set_hub_log(hub: str, body: HubLogConfig, pw: str = Depends(get_password)):
    return await rpc("SetHubLog", {
        "HubName_str": hub,
        "SaveSecurityLog_bool": body.save_security_log,
        "SecurityLogSwitchType_u32": body.security_log_switch_type,
        "SavePacketLog_bool": body.save_packet_log,
        "PacketLogSwitchType_u32": body.packet_log_switch_type,
    }, admin_password=pw)

@app.get("/api/hubs/{hub}/radius")
async def hub_radius(hub: str, pw: str = Depends(get_password)):
    return await rpc("GetHubRadius", {"HubName_str": hub}, admin_password=pw)

class RadiusConfig(BaseModel):
    server: str = ""
    port: int = 1812
    secret: str = ""
    retry_interval: int = 500

@app.put("/api/hubs/{hub}/radius")
async def set_hub_radius(hub: str, body: RadiusConfig, pw: str = Depends(get_password)):
    return await rpc("SetHubRadius", {
        "HubName_str": hub,
        "RadiusServerName_str": body.server,
        "RadiusPort_u32": body.port,
        "RadiusSecret_str": body.secret,
        "RadiusRetryInterval_u32": body.retry_interval,
    }, admin_password=pw)


# --- Users ---

@app.get("/api/hubs/{hub}/users")
async def list_users(hub: str, pw: str = Depends(get_password)):
    host = _rpc_host.get()
    port = _rpc_port.get()
    params = {"HubName_str": hub}
    try:
        result = await _rpc_direct("EnumUser", params, host, port, pw)
    except HTTPException:
        result = await _vpncmd_rpc("EnumUser", params, host, port, pw)
    users = result.get("UserList", [])
    for u in users:
        p12_path = _cert_path(hub, u.get("Name_str", ""))
        u["has_p12"] = p12_path.exists()
        if u.get("AuthType_u32") == 2 and u["has_p12"]:
            try:
                _, cert, _ = _pkcs12.load_key_and_certificates(p12_path.read_bytes(), None)
                try:
                    u["cert_expires"] = cert.not_valid_after_utc.strftime("%Y-%m-%d")
                except AttributeError:
                    u["cert_expires"] = cert.not_valid_after.strftime("%Y-%m-%d")
            except Exception:
                pass
    return users


_CERT_FIELD_CANDIDATES = [
    "UserX_bin",                   # SoftEther JSON-RPC GetUser actual field name
    "Auth_UserCert_CertData_bin",  # SoftEther SetUser input field name (kept for compatibility)
    "AuthUserCert_bin",
    "Auth_UserCert_bin",
]

@app.get("/api/hubs/{hub}/users/{username}")
async def get_user(hub: str, username: str, pw: str = Depends(get_password)):
    user = await rpc("GetUser", {"HubName_str": hub, "Name_str": username}, admin_password=pw)
    if user.get("AuthType_u32") == 2:
        for _cf in _CERT_FIELD_CANDIDATES:
            _cert_val = user.get(_cf)
            if _cert_val:
                info = _parse_cert_info(_cert_val)
                if info:
                    user["cert_info"] = info
                break
    user["has_p12"] = _cert_path(hub, username).exists()
    meta = _load_meta().get(_meta_key(hub, username), {})
    user["email"] = meta.get("email", "")
    user["invite_status"] = meta.get("invite_status")
    user["invite_sent_at"] = meta.get("invite_sent_at")
    return user

class UserCreate(BaseModel):
    username: str
    password: str = ""
    realname: str = ""
    note: str = ""
    group: str = ""
    # Invite / cert fields
    email: str = ""
    send_invite: bool = False
    cert_cn: str = ""
    cert_o: str = ""
    cert_ou: str = ""
    cert_c: str = ""
    cert_st: str = ""
    cert_l: str = ""
    cert_days: int = 1825
    cert_key_size: int = 2048
    expiry_hours: Optional[int] = None

@app.post("/api/hubs/{hub}/users")
async def create_user(hub: str, body: UserCreate, request: Request, pw: str = Depends(get_password)):
    placeholder_pw = secrets.token_urlsafe(24) if not body.password else body.password
    await rpc("CreateUser", {
        "HubName_str": hub,
        "Name_str": body.username,
        "RealName_utf": body.realname,
        "Note_utf": body.note,
        "GroupName_str": body.group,
        "AuthType_u32": 1,
        "Auth_Password_str": placeholder_pw,
    }, admin_password=pw)

    if body.email:
        async with _meta_lock:
            meta = _load_meta()
            key = _meta_key(hub, body.username)
            meta[key] = meta.get(key, {})
            meta[key]["email"] = body.email
            _save_json_file(USER_META_FILE, meta)

    if body.send_invite:
        if not body.email:
            raise HTTPException(400, "Email is required to send a registration invite")
        cfg = _load_config()
        reg_cfg = cfg.get("registration", {})
        expiry_hours = body.expiry_hours or reg_cfg.get("token_expiry_hours", 72)
        base_url = reg_cfg.get("base_url", "") or f"http://{request.headers.get('host', 'localhost')}"
        host = _rpc_host.get()
        port = _rpc_port.get()
        cert_params = {k: getattr(body, k) for k in (
            "cert_cn", "cert_o", "cert_ou", "cert_c", "cert_st", "cert_l", "cert_days", "cert_key_size"
        )}
        async with _tokens_lock:
            token = _make_reg_token(hub, body.username, host, port, pw, cert_params, expiry_hours)
        async with _meta_lock:
            meta = _load_meta()
            key = _meta_key(hub, body.username)
            meta[key] = meta.get(key, {})
            meta[key]["invite_status"] = "pending"
            meta[key]["invite_sent_at"] = _dt.datetime.utcnow().isoformat()
            _save_json_file(USER_META_FILE, meta)
        await _send_invite_email(body.email, token, body.username, hub, base_url, expiry_hours)

    return {"ok": True}

class UserUpdate(BaseModel):
    realname: str = ""
    note: str = ""
    group: str = ""
    password: Optional[str] = None

@app.put("/api/hubs/{hub}/users/{username}")
async def update_user(hub: str, username: str, body: UserUpdate, pw: str = Depends(get_password)):
    current = await rpc("GetUser", {"HubName_str": hub, "Name_str": username}, admin_password=pw)
    auth_type = current.get("AuthType_u32", 1)
    params: dict = {
        "HubName_str": hub,
        "Name_str": username,
        "RealName_utf": body.realname,
        "Note_utf": body.note,
        "GroupName_str": body.group,
        "AuthType_u32": auth_type,
    }
    if auth_type == 1 and body.password:
        params["Auth_Password_str"] = body.password
    elif auth_type == 2:
        cert_data = (current.get("UserX_bin") or current.get("Auth_UserCert_CertData_bin"))
        if cert_data:
            params["UserX_bin"] = cert_data
    return await rpc("SetUser", params, admin_password=pw)

@app.delete("/api/hubs/{hub}/users/{username}")
async def delete_user(hub: str, username: str, pw: str = Depends(get_password)):
    return await rpc("DeleteUser", {"HubName_str": hub, "Name_str": username}, admin_password=pw)


class UserCertBody(BaseModel):
    cert_pem: str

class UserCertRevoke(BaseModel):
    password: str

@app.post("/api/hubs/{hub}/users/{username}/cert")
async def set_user_cert(hub: str, username: str, body: UserCertBody, pw: str = Depends(get_password)):
    try:
        der = _pem_to_der(body.cert_pem)
    except Exception:
        raise HTTPException(400, "Invalid PEM certificate")
    der_b64 = base64.b64encode(der).decode()
    current = await rpc("GetUser", {"HubName_str": hub, "Name_str": username}, admin_password=pw)
    await rpc("SetUser", {
        "HubName_str": hub,
        "Name_str": username,
        "RealName_utf": current.get("Realname_utf") or current.get("RealName_utf") or "",
        "Note_utf": current.get("Note_utf") or "",
        "GroupName_str": current.get("GroupName_str") or "",
        "AuthType_u32": 2,
        "UserX_bin": der_b64,
    }, admin_password=pw)
    return _parse_cert_info(der_b64)

@app.delete("/api/hubs/{hub}/users/{username}/cert")
async def revoke_user_cert(hub: str, username: str, body: UserCertRevoke, pw: str = Depends(get_password)):
    current = await rpc("GetUser", {"HubName_str": hub, "Name_str": username}, admin_password=pw)
    await rpc("SetUser", {
        "HubName_str": hub,
        "Name_str": username,
        "RealName_utf": current.get("Realname_utf") or current.get("RealName_utf") or "",
        "Note_utf": current.get("Note_utf") or "",
        "GroupName_str": current.get("GroupName_str") or "",
        "AuthType_u32": 1,
        "Auth_Password_str": body.password,
    }, admin_password=pw)
    p12_path = _cert_path(hub, username)
    p12_path.unlink(missing_ok=True)
    return {"ok": True}

@app.get("/api/hubs/{hub}/users/{username}/cert/export")
async def export_user_cert(hub: str, username: str, pw: str = Depends(get_password)):
    user = await rpc("GetUser", {"HubName_str": hub, "Name_str": username}, admin_password=pw)
    cert_b64 = user.get("UserX_bin") or user.get("Auth_UserCert_CertData_bin")
    if user.get("AuthType_u32") != 2 or not cert_b64:
        raise HTTPException(404, "No certificate registered for this user")
    der = base64.b64decode(cert_b64)
    pem = _der_to_pem(der)
    return Response(
        content=pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{username}_{hub}.crt"'}
    )

class UserCertGenerate(BaseModel):
    cn: str = ""
    o: str = ""
    ou: str = ""
    c: str = ""
    st: str = ""
    l: str = ""
    days: int = 1825
    key_size: int = 2048

@app.post("/api/hubs/{hub}/users/{username}/cert/generate")
async def generate_user_cert(hub: str, username: str, body: UserCertGenerate, pw: str = Depends(get_password)):
    if body.key_size not in (2048, 4096):
        raise HTTPException(400, "key_size must be 2048 or 4096")
    cn = body.cn.strip() or username
    oid = _x509.oid.NameOID
    attrs = [_x509.NameAttribute(oid.COMMON_NAME, cn)]
    if body.o.strip():  attrs.append(_x509.NameAttribute(oid.ORGANIZATION_NAME,        body.o.strip()))
    if body.ou.strip(): attrs.append(_x509.NameAttribute(oid.ORGANIZATIONAL_UNIT_NAME, body.ou.strip()))
    if body.c.strip():  attrs.append(_x509.NameAttribute(oid.COUNTRY_NAME,             body.c.strip().upper()[:2]))
    if body.st.strip(): attrs.append(_x509.NameAttribute(oid.STATE_OR_PROVINCE_NAME,   body.st.strip()))
    if body.l.strip():  attrs.append(_x509.NameAttribute(oid.LOCALITY_NAME,            body.l.strip()))
    key = _rsa.generate_private_key(
        public_exponent=65537, key_size=body.key_size, backend=_crypto_backend()
    )
    subject = issuer = _x509.Name(attrs)
    cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow())
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=body.days))
        .sign(key, _hashes.SHA256(), _crypto_backend())
    )
    cert_der = cert.public_bytes(_serialization.Encoding.DER)
    der_b64 = base64.b64encode(cert_der).decode()
    current = await rpc("GetUser", {"HubName_str": hub, "Name_str": username}, admin_password=pw)
    await rpc("SetUser", {
        "HubName_str": hub,
        "Name_str": username,
        "RealName_utf": current.get("Realname_utf") or current.get("RealName_utf") or "",
        "Note_utf": current.get("Note_utf") or "",
        "GroupName_str": current.get("GroupName_str") or "",
        "AuthType_u32": 2,
        "UserX_bin": der_b64,
    }, admin_password=pw)
    p12 = _pkcs12.serialize_key_and_certificates(
        name=cn.encode(), key=key, cert=cert, cas=None,
        encryption_algorithm=_serialization.NoEncryption()
    )
    (_cert_path(hub, username)).write_bytes(p12)
    return {"ok": True}

@app.get("/api/hubs/{hub}/users/{username}/cert/p12")
async def download_user_p12(hub: str, username: str, pw: str = Depends(get_password)):
    p12_path = _cert_path(hub, username)
    if not p12_path.exists():
        raise HTTPException(404, "No .p12 on server — regenerate the certificate")
    return Response(
        content=p12_path.read_bytes(),
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f'attachment; filename="{username}_{hub}.p12"'}
    )

def _ovpn_host(request: Request, remote_host: Optional[str]) -> str:
    """Resolve the VPN server hostname for a .ovpn remote directive.
    Priority: explicit remote_host > profile RPC host > request Host header.
    Never returns 127.0.0.1/localhost — that's the local JSON-RPC address, not
    the client-facing address."""
    if remote_host:
        return remote_host
    rpc = _rpc_host.get()
    if rpc not in ("127.0.0.1", "::1", "localhost"):
        return rpc
    # Fall back to the host the browser used to reach vpnweb (strips port)
    browser_host = request.headers.get("host", "").split(":")[0]
    return browser_host or rpc


@app.get("/api/hubs/{hub}/users/{username}/ovpn")
async def download_user_ovpn(
    hub: str, username: str, pkcs11_id: str,
    request: Request,
    remote_host: Optional[str] = None,
    pw: str = Depends(get_password)
):
    host = _rpc_host.get()
    port = _rpc_port.get()
    ovpn_host = _ovpn_host(request, remote_host)

    try:
        ovpn_cfg = await _rpc_direct("GetOpenVpnSstpConfig", {}, host, port, pw)
        ovpn_port = ovpn_cfg.get("OpenVPNPortList_str", "1194").split(",")[0].strip()
    except Exception:
        ovpn_port = "1194"

    try:
        info = await _rpc_direct("GetServerCert", {}, host, port, pw)
        ca_der_b64 = info.get("Cert_bin", "")
        ca_pem = _der_to_pem(base64.b64decode(ca_der_b64)) if ca_der_b64 else ""
    except Exception:
        ca_pem = ""

    if not ca_pem:
        raise HTTPException(500, "Could not retrieve server CA certificate")

    ovpn_content = (
        f"client\ndev tun\nproto udp\nremote {ovpn_host} {ovpn_port}\n\n"
        f"tls-client\ndata-ciphers AES-128-CBC\nverb 3\nconnect-retry 5\nconnect-timeout 30\n\n"
        f'pkcs11-providers "C:\\\\Program Files\\\\Yubico\\\\Yubico PIV Tool\\\\bin\\\\libykcs11.dll"\n'
        f"pkcs11-id '{pkcs11_id}'\n\n"
        f"auth-user-pass\n<auth-user-pass>\n{username}@{hub}\nx\n</auth-user-pass>\n\n"
        f"<ca>\n{ca_pem}\n</ca>\n"
    )
    filename = f"{username}_{hub}.ovpn"
    return Response(
        content=ovpn_content,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}
    )


@app.get("/api/hubs/{hub}/users/{username}/ovpn/connect")
async def download_user_ovpn_connect(
    hub: str, username: str,
    request: Request,
    remote_host: Optional[str] = None,
    pw: str = Depends(get_password)
):
    """OpenVPN Connect profile — no pkcs11 directives; user assigns YubiKey via app GUI."""
    host = _rpc_host.get()
    port = _rpc_port.get()
    ovpn_host = _ovpn_host(request, remote_host)

    try:
        ovpn_cfg = await _rpc_direct("GetOpenVpnSstpConfig", {}, host, port, pw)
        ovpn_port = ovpn_cfg.get("OpenVPNPortList_str", "1194").split(",")[0].strip()
    except Exception:
        ovpn_port = "1194"

    try:
        info = await _rpc_direct("GetServerCert", {}, host, port, pw)
        ca_der_b64 = info.get("Cert_bin", "")
        ca_pem = _der_to_pem(base64.b64decode(ca_der_b64)) if ca_der_b64 else ""
    except Exception:
        ca_pem = ""

    if not ca_pem:
        raise HTTPException(500, "Could not retrieve server CA certificate")

    ovpn_content = (
        f"# OpenVPN Connect profile\n"
        f"# After importing: edit profile -> Certificate and Key -> Assign\n"
        f"# -> Hardware Tokens -> select YubiKey -> enter PIN.\n"
        f"# Requires: Yubico PIV Tool installed + libykcs11.dll in\n"
        f"# C:\\Program Files\\OpenVPN Connect\\pkcs11_modules\\\n\n"
        f"client\n"
        f"dev tun\n"
        f"proto udp\n"
        f"remote {ovpn_host} {ovpn_port}\n"
        f"nobind\n"
        f"remote-cert-tls server\n"
        f"cipher AES-128-CBC\n"
        f"verb 3\n\n"
        f"auth-user-pass\n"
        f"<auth-user-pass>\n{username}@{hub}\n\n</auth-user-pass>\n\n"
        f"<ca>\n{ca_pem}\n</ca>\n"
    )
    filename = f"{username}_{hub}_connect.ovpn"
    return Response(
        content=ovpn_content,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}
    )


# --- Groups ---

@app.get("/api/hubs/{hub}/groups")
async def list_groups(hub: str, pw: str = Depends(get_password)):
    result = await rpc("EnumGroup", {"HubName_str": hub}, admin_password=pw)
    return result.get("GroupList", [])

@app.get("/api/hubs/{hub}/groups/{group}")
async def get_group(hub: str, group: str, pw: str = Depends(get_password)):
    return await rpc("GetGroup", {"HubName_str": hub, "Name_str": group}, admin_password=pw)

class GroupCreate(BaseModel):
    name: str
    realname: str = ""
    note: str = ""

@app.post("/api/hubs/{hub}/groups")
async def create_group(hub: str, body: GroupCreate, pw: str = Depends(get_password)):
    return await rpc("CreateGroup", {
        "HubName_str": hub,
        "Name_str": body.name,
        "Realname_utf": body.realname,
        "Note_utf": body.note,
    }, admin_password=pw)

class GroupUpdate(BaseModel):
    realname: str = ""
    note: str = ""

@app.put("/api/hubs/{hub}/groups/{group}")
async def update_group(hub: str, group: str, body: GroupUpdate, pw: str = Depends(get_password)):
    return await rpc("SetGroup", {
        "HubName_str": hub,
        "Name_str": group,
        "Realname_utf": body.realname,
        "Note_utf": body.note,
    }, admin_password=pw)

@app.delete("/api/hubs/{hub}/groups/{group}")
async def delete_group(hub: str, group: str, pw: str = Depends(get_password)):
    return await rpc("DeleteGroup", {"HubName_str": hub, "Name_str": group}, admin_password=pw)


# --- Sessions ---

@app.get("/api/hubs/{hub}/sessions")
async def list_sessions(hub: str, pw: str = Depends(get_password)):
    result = await rpc("EnumSession", {"HubName_str": hub}, admin_password=pw)
    return result.get("SessionList", [])

@app.get("/api/hubs/{hub}/sessions/{session_name}")
async def get_session_status(hub: str, session_name: str, pw: str = Depends(get_password)):
    return await rpc("GetSessionStatus", {"HubName_str": hub, "Name_str": session_name}, admin_password=pw)

@app.delete("/api/hubs/{hub}/sessions/{session_name}")
async def disconnect_session(hub: str, session_name: str, pw: str = Depends(get_password)):
    return await rpc("DeleteSession", {"HubName_str": hub, "Name_str": session_name}, admin_password=pw)


# --- MAC / IP tables ---

@app.get("/api/hubs/{hub}/mac-table")
async def mac_table(hub: str, pw: str = Depends(get_password)):
    result = await rpc("EnumMacTable", {"HubName_str": hub}, admin_password=pw)
    return result.get("MacTable", [])

@app.get("/api/hubs/{hub}/ip-table")
async def ip_table(hub: str, pw: str = Depends(get_password)):
    result = await rpc("EnumIpTable", {"HubName_str": hub}, admin_password=pw)
    return result.get("IpTable", [])


# --- Cascade links ---

@app.get("/api/hubs/{hub}/links")
async def list_links(hub: str, pw: str = Depends(get_password)):
    result = await rpc("EnumLink", {"HubName_str": hub}, admin_password=pw)
    return result.get("LinkList", [])

@app.get("/api/hubs/{hub}/links/{link}")
async def get_link(hub: str, link: str, pw: str = Depends(get_password)):
    return await rpc("GetLink", {"HubName_Ex_str": hub, "AccountName_utf": link}, admin_password=pw)

@app.get("/api/hubs/{hub}/links/{link}/status")
async def get_link_status(hub: str, link: str, pw: str = Depends(get_password)):
    return await rpc("GetLinkStatus", {"HubName_Ex_str": hub, "AccountName_utf": link}, admin_password=pw)

class LinkConfig(BaseModel):
    name: str
    hostname: str
    port: int = 5555
    dest_hub: str = "DEFAULT"
    username: str = ""
    password: str = ""
    online: bool = False
    use_encrypt: bool = True
    use_compress: bool = False
    check_server_cert: bool = False
    max_connection: int = 8
    half_connection: bool = False
    no_routing_tracking: bool = True
    require_bridge_routing: bool = True
    no_udp_acceleration: bool = False
    num_retry: int = 4294967295
    retry_interval: int = 15

def _link_params(hub: str, body: LinkConfig) -> dict:
    return {
        "HubName_Ex_str": hub,
        "AccountName_utf": body.name,
        "Hostname_str": body.hostname,
        "Port_u32": body.port,
        "HubName_str": body.dest_hub,
        "AuthType_u32": 3,  # plain password
        "Username_str": body.username,
        "PlainPassword_str": body.password,
        "Online_bool": body.online,
        "CheckServerCert_bool": body.check_server_cert,
        "AddDefaultCA_bool": False,
        "UseEncrypt_u32": 1 if body.use_encrypt else 0,
        "UseCompress_u32": 1 if body.use_compress else 0,
        "HalfConnection_bool": body.half_connection,
        "NoRoutingTracking_bool": body.no_routing_tracking,
        "RequireBridgeRoutingMode_bool": body.require_bridge_routing,
        "RequireMonitorMode_bool": False,
        "MaxConnection_u32": body.max_connection,
        "NumRetry_u32": body.num_retry,
        "RetryInterval_u32": body.retry_interval,
        "AdditionalConnectionInterval_u32": 1,
        "ConnectionDisconnectSpan_u32": 0,
        "NoUdpAcceleration_bool": body.no_udp_acceleration,
    }

@app.post("/api/hubs/{hub}/links")
async def create_link(hub: str, body: LinkConfig, pw: str = Depends(get_password)):
    return await rpc("CreateLink", _link_params(hub, body), admin_password=pw)

@app.put("/api/hubs/{hub}/links/{link}")
async def update_link(hub: str, link: str, body: LinkConfig, pw: str = Depends(get_password)):
    params = _link_params(hub, body)
    params["AccountName_utf"] = link  # keep old name; name in body is the new name for SetLink
    return await rpc("SetLink", params, admin_password=pw)

@app.delete("/api/hubs/{hub}/links/{link}")
async def delete_link(hub: str, link: str, pw: str = Depends(get_password)):
    return await rpc("DeleteLink", {"HubName_str": hub, "AccountName_utf": link}, admin_password=pw)

@app.post("/api/hubs/{hub}/links/{link}/online")
async def link_online(hub: str, link: str, pw: str = Depends(get_password)):
    return await rpc("SetLinkOnline", {"HubName_str": hub, "AccountName_utf": link}, admin_password=pw)

@app.post("/api/hubs/{hub}/links/{link}/offline")
async def link_offline(hub: str, link: str, pw: str = Depends(get_password)):
    return await rpc("SetLinkOffline", {"HubName_str": hub, "AccountName_utf": link}, admin_password=pw)


# --- SoftEther native PACK protocol helpers ---

def _wi(v: int) -> bytes:
    return struct.pack('>I', v)

def _pack_build(elements: list) -> bytes:
    """elements: list of (name, type, values)  type: 0=int,1=data,2=str"""
    out = _wi(len(elements))
    for name, typ, values in elements:
        nb = name.encode('ascii')
        out += _wi(len(nb) + 1) + nb   # element name (len+1, no null)
        out += _wi(typ)
        out += _wi(len(values))
        for v in values:
            if typ == 0:   # int
                out += _wi(v)
            elif typ == 2: # str
                vb = v.encode('ascii')
                out += _wi(len(vb)) + vb
            elif typ == 1: # data
                out += _wi(len(v)) + v
    return out

def _pack_parse(data: bytes) -> dict:
    buf = memoryview(data)
    pos = 0
    def ri():
        nonlocal pos
        v = struct.unpack_from('>I', buf, pos)[0]; pos += 4; return v
    def rs():
        nonlocal pos
        ln = ri(); s = bytes(buf[pos:pos+ln-1]).decode('ascii','replace'); pos += ln-1; return s
    result = {}
    n_elem = ri()
    for _ in range(n_elem):
        name = rs()
        typ = ri(); nv = ri()
        vals = []
        for _ in range(nv):
            if typ == 0:
                vals.append(ri())
            elif typ == 2:
                ln = ri(); vals.append(bytes(buf[pos:pos+ln]).decode('ascii','replace')); pos += ln
            elif typ == 1:
                ln = ri(); vals.append(bytes(buf[pos:pos+ln])); pos += ln
            elif typ == 4:
                v = struct.unpack_from('>Q', buf, pos)[0]; pos += 8; vals.append(v)
        result.setdefault(name, []).extend(vals)
    return result

async def _read_http_body(reader) -> bytes:
    """Read one HTTP response, return its body."""
    hdrs = b""
    while not hdrs.endswith(b"\r\n\r\n"):
        b = await asyncio.wait_for(reader.read(1), timeout=6)
        if not b:
            return b""
        hdrs += b
    clen = 0
    for line in hdrs.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1].strip())
            break
    body = b""
    while len(body) < clen:
        chunk = await asyncio.wait_for(reader.read(clen - len(body)), timeout=6)
        if not chunk:
            break
        body += chunk
    return body

async def _softether_enum_hub(hostname: str, port: int) -> list:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(hostname, port, ssl=ctx), timeout=6
    )
    try:
        # Step 1: POST VPNCONNECT to /vpnsvc/connect.cgi  →  server replies with hello PACK
        connect_body = b"VPNCONNECT"
        writer.write(
            f"POST /vpnsvc/connect.cgi HTTP/1.1\r\nHost: {hostname}\r\n"
            f"Content-Type: application/octet-stream\r\nContent-Length: {len(connect_body)}\r\n"
            f"Connection: Keep-Alive\r\n\r\n".encode() + connect_body
        )
        await writer.drain()
        await _read_http_body(reader)   # discard hello PACK

        # Step 2: POST enum_hub PACK to /vpnsvc/vpn.cgi  →  server replies with hub list
        pack = _pack_build([("method", 2, ["enum_hub"])])
        writer.write(
            f"POST /vpnsvc/vpn.cgi HTTP/1.1\r\nHost: {hostname}\r\n"
            f"Content-Type: application/octet-stream\r\nContent-Length: {len(pack)}\r\n"
            f"Connection: close\r\n\r\n".encode() + pack
        )
        await writer.drain()
        body = await _read_http_body(reader)
    finally:
        writer.close()

    if not body:
        return []
    parsed = _pack_parse(body)
    return [h for h in parsed.get("HubName", []) if not h.startswith("$")]


# --- Remote hub probe ---

class ProbeRequest(BaseModel):
    hostname: str
    port: int = 5555

@app.post("/api/probe/hubs")
async def probe_hubs(body: ProbeRequest, pw: str = Depends(get_password)):
    try:
        hubs = await _softether_enum_hub(body.hostname, body.port)
        return hubs
    except Exception:
        raise HTTPException(status_code=502, detail="Could not reach remote server")


# --- Layer 3 Switch ---

@app.get("/api/l3")
async def list_l3(pw: str = Depends(get_password)):
    result = await rpc("EnumL3Switch", {}, admin_password=pw)
    return result.get("L3SWList", [])

class L3SwitchCreate(BaseModel):
    name: str

@app.post("/api/l3")
async def create_l3(body: L3SwitchCreate, pw: str = Depends(get_password)):
    return await rpc("AddL3Switch", {"Name_str": body.name}, admin_password=pw)

@app.delete("/api/l3/{name}")
async def delete_l3(name: str, pw: str = Depends(get_password)):
    return await rpc("DelL3Switch", {"Name_str": name}, admin_password=pw)

@app.post("/api/l3/{name}/start")
async def start_l3(name: str, pw: str = Depends(get_password)):
    return await rpc("StartL3Switch", {"Name_str": name}, admin_password=pw)

@app.post("/api/l3/{name}/stop")
async def stop_l3(name: str, pw: str = Depends(get_password)):
    return await rpc("StopL3Switch", {"Name_str": name}, admin_password=pw)

@app.get("/api/l3/{name}/interfaces")
async def list_l3_interfaces(name: str, pw: str = Depends(get_password)):
    result = await rpc("EnumL3If", {"Name_str": name}, admin_password=pw)
    return result.get("L3IFList", [])

class L3Interface(BaseModel):
    hub: str
    ip: str
    mask: str

@app.post("/api/l3/{name}/interfaces")
async def add_l3_interface(name: str, body: L3Interface, pw: str = Depends(get_password)):
    return await rpc("AddL3If", {
        "Name_str": name,
        "HubName_str": body.hub,
        "IpAddress_ip": body.ip,
        "SubnetMask_ip": body.mask,
    }, admin_password=pw)

@app.delete("/api/l3/{name}/interfaces/{hub}")
async def del_l3_interface(name: str, hub: str, ip: str, mask: str, pw: str = Depends(get_password)):
    return await rpc("DelL3If", {
        "Name_str": name,
        "HubName_str": hub,
        "IpAddress_ip": ip,
        "SubnetMask_ip": mask,
    }, admin_password=pw)

@app.get("/api/l3/{name}/routes")
async def list_l3_routes(name: str, pw: str = Depends(get_password)):
    result = await rpc("EnumL3Table", {"Name_str": name}, admin_password=pw)
    return result.get("L3Table", [])

class L3Route(BaseModel):
    network: str
    mask: str
    gateway: str
    metric: int = 1

@app.post("/api/l3/{name}/routes")
async def add_l3_route(name: str, body: L3Route, pw: str = Depends(get_password)):
    return await rpc("AddL3Table", {
        "Name_str": name,
        "NetworkAddress_ip": body.network,
        "SubnetMask_ip": body.mask,
        "GatewayAddress_ip": body.gateway,
        "Metric_u32": body.metric,
    }, admin_password=pw)

@app.delete("/api/l3/{name}/routes")
async def del_l3_route(name: str, network: str, mask: str, gateway: str, metric: int = 1, pw: str = Depends(get_password)):
    return await rpc("DelL3Table", {
        "Name_str": name,
        "NetworkAddress_ip": network,
        "SubnetMask_ip": mask,
        "GatewayAddress_ip": gateway,
        "Metric_u32": metric,
    }, admin_password=pw)


# --- Server Settings ---

@app.get("/api/server/ethernet")
async def list_ethernet(pw: str = Depends(get_password)):
    result = await rpc("EnumEthernet", {}, admin_password=pw)
    return result.get("EthList", [])

@app.get("/api/server/bridges")
async def list_bridges(pw: str = Depends(get_password)):
    result = await rpc("EnumLocalBridge", {}, admin_password=pw)
    return result.get("LocalBridgeList", [])

class BridgeCreate(BaseModel):
    hub: str
    device: str
    tap: bool = False

@app.post("/api/server/bridges")
async def create_bridge(body: BridgeCreate, pw: str = Depends(get_password)):
    return await rpc("AddLocalBridge", {
        "HubNameLB_str": body.hub,
        "DeviceName_str": body.device,
        "TapMode_bool": body.tap,
    }, admin_password=pw)

@app.delete("/api/server/bridges/{hub}/{device}")
async def delete_bridge(hub: str, device: str, pw: str = Depends(get_password)):
    return await rpc("DeleteLocalBridge", {
        "HubNameLB_str": hub,
        "DeviceName_str": device,
        "TapMode_bool": False,
    }, admin_password=pw)

@app.get("/api/server/listeners")
async def list_listeners(pw: str = Depends(get_password)):
    result = await rpc("EnumListener", {}, admin_password=pw)
    return result.get("ListenerList", [])

class ListenerCreate(BaseModel):
    port: int

@app.post("/api/server/listeners")
async def create_listener(body: ListenerCreate, pw: str = Depends(get_password)):
    return await rpc("CreateListener", {"Ports_u32": body.port}, admin_password=pw)

@app.put("/api/server/listeners/{port}/enable")
async def enable_listener(port: int, pw: str = Depends(get_password)):
    return await rpc("EnableListener", {"Ports_u32": port, "Enable_bool": True}, admin_password=pw)

@app.put("/api/server/listeners/{port}/disable")
async def disable_listener(port: int, pw: str = Depends(get_password)):
    return await rpc("EnableListener", {"Ports_u32": port, "Enable_bool": False}, admin_password=pw)

@app.delete("/api/server/listeners/{port}")
async def delete_listener(port: int, pw: str = Depends(get_password)):
    return await rpc("DeleteListener", {"Ports_u32": port}, admin_password=pw)

@app.get("/api/server/ipsec")
async def get_ipsec(pw: str = Depends(get_password)):
    return await rpc("GetIPsecServices", {}, admin_password=pw)

class IPsecConfig(BaseModel):
    l2tp_raw: bool = False
    l2tp_ipsec: bool = False
    etherip_ipsec: bool = False
    secret: str = ""
    default_hub: str = ""

@app.put("/api/server/ipsec")
async def set_ipsec(body: IPsecConfig, pw: str = Depends(get_password)):
    return await rpc("SetIPsecServices", {
        "L2TP_Raw_bool": body.l2tp_raw,
        "L2TP_IPsec_bool": body.l2tp_ipsec,
        "EtherIP_IPsec_bool": body.etherip_ipsec,
        "IPsec_Secret_str": body.secret,
        "L2TP_DefaultHub_str": body.default_hub,
    }, admin_password=pw)

@app.get("/api/server/openvpn/sample")
async def openvpn_sample(pw: str = Depends(get_password)):
    result = await rpc("MakeOpenVpnConfigFile", {}, admin_password=pw)
    data = base64.b64decode(result.get("Buffer_bin", ""))
    return StreamingResponse(
        iter([data]),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=\"openvpn_sample.zip\""}
    )

@app.get("/api/server/openvpn")
async def get_openvpn(pw: str = Depends(get_password)):
    return await rpc("GetOpenVpnSstpConfig", {}, admin_password=pw)

class OpenVpnConfig(BaseModel):
    enable_openvpn: bool = False
    openvpn_port_list: str = "1194"
    enable_sstp: bool = False

@app.put("/api/server/openvpn")
async def set_openvpn(body: OpenVpnConfig, pw: str = Depends(get_password)):
    return await rpc("SetOpenVpnSstpConfig", {
        "EnableOpenVPN_bool": body.enable_openvpn,
        "OpenVPNPortList_str": body.openvpn_port_list,
        "EnableSSTP_bool": body.enable_sstp,
    }, admin_password=pw)

@app.get("/api/server/syslog")
async def get_syslog(pw: str = Depends(get_password)):
    return await rpc("GetSysLog", {}, admin_password=pw)

class SyslogConfig(BaseModel):
    save_type: int = 0
    hostname: str = ""
    port: int = 514

@app.put("/api/server/syslog")
async def set_syslog(body: SyslogConfig, pw: str = Depends(get_password)):
    return await rpc("SetSysLog", {
        "SaveType_u32": body.save_type,
        "Hostname_str": body.hostname,
        "Port_u32": body.port,
    }, admin_password=pw)

class PasswordChange(BaseModel):
    password: str

@app.put("/api/server/password")
async def set_server_password(body: PasswordChange, pw: str = Depends(get_password)):
    return await rpc("SetServerPassword", {"PlainTextPassword_str": body.password}, admin_password=pw)


# --- SecureNAT / Virtual NAT+DHCP ---

@app.get("/api/hubs/{hub}/securenat")
async def get_securenat(hub: str, pw: str = Depends(get_password)):
    opt = await rpc("GetSecureNATOption", {"RpcHubName_str": hub}, admin_password=pw)
    try:
        await rpc("GetHubSecureNATStatus", {"HubName_str": hub}, admin_password=pw)
        opt["_enabled"] = True
    except Exception:
        opt["_enabled"] = False
    return opt

class SecureNatConfig(BaseModel):
    enabled: bool = False
    mac: str = ""
    ip: str = "192.168.30.1"
    mask: str = "255.255.255.0"
    use_nat: bool = True
    mtu: int = 1500
    tcp_timeout: int = 60
    udp_timeout: int = 30
    use_dhcp: bool = True
    dhcp_start: str = "192.168.30.10"
    dhcp_end: str = "192.168.30.200"
    dhcp_mask: str = "255.255.255.0"
    dhcp_gateway: str = "192.168.30.1"
    dhcp_dns1: str = "8.8.8.8"
    dhcp_dns2: str = "8.8.4.4"
    dhcp_domain: str = ""
    dhcp_lease: int = 7200
    dhcp_push_routes: str = ""
    save_log: bool = True

@app.put("/api/hubs/{hub}/securenat")
async def set_securenat(hub: str, body: SecureNatConfig, pw: str = Depends(get_password)):
    await rpc("SetSecureNATOption", {
        "RpcHubName_str": hub,
        "MacAddress_bin": body.mac,
        "Ip_ip": body.ip,
        "Mask_ip": body.mask,
        "UseNat_bool": body.use_nat,
        "Mtu_u32": body.mtu,
        "NatTcpTimeout_u32": body.tcp_timeout,
        "NatUdpTimeout_u32": body.udp_timeout,
        "UseDhcp_bool": body.use_dhcp,
        "DhcpLeaseIPStart_ip": body.dhcp_start,
        "DhcpLeaseIPEnd_ip": body.dhcp_end,
        "DhcpSubnetMask_ip": body.dhcp_mask,
        "DhcpGatewayAddress_ip": body.dhcp_gateway,
        "DhcpDnsServerAddress_ip": body.dhcp_dns1,
        "DhcpDnsServerAddress2_ip": body.dhcp_dns2,
        "DhcpDomainName_str": body.dhcp_domain,
        "DhcpExpireTimeSpan_u32": body.dhcp_lease,
        "ApplyDhcpPushRoutes_bool": bool(body.dhcp_push_routes.strip()),
        "DhcpPushRoutes_str": body.dhcp_push_routes.strip(),
        "SaveLog_bool": body.save_log,
    }, admin_password=pw)
    if body.enabled:
        await rpc("EnableSecureNAT", {"HubName_str": hub}, admin_password=pw)
    else:
        await rpc("DisableSecureNAT", {"HubName_str": hub}, admin_password=pw)
    return {"ok": True}

@app.get("/api/hubs/{hub}/securenat/sessions")
async def get_securenat_sessions(hub: str, pw: str = Depends(get_password)):
    try:
        nat = await rpc("EnumNAT", {"HubName_str": hub}, admin_password=pw)
        dhcp = await rpc("EnumDHCP", {"HubName_str": hub}, admin_password=pw)
        return {"nat": nat.get("Log", []), "dhcp": dhcp.get("Log", [])}
    except Exception:
        return {"nat": [], "dhcp": []}


# --- ACL ---

@app.get("/api/hubs/{hub}/acl")
async def list_acl(hub: str, pw: str = Depends(get_password)):
    result = await rpc("EnumAccess", {"HubName_str": hub}, admin_password=pw)
    return result.get("AccessList", [])

class AclRule(BaseModel):
    note: str = "rule"
    active: bool = True
    priority: int = 100
    discard: bool = False
    src_ip: str = "0.0.0.0"
    src_mask: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    dst_mask: str = "0.0.0.0"
    protocol: int = 0
    src_port_start: int = 0
    src_port_end: int = 65535
    dst_port_start: int = 0
    dst_port_end: int = 65535
    src_user: str = ""
    dst_user: str = ""

@app.post("/api/hubs/{hub}/acl")
async def add_acl(hub: str, body: AclRule, pw: str = Depends(get_password)):
    return await rpc("AddAccess", {
        "HubName_str": hub,
        "AccessListSingleElement": {
            "Note_utf":          body.note,
            "Active_bool":       body.active,
            "Priority_u32":      body.priority,
            "Discard_bool":      body.discard,
            "SrcIpAddress_ip":   body.src_ip,
            "SrcSubnetMask_ip":  body.src_mask,
            "DestIpAddress_ip":  body.dst_ip,
            "DestSubnetMask_ip": body.dst_mask,
            "Protocol_u32":      body.protocol,
            "SrcPortStart_u32":  body.src_port_start,
            "SrcPortEnd_u32":    body.src_port_end,
            "DestPortStart_u32": body.dst_port_start,
            "DestPortEnd_u32":   body.dst_port_end,
            "SrcUsername_str":   body.src_user,
            "DestUsername_str":  body.dst_user,
        },
    }, admin_password=pw)

@app.delete("/api/hubs/{hub}/acl/{rule_id}")
async def delete_acl(hub: str, rule_id: int, pw: str = Depends(get_password)):
    return await rpc("DeleteAccess", {"HubName_str": hub, "Id_u32": rule_id}, admin_password=pw)


# --- VPN Azure ---

class AzureConfig(BaseModel):
    enabled: bool

@app.put("/api/server/azure")
async def set_azure(body: AzureConfig, pw: str = Depends(get_password)):
    host = _rpc_host.get()
    port = _rpc_port.get()
    params = {"IsEnabled_bool": body.enabled}
    try:
        return await _rpc_direct("SetVpnAzureClientStatus", params, host, port, pw)
    except HTTPException:
        return await _vpncmd_rpc("SetVpnAzureClientStatus", params, host, port, pw)


# --- Keep-Alive ---

@app.get("/api/server/keepalive")
async def get_keepalive(pw: str = Depends(get_password)):
    return await rpc("GetKeepAlive", {}, admin_password=pw)

class KeepAliveConfig(BaseModel):
    enabled: bool = False
    host: str = "www.google.com"
    port: int = 80
    protocol: int = 0
    interval: int = 50

@app.put("/api/server/keepalive")
async def set_keepalive(body: KeepAliveConfig, pw: str = Depends(get_password)):
    return await rpc("SetKeepAlive", {
        "UseKeepConnect_bool":     body.enabled,
        "KeepConnectHost_str":     body.host,
        "KeepConnectPort_u32":     body.port,
        "KeepConnectProtocol_u32": body.protocol,
        "KeepConnectInterval_u32": body.interval,
    }, admin_password=pw)


# --- Debug: raw vpncmd output (authenticated) ---

class VcmdDebugRequest(BaseModel):
    commands: list[str]

@app.post("/api/debug/vcmd")
async def debug_vcmd(body: VcmdDebugRequest, request: Request, pw: str = Depends(get_password)):
    token = request.cookies.get("vpnweb_sid")
    d = sessions_data.get(token, {})
    host = d.get("host", SOFTETHER_HOST)  # full host with hint for vpncmd
    port = d.get("port", SOFTETHER_PORT)
    if len(body.commands) == 1:
        text = await _vc(host, port, pw, body.commands[0])
    else:
        text = await _vc_in(host, port, pw, body.commands)
    return {"raw": text}

@app.get("/api/debug/hub/{hub}/users")
async def debug_hub_users(hub: str, pw: str = Depends(get_password)):
    host = _rpc_host.get()
    port = _rpc_port.get()
    # Test individual vpncmd call
    try:
        vc_single = await _vpncmd_rpc("EnumUser", {"HubName_str": hub}, host, port, pw)
        vc_single_err = None
    except Exception as e:
        vc_single = None; vc_single_err = repr(e)
    # Test bulk vpncmd (what _bulk_hub_vpncmd does)
    try:
        kv_text, table_text = await asyncio.gather(
            _vc_in(host, port, pw, [f"Hub {hub}", "StatusGet"]),
            _vc_in(host, port, pw, [f"Hub {hub}", "UserList", "GroupList", "SessionList", "CascadeList", "MacTable", "IpTable"]),
        )
        tables = _parse_tables(table_text)
        bulk_tables_keys = list(tables.keys())
        bulk_users_raw = tables.get("users", [])
    except Exception as e:
        table_text = None; tables = {}; bulk_tables_keys = []; bulk_users_raw = []; kv_text = repr(e)
    return {
        "host": host, "port": port, "hub": hub,
        "vcmd_single_err": vc_single_err,
        "vcmd_single_users": vc_single,
        "bulk_kv_text": kv_text,
        "bulk_table_text": table_text,
        "bulk_tables_keys": bulk_tables_keys,
        "bulk_users_raw": bulk_users_raw,
    }

@app.get("/api/debug/ddns")
async def debug_ddns(pw: str = Depends(get_password)):
    host = _rpc_host.get()
    port = _rpc_port.get()
    # JSON-RPC direct attempts (stripped host)
    try:
        rpc_ddns = await _rpc_direct("GetDDnsClientStatus", {}, host, port, pw)
    except Exception as e:
        rpc_ddns = {"_error": str(e)}
    try:
        rpc_azure = await _rpc_direct("GetVpnAzureClientStatus", {}, host, port, pw)
    except Exception as e:
        rpc_azure = {"_error": str(e)}
    # vpncmd raw (full host with hint)
    try:
        vcmd_raw = await _vc_in(host, port, pw, ["DynamicDnsGetStatus", "VpnAzureGetStatus"])
        vcmd_kv  = _vc_kv(vcmd_raw)
    except Exception as e:
        vcmd_raw = str(e); vcmd_kv = {}
    # merged result
    merged = await _get_ddns_azure(host, port, pw)
    return {
        "host": host, "port": port,
        "json_rpc_ddns": rpc_ddns,
        "json_rpc_azure": rpc_azure,
        "vcmd_raw": vcmd_raw,
        "vcmd_kv": vcmd_kv,
        "merged": merged,
    }




# --- SMTP helpers ---

async def _send_invite_email(to_email: str, token: str, username: str, hub: str, base_url: str, expiry_hours: int):
    cfg = _load_config()
    smtp = cfg.get("smtp", {})
    host = smtp.get("host", "")
    if not host:
        raise HTTPException(500, "SMTP not configured — set it in Settings → Email")
    port = int(smtp.get("port", 587))
    smtp_user = smtp.get("username", "")
    smtp_pass = smtp.get("password", "")
    from_addr = smtp.get("from_address", "") or smtp_user
    use_ssl = smtp.get("ssl", False)
    starttls = smtp.get("starttls", True) and not use_ssl

    base = base_url.rstrip('/')
    link = f"{base}/register?token={token}"
    body_text = (
        f"You have been invited to set up VPN access.\n\n"
        f"Username : {username}\n"
        f"Hub      : {hub}\n\n"
        f"Open the link below — the page will guide you through downloading the installer,\n"
        f"programming your YubiKey, and importing your VPN profile:\n\n"
        f"  {link}\n\n"
        f"This link expires in {expiry_hours} hours.\n"
    )
    body_html = f"""<html><body style="font-family:sans-serif;color:#222;max-width:540px">
<p>You have been invited to set up VPN access.</p>
<table style="border-collapse:collapse;margin:.5rem 0">
  <tr><td style="padding:.2rem .8rem .2rem 0"><b>Username</b></td><td>{username}</td></tr>
  <tr><td style="padding:.2rem .8rem .2rem 0"><b>Hub</b></td><td>{hub}</td></tr>
</table>
<p style="margin-top:1.2rem">Click below to get started &mdash; the page will walk you through downloading the installer, programming your YubiKey, and importing your VPN profile.</p>
<p style="margin-top:.8rem"><a href="{link}" style="background:#4f6ef7;color:#fff;padding:.55rem 1.3rem;border-radius:6px;text-decoration:none;display:inline-block;font-size:.95rem;font-weight:600">&#128273; Set Up VPN Access</a></p>
<p style="font-size:.82rem;color:#999;margin-top:1rem">Link expires in {expiry_hours} hours.</p>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"VPN Certificate Registration — {username}@{hub}"
    msg["From"] = from_addr
    msg["To"] = to_email
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    try:
        await aiosmtplib.send(
            msg,
            hostname=host, port=port,
            username=smtp_user or None,
            password=smtp_pass or None,
            use_tls=use_ssl,
            start_tls=starttls,
        )
    except Exception as e:
        raise HTTPException(500, f"Failed to send email: {e}")


# --- SMTP / registration config ---

class SmtpConfigModel(BaseModel):
    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    from_address: str = ""
    starttls: bool = True
    ssl: bool = False

class RegistrationConfigModel(BaseModel):
    token_expiry_hours: int = 72
    base_url: str = ""

@app.get("/api/config/smtp")
async def get_smtp_config(pw: str = Depends(get_password)):
    cfg = _load_config()
    smtp = cfg.get("smtp", {})
    return {**smtp, "password": "***" if smtp.get("password") else ""}

@app.put("/api/config/smtp")
async def set_smtp_config(body: SmtpConfigModel, pw: str = Depends(get_password)):
    async with _config_lock:
        cfg = _load_config()
        existing_pw = cfg.get("smtp", {}).get("password", "")
        d = body.dict()
        if d.get("password") == "***":
            d["password"] = existing_pw
        cfg["smtp"] = d
        _save_json_file(CONFIG_FILE, cfg)
    return {"ok": True}

class SmtpTestBody(BaseModel):
    to: str

@app.post("/api/config/smtp/test")
async def test_smtp_config(body: SmtpTestBody, pw: str = Depends(get_password)):
    if not body.to or "@" not in body.to:
        raise HTTPException(400, "Invalid email address")
    cfg = _load_config()
    smtp = cfg.get("smtp", {})
    if not smtp.get("host"):
        raise HTTPException(400, "SMTP not configured — fill in and save settings first")
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "vpnweb SMTP test"
    msg["From"] = smtp.get("from_address") or smtp.get("username") or "vpnweb"
    msg["To"] = body.to
    msg.attach(MIMEText("This is a test email from vpnweb. SMTP is configured correctly.", "plain"))
    use_ssl  = smtp.get("ssl", False)
    starttls = smtp.get("starttls", True) and not use_ssl
    try:
        await aiosmtplib.send(
            msg,
            hostname=smtp.get("host"), port=int(smtp.get("port", 587)),
            username=smtp.get("username") or None,
            password=smtp.get("password") or None,
            use_tls=use_ssl, start_tls=starttls,
        )
    except Exception as e:
        raise HTTPException(500, f"Send failed: {e}")
    return {"ok": True}

@app.get("/api/config/registration")
async def get_registration_config(pw: str = Depends(get_password)):
    cfg = _load_config()
    return cfg.get("registration", {"token_expiry_hours": 72, "base_url": ""})

@app.put("/api/config/registration")
async def set_registration_config(body: RegistrationConfigModel, pw: str = Depends(get_password)):
    async with _config_lock:
        cfg = _load_config()
        cfg["registration"] = body.dict()
        _save_json_file(CONFIG_FILE, cfg)
    return {"ok": True}


# --- User meta ---

class UserMetaUpdate(BaseModel):
    email: str = ""

@app.get("/api/hubs/{hub}/users/{username}/meta")
async def get_user_meta_ep(hub: str, username: str, pw: str = Depends(get_password)):
    return _load_meta().get(_meta_key(hub, username), {"email": "", "invite_status": None})

@app.put("/api/hubs/{hub}/users/{username}/meta")
async def update_user_meta_ep(hub: str, username: str, body: UserMetaUpdate, pw: str = Depends(get_password)):
    async with _meta_lock:
        meta = _load_meta()
        key = _meta_key(hub, username)
        entry = meta.get(key, {})
        entry["email"] = body.email
        meta[key] = entry
        _save_json_file(USER_META_FILE, meta)
    return {"ok": True}


# --- Registration token helpers ---

def _make_reg_token(hub: str, username: str, host: str, port: int, password: str,
                    cert_params: dict, expiry_hours: int) -> str:
    token = secrets.token_urlsafe(32)
    now = _dt.datetime.utcnow()
    tokens = _load_tokens()
    tokens[token] = {
        "hub": hub, "username": username,
        "host": host, "port": port, "admin_password": password,
        "created_at": now.isoformat(),
        "expires_at": (now + _dt.timedelta(hours=expiry_hours)).isoformat(),
        "used": False, "activated": False,
        **cert_params,
    }
    _save_json_file(TOKENS_FILE, tokens)
    return token

def _validate_token(token: str) -> dict:
    tokens = _load_tokens()
    rec = tokens.get(token)
    if not rec:
        raise HTTPException(404, "Invalid or expired registration link")
    if _dt.datetime.utcnow() > _dt.datetime.fromisoformat(rec["expires_at"]):
        raise HTTPException(410, "Registration link has expired")
    if rec.get("revoked"):
        raise HTTPException(410, "This invitation has been superseded — ask admin for a new link")
    if rec.get("used"):
        raise HTTPException(409, "Certificate already downloaded — ask admin for a new link")
    return rec

_SAFE_NAME_RE = re.compile(r'^[a-zA-Z0-9_\-\.]{1,64}$')

def _cert_path(hub: str, username: str) -> _pl.Path:
    """Return the .p12 path for hub/username, rejecting path-traversal attempts."""
    if not _SAFE_NAME_RE.match(hub) or not _SAFE_NAME_RE.match(username):
        raise HTTPException(400, "Invalid hub or username")
    path = (CERTS_DIR / f"{hub}__{username}.p12").resolve()
    if not str(path).startswith(str(CERTS_DIR.resolve())):
        raise HTTPException(400, "Invalid hub or username")
    return path


# --- Invite endpoint (resend / admin-triggered) ---

class UserInviteBody(BaseModel):
    email: str = ""
    cert_cn: str = ""
    cert_o: str = ""
    cert_ou: str = ""
    cert_c: str = ""
    cert_st: str = ""
    cert_l: str = ""
    cert_days: int = 1825
    cert_key_size: int = 2048
    expiry_hours: Optional[int] = None

@app.post("/api/hubs/{hub}/users/{username}/invite")
async def send_user_invite(hub: str, username: str, body: UserInviteBody,
                           request: Request, pw: str = Depends(get_password)):
    cfg = _load_config()
    reg_cfg = cfg.get("registration", {})
    expiry_hours = body.expiry_hours or reg_cfg.get("token_expiry_hours", 72)
    base_url = reg_cfg.get("base_url", "") or f"http://{request.headers.get('host', 'localhost')}"

    email = body.email
    async with _meta_lock:
        meta = _load_meta()
        key = _meta_key(hub, username)
        entry = meta.get(key, {})
        if email:
            entry["email"] = email
        else:
            email = entry.get("email", "")
        if not email:
            raise HTTPException(400, "No email address for this user — provide one")
        entry["invite_status"] = "pending"
        entry["invite_sent_at"] = _dt.datetime.utcnow().isoformat()
        meta[key] = entry
        _save_json_file(USER_META_FILE, meta)

    host = _rpc_host.get()
    port = _rpc_port.get()
    cert_params = {k: getattr(body, k) for k in (
        "cert_cn", "cert_o", "cert_ou", "cert_c", "cert_st", "cert_l", "cert_days", "cert_key_size"
    )}
    async with _tokens_lock:
        # Revoke any outstanding unused tokens for this user before issuing a new one
        existing = _load_tokens()
        for t, rec in existing.items():
            if rec.get("hub") == hub and rec.get("username") == username and not rec.get("used"):
                rec["revoked"] = True
        _save_json_file(TOKENS_FILE, existing)
        token = _make_reg_token(hub, username, host, port, pw, cert_params, expiry_hours)

    await _send_invite_email(email, token, username, hub, base_url, expiry_hours)
    return {"ok": True}


# --- Public registration endpoints ---

@app.get("/api/register/{token}")
async def get_register_info(token: str):
    rec = _validate_token(token)
    return {
        "username": rec["username"],
        "hub":      rec["hub"],
        "expires_at": rec["expires_at"],
        "activated":  rec.get("activated", False),
    }

@app.post("/api/register/{token}/activate")
async def activate_registration(token: str):
    async with _tokens_lock:
        tokens = _load_tokens()
        rec = tokens.get(token)
        if not rec:
            raise HTTPException(404, "Invalid or expired registration link")
        if _dt.datetime.utcnow() > _dt.datetime.fromisoformat(rec["expires_at"]):
            raise HTTPException(410, "Registration link has expired")
        if rec.get("used"):
            raise HTTPException(409, "Certificate already downloaded — ask admin for a new link")
        if rec.get("activated"):
            return {"ok": True}

        hub      = rec["hub"]
        username = rec["username"]
        host     = rec["host"]
        port     = rec["port"]
        password = rec["admin_password"]

        cn = rec.get("cert_cn", "").strip() or username
        oid = _x509.oid.NameOID
        attrs = [_x509.NameAttribute(oid.COMMON_NAME, cn)]
        if rec.get("cert_o",  "").strip(): attrs.append(_x509.NameAttribute(oid.ORGANIZATION_NAME,        rec["cert_o"].strip()))
        if rec.get("cert_ou", "").strip(): attrs.append(_x509.NameAttribute(oid.ORGANIZATIONAL_UNIT_NAME, rec["cert_ou"].strip()))
        if rec.get("cert_c",  "").strip(): attrs.append(_x509.NameAttribute(oid.COUNTRY_NAME,             rec["cert_c"].strip().upper()[:2]))
        if rec.get("cert_st", "").strip(): attrs.append(_x509.NameAttribute(oid.STATE_OR_PROVINCE_NAME,   rec["cert_st"].strip()))
        if rec.get("cert_l",  "").strip(): attrs.append(_x509.NameAttribute(oid.LOCALITY_NAME,            rec["cert_l"].strip()))

        key_size = rec.get("cert_key_size", 2048)
        if key_size not in (2048, 4096): key_size = 2048
        days = rec.get("cert_days", 1825)

        key = _rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=_crypto_backend())
        subject = issuer = _x509.Name(attrs)
        cert = (
            _x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow())
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=days))
            .sign(key, _hashes.SHA256(), _crypto_backend())
        )
        cert_der = cert.public_bytes(_serialization.Encoding.DER)
        der_b64  = base64.b64encode(cert_der).decode()

        current = await _rpc_direct("GetUser", {"HubName_str": hub, "Name_str": username}, host, port, password)
        await _rpc_direct("SetUser", {
            "HubName_str":   hub,
            "Name_str":      username,
            "RealName_utf":  current.get("Realname_utf") or current.get("RealName_utf") or "",
            "Note_utf":      current.get("Note_utf") or "",
            "GroupName_str": current.get("GroupName_str") or "",
            "AuthType_u32":  2,
            "UserX_bin":     der_b64,
        }, host, port, password)

        p12 = _pkcs12.serialize_key_and_certificates(
            name=cn.encode(), key=key, cert=cert, cas=None,
            encryption_algorithm=_serialization.NoEncryption()
        )
        (_cert_path(hub, username)).write_bytes(p12)

        rec["activated"] = True
        tokens[token] = rec
        _save_json_file(TOKENS_FILE, tokens)

    async with _meta_lock:
        meta = _load_meta()
        entry = meta.get(_meta_key(hub, username), {})
        entry["invite_status"] = "activated"
        meta[_meta_key(hub, username)] = entry
        _save_json_file(USER_META_FILE, meta)

    return {"ok": True}

@app.get("/api/register/{token}/p12")
async def download_register_p12(token: str):
    # Validate and mark used atomically to prevent double-download race
    async with _tokens_lock:
        tokens = _load_tokens()
        rec = tokens.get(token)
        if not rec:
            raise HTTPException(404, "Invalid or expired registration link")
        if _dt.datetime.utcnow() > _dt.datetime.fromisoformat(rec["expires_at"]):
            raise HTTPException(410, "Registration link has expired")
        if rec.get("revoked"):
            raise HTTPException(410, "This invitation has been superseded — ask admin for a new link")
        if rec.get("used"):
            raise HTTPException(409, "Certificate already downloaded — ask admin for a new link")
        if not rec.get("activated"):
            raise HTTPException(400, "Certificate not yet generated — click Generate first")
        tokens[token]["used"] = True
        _save_json_file(TOKENS_FILE, tokens)

    hub = rec["hub"]; username = rec["username"]
    p12_path = _cert_path(hub, username)
    if not p12_path.exists():
        raise HTTPException(404, "Certificate file not found — contact admin")
    async with _meta_lock:
        meta = _load_meta()
        entry = meta.get(_meta_key(hub, username), {})
        entry["invite_status"] = "used"
        meta[_meta_key(hub, username)] = entry
        _save_json_file(USER_META_FILE, meta)
    return Response(
        content=p12_path.read_bytes(),
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f'attachment; filename="{username}_{hub}.p12"'}
    )

@app.get("/api/register/{token}/ovpn/connect")
async def download_register_ovpn_connect(token: str, request: Request):
    # .ovpn has no private key — allow download even after token is marked used
    tokens = _load_tokens()
    rec = tokens.get(token)
    if not rec:
        raise HTTPException(404, "Invalid or expired registration link")
    if _dt.datetime.utcnow() > _dt.datetime.fromisoformat(rec["expires_at"]):
        raise HTTPException(410, "Registration link has expired")
    if not rec.get("activated"):
        raise HTTPException(400, "Certificate not yet generated — click Generate first")
    hub = rec["hub"]; username = rec["username"]
    host = rec["host"]; port = rec["port"]; password = rec["admin_password"]
    ovpn_host = _ovpn_host(request, None)
    try:
        ovpn_cfg = await _rpc_direct("GetOpenVpnSstpConfig", {}, host, port, password)
        ovpn_port = ovpn_cfg.get("OpenVPNPortList_str", "1194").split(",")[0].strip()
    except Exception:
        ovpn_port = "1194"
    try:
        info = await _rpc_direct("GetServerCert", {}, host, port, password)
        ca_pem = _der_to_pem(base64.b64decode(info.get("Cert_bin", "")))
    except Exception:
        raise HTTPException(500, "Could not retrieve server CA certificate")
    ovpn_content = (
        f"client\ndev tun\nproto udp\nremote {ovpn_host} {ovpn_port}\n"
        f"nobind\nremote-cert-tls server\ncipher AES-128-CBC\nverb 3\n\n"
        f"auth-user-pass\n<auth-user-pass>\n{username}@{hub}\n\n</auth-user-pass>\n\n"
        f"<ca>\n{ca_pem}\n</ca>\n"
    )
    return Response(
        content=ovpn_content,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="{username}_{hub}_connect.ovpn"'}
    )


# --- Helper endpoints (used by vpnweb-helper.py via localhost) ---

@app.get("/api/register/{token}/p12-raw")
async def download_register_p12_raw(token: str):
    """Return raw p12 bytes for the helper to program into YubiKey (no used-marking)."""
    tokens = _load_tokens()
    rec = tokens.get(token)
    if not rec:
        raise HTTPException(404, "Invalid registration token")
    if _dt.datetime.utcnow() > _dt.datetime.fromisoformat(rec["expires_at"]):
        raise HTTPException(410, "Registration link has expired")
    if not rec.get("activated"):
        raise HTTPException(400, "Certificate not yet generated")
    hub = rec["hub"]; username = rec["username"]
    p12_path = _cert_path(hub, username)
    if not p12_path.exists():
        raise HTTPException(404, "Certificate file not found")
    return Response(
        content=p12_path.read_bytes(),
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f'attachment; filename="{username}_{hub}.p12"'}
    )


@app.get("/api/register/{token}/installer")
async def download_register_installer(token: str):
    """Serve VPNSetup.exe, gated by a valid registration token."""
    tokens = _load_tokens()
    rec = tokens.get(token)
    if not rec:
        raise HTTPException(404, "Invalid registration token")
    installer = _pl.Path(__file__).parent / "static" / "VPNSetup.exe"
    if not installer.exists():
        raise HTTPException(404, "Installer not available on this server")
    return FileResponse(
        installer,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="VPNSetup.exe"'},
    )


@app.get("/api/register/{token}/puk")
async def get_register_puk(token: str):
    """Return system PUK for the helper to program into YubiKey."""
    tokens = _load_tokens()
    rec = tokens.get(token)
    if not rec:
        raise HTTPException(404, "Invalid registration token")
    if _dt.datetime.utcnow() > _dt.datetime.fromisoformat(rec["expires_at"]):
        raise HTTPException(410, "Registration link has expired")
    if not rec.get("activated"):
        raise HTTPException(400, "Certificate not yet generated")
    cfg = _load_config()
    puk = cfg.get("puk", "12345678")
    return {"puk": puk}


class RegisterCompleteBody(BaseModel):
    pin: str = ""
    serial: str = ""

@app.post("/api/register/{token}/complete")
async def register_complete(token: str, body: RegisterCompleteBody):
    """Called by helper after YubiKey programming — marks token used and sends PIN email."""
    async with _tokens_lock:
        tokens = _load_tokens()
        rec = tokens.get(token)
        if not rec:
            raise HTTPException(404, "Invalid registration token")
        if _dt.datetime.utcnow() > _dt.datetime.fromisoformat(rec["expires_at"]):
            raise HTTPException(410, "Registration link has expired")
        tokens[token]["used"] = True
        if body.serial:
            tokens[token]["yubikey_serial"] = body.serial
        _save_json_file(TOKENS_FILE, tokens)

    hub = rec["hub"]; username = rec["username"]
    async with _meta_lock:
        meta = _load_meta()
        entry = meta.get(_meta_key(hub, username), {})
        entry["invite_status"] = "used"
        if body.serial:
            entry["yubikey_serial"] = body.serial
        meta[_meta_key(hub, username)] = entry
        _save_json_file(USER_META_FILE, meta)

    # Record PUK in YubiKey registry (history per serial)
    if body.serial:
        cfg = _load_config()
        puk_used = cfg.get("puk", "12345678")
        async with _registry_lock:
            reg = _load_registry()
            serial_key = str(body.serial)
            if serial_key not in reg:
                reg[serial_key] = []
            reg[serial_key].append({
                "puk":           puk_used,
                "programmed_at": _dt.datetime.utcnow().isoformat(),
                "username":      username,
                "hub":           hub,
            })
            _save_json_file(REGISTRY_FILE, reg)

    # Auto-backup via rclone (best-effort)
    backup_cfg = _load_config().get("backup", {})
    if backup_cfg.get("auto_backup", True) and backup_cfg.get("rclone_remote"):
        try:
            await _run_rclone_backup()
        except Exception:
            pass

    # Send PIN email (best-effort — don't fail registration if email fails)
    if body.pin:
        email = _load_meta().get(_meta_key(hub, username), {}).get("email", "")
        if email:
            try:
                await _send_pin_email(email, username, hub, body.pin, body.serial)
            except Exception:
                pass

    return {"ok": True}


async def _send_pin_email(to_email: str, username: str, hub: str, pin: str, serial: str):
    cfg = _load_config()
    smtp = cfg.get("smtp", {})
    host = smtp.get("host", "")
    if not host:
        return
    port = int(smtp.get("port", 587))
    smtp_user = smtp.get("username", "")
    smtp_pass = smtp.get("password", "")
    from_addr = smtp.get("from_address", "") or smtp_user
    use_ssl = smtp.get("ssl", False)
    starttls = smtp.get("starttls", True) and not use_ssl

    serial_line = f"\nYubiKey serial: {serial}" if serial else ""
    body_text = (
        f"Your VPN YubiKey has been programmed successfully.\n\n"
        f"Username : {username}\n"
        f"Hub      : {hub}{serial_line}\n\n"
        f"Your YubiKey PIN is: {pin}\n\n"
        f"Keep this PIN safe — you will need it every time you connect to the VPN.\n"
        f"Do not share it with anyone.\n"
    )
    serial_row = f'<tr><td style="padding:.2rem .8rem .2rem 0"><b>YubiKey serial</b></td><td>{serial}</td></tr>' if serial else ""
    body_html = f"""<html><body style="font-family:sans-serif;color:#222">
<p>Your VPN YubiKey has been programmed successfully.</p>
<table style="border-collapse:collapse;margin:.5rem 0">
  <tr><td style="padding:.2rem .8rem .2rem 0"><b>Username</b></td><td>{username}</td></tr>
  <tr><td style="padding:.2rem .8rem .2rem 0"><b>Hub</b></td><td>{hub}</td></tr>
  {serial_row}
</table>
<p>Your YubiKey PIN is: <strong style="font-size:1.2rem;letter-spacing:.1em">{pin}</strong></p>
<p style="font-size:.85rem;color:#666">Keep this PIN safe — you will need it every time you connect to the VPN.<br>
Do not share it with anyone.</p>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Your VPN YubiKey PIN — {username}@{hub}"
    msg["From"] = from_addr
    msg["To"] = to_email
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    await aiosmtplib.send(
        msg,
        hostname=host, port=port,
        username=smtp_user or None,
        password=smtp_pass or None,
        use_tls=use_ssl,
        start_tls=starttls,
    )


# --- System PUK config ---

@app.get("/api/config/puk")
async def get_puk_config(pw: str = Depends(get_password)):
    cfg = _load_config()
    return {"puk": cfg.get("puk", "12345678")}

@app.put("/api/config/puk")
async def set_puk_config(body: dict, pw: str = Depends(get_password)):
    puk = str(body.get("puk", "")).strip()
    if not puk.isdigit() or not (6 <= len(puk) <= 8):
        raise HTTPException(400, "PUK must be 6–8 digits")
    async with _config_lock:
        cfg = _load_config()
        cfg["puk"] = puk
        _save_json_file(CONFIG_FILE, cfg)
    return {"ok": True}

@app.get("/api/config/yubikeys")
async def get_yubikey_registry(pw: str = Depends(get_password)):
    """Return the YubiKey registry: per-serial history of programmed PUKs and users."""
    reg = _load_registry()
    # Return as a list sorted by most recently programmed first
    result = []
    for serial, history in reg.items():
        if not history:
            continue
        last = history[-1]
        result.append({
            "serial":       serial,
            "last_user":    f"{last['username']}@{last['hub']}",
            "username":     last["username"],
            "hub":          last["hub"],
            "last_puk":     last["puk"],
            "last_at":      last["programmed_at"],
            "history":      history,
        })
    result.sort(key=lambda x: x["last_at"], reverse=True)
    return result


# --- rclone backup ---

async def _run_rclone_backup():
    """Copy yubikey_registry.json to the configured rclone remote. Raises on error."""
    cfg = _load_config()
    remote = cfg.get("backup", {}).get("rclone_remote", "").strip()
    if not remote:
        raise ValueError("No rclone remote configured")
    rclone = _shutil.which("rclone")
    if not rclone:
        raise RuntimeError("rclone not found — install it: https://rclone.org/install/")

    def _sync():
        return _subprocess.run(
            [rclone, "copy", str(REGISTRY_FILE), remote],
            capture_output=True, text=True, timeout=60,
        )

    result = await asyncio.to_thread(_sync)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"rclone exited with code {result.returncode}")

    async with _config_lock:
        cfg2 = _load_config()
        bk = cfg2.setdefault("backup", {})
        bk["last_backup_at"]     = _dt.datetime.utcnow().isoformat()
        bk["last_backup_status"] = "ok"
        _save_json_file(CONFIG_FILE, cfg2)


class BackupConfigModel(BaseModel):
    rclone_remote: str  = ""
    auto_backup:   bool = True

@app.get("/api/config/backup")
async def get_backup_config(pw: str = Depends(get_password)):
    cfg = _load_config()
    bk  = cfg.get("backup", {})
    rclone_found = bool(_shutil.which("rclone"))
    return {
        "rclone_remote":      bk.get("rclone_remote", ""),
        "auto_backup":        bk.get("auto_backup", True),
        "last_backup_at":     bk.get("last_backup_at", ""),
        "last_backup_status": bk.get("last_backup_status", ""),
        "rclone_found":       rclone_found,
    }

_RCLONE_REMOTE_RE = re.compile(r'^[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-/. ]*$')

@app.put("/api/config/backup")
async def set_backup_config(body: BackupConfigModel, pw: str = Depends(get_password)):
    remote = body.rclone_remote.strip()
    if remote and not _RCLONE_REMOTE_RE.match(remote):
        raise HTTPException(400, "Invalid rclone remote — expected format: remotename:path/to/folder")
    async with _config_lock:
        cfg = _load_config()
        bk  = cfg.setdefault("backup", {})
        bk["rclone_remote"] = remote
        bk["auto_backup"]   = body.auto_backup
        _save_json_file(CONFIG_FILE, cfg)
    return {"ok": True}

@app.post("/api/config/backup/run")
async def trigger_backup(pw: str = Depends(get_password)):
    try:
        await _run_rclone_backup()
    except Exception as e:
        async with _config_lock:
            cfg = _load_config()
            cfg.setdefault("backup", {})["last_backup_status"] = f"error: {e}"
            _save_json_file(CONFIG_FILE, cfg)
        raise HTTPException(500, str(e))
    return {"ok": True}


# --- Serve frontend ---

@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(os.path.dirname(__file__), "static/index.html")) as f:
        return f.read()

@app.get("/register", response_class=HTMLResponse)
async def register_page():
    with open(os.path.join(os.path.dirname(__file__), "static/register.html")) as f:
        return f.read()

app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
