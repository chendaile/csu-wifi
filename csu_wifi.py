#!/usr/bin/env python3
"""
CSU (Central South University) Campus WiFi Authentication CLI
=============================================================
Supports Dr.COM Web Portal authentication for CSU campus network.

Commands:
  connect  - Authenticate to campus WiFi
  logout   - Cancel authentication
  status   - Check current connection status
  daemon   - Auto-reconnect when disconnected
  autostart - Manage Windows autostart for daemon mode
"""

import argparse
import json
import os
import platform
import re
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import requests
import urllib3

# Suppress insecure HTTPS warnings (portal uses self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Constants -----------------------------------------------------------------
CONFIG_DIR = Path.home() / ".csu-wifi"
CONFIG_FILE = CONFIG_DIR / "config.json"

PORTAL_HOST = "portal.csu.edu.cn"
AUTH_SERVER = "10.1.1.1"
AUTH_PORT_HTTP = 801     # eportal HTTP port
AUTH_PORT_HTTPS = 802    # eportal HTTPS port
VERSION = "1.1.0"
AUTOSTART_TASK_NAME = "CSU WiFi Daemon"
AUTOSTART_STARTUP_SCRIPT = "csu-wifi-daemon.cmd"
AUTOSTART_SYSTEMD_SERVICE = "csu-wifi.service"
PORTAL_ONLINE_LIST_URL = f"https://{PORTAL_HOST}:{AUTH_PORT_HTTPS}/eportal/portal/online_list"
PORTAL_LOGOUT_URL = f"https://{PORTAL_HOST}:{AUTH_PORT_HTTPS}/eportal/portal/logout"
PORTAL_CONFIG_URL = f"https://{PORTAL_HOST}:{AUTH_PORT_HTTPS}/eportal/portal/page/loadConfig"
PORTAL_DRCOM_LOGOUT_URL = (
    f"http://{PORTAL_HOST}:{AUTH_PORT_HTTP}/eportal/?c=ACSetting&a=Logout&ver=1.0&url=drappall"
)

ISP_OPTIONS = {
    "campus":  {"suffix": "",           "name": "校园网"},
    "telecom": {"suffix": "@telecomn",  "name": "中国电信"},
    "unicom":  {"suffix": "@unicomn",   "name": "中国联通"},
    "mobile":  {"suffix": "@cmccn",     "name": "中国移动"},
}

# URL to detect if we're behind captive portal
CHECK_URLS = [
    "http://connect.rom.miui.com/generate_204",  # Android/MIUI captive detection
    "http://www.msftconnecttest.com/connecttest.txt",  # Windows captive detection
    "https://www.baidu.com",
]


# --- Helpers --------------------------------------------------------------------

def get_session():
    """Create a requests session with common headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate",
    })
    session.verify = False
    return session


def load_config():
    """Load saved credentials from config file."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def save_config(config):
    """Save credentials to config file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def parse_json_like(text):
    """Parse JSON, JSONP, or a JSON object embedded in portal responses."""
    stripped = text.strip()
    if not stripped:
        raise ValueError("empty response")
    if stripped.startswith("{") or stripped.startswith("["):
        return json.loads(stripped)

    jsonp_match = re.search(r"^[\w$]+\((.*)\)\s*;?\s*$", stripped, re.DOTALL)
    if jsonp_match:
        return json.loads(jsonp_match.group(1))

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        return json.loads(stripped[start:end + 1])

    raise ValueError("response does not contain JSON")


def _find_session_list(value):
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in (
            "list",
            "online_list",
            "onlineList",
            "online_sessions",
            "onlineSessions",
            "rows",
            "data",
            "result",
        ):
            found = _find_session_list(value.get(key))
            if found is not None:
                return found
    return None


def fetch_portal_config(session):
    """Fetch the current portal page config used by the live JavaScript."""
    try:
        response = session.get(PORTAL_CONFIG_URL, timeout=8)
        response.raise_for_status()
        data = parse_json_like(response.text)
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            return data["data"]
    except Exception:
        pass
    return {}


def portal_status(session=None, timeout=6):
    """
    Query the campus portal's online session list.
    Returns a dict with campus_auth: logged_in | logged_out | unknown.
    """
    close_session = False
    if session is None:
        session = get_session()
        close_session = True
    try:
        response = session.get(PORTAL_ONLINE_LIST_URL, timeout=timeout)
        response.raise_for_status()
        data = parse_json_like(response.text)
    except Exception as exc:
        return {
            "campus_auth": "unknown",
            "campus_sessions": None,
            "online_sessions": [],
            "message": f"failed to query online_list: {exc}",
        }
    finally:
        if close_session:
            session.close()

    sessions = _find_session_list(data)
    if sessions is not None:
        return {
            "campus_auth": "logged_in" if sessions else "logged_out",
            "campus_sessions": len(sessions),
            "online_sessions": sessions,
            "message": str(data.get("msg") or "online_list queried") if isinstance(data, dict) else "online_list queried",
        }

    if isinstance(data, dict):
        result = data.get("result")
        message = str(data.get("msg") or data.get("message") or "online_list queried")
        if result == 0:
            return {
                "campus_auth": "logged_out",
                "campus_sessions": 0,
                "online_sessions": [],
                "message": message,
            }
        if "online_session" in json.dumps(data, ensure_ascii=False):
            return {
                "campus_auth": "logged_in",
                "campus_sessions": 1,
                "online_sessions": [],
                "message": message,
            }
        return {
            "campus_auth": "unknown",
            "campus_sessions": None,
            "online_sessions": [],
            "message": message,
        }

    return {
        "campus_auth": "unknown",
        "campus_sessions": None,
        "online_sessions": [],
        "message": "unexpected online_list response",
    }


def print_portal_status(status, prefix="  ", include_message=False):
    print(f"{prefix}campus_auth: {status['campus_auth']}")
    if status.get("campus_sessions") is not None:
        print(f"{prefix}campus_sessions: {status['campus_sessions']}")
    if include_message and status.get("message"):
        print(f"{prefix}portal_message: {status['message']}")


def looks_like_already_logged_in_message(message):
    if not message:
        return False
    text = str(message)
    return any(token in text for token in ("错误代码99", "IP已经在线", "已经在线", "终端IP已经在线"))


def get_local_ip():
    """Get the local IP address used for WLAN."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.1.1.1", 801))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def get_local_mac():
    """Get the MAC address of the active network interface."""
    try:
        import uuid
        mac = uuid.getnode()
        return "{:012x}".format(mac)
    except Exception:
        return "000000000000"


def fetch_portal_info(session):
    """Fetch IP, MAC, and other info from the portal page."""
    info = {"ip": "", "ipv6": "", "mac": "", "ac_ip": "", "ac_name": "", "vlan": ""}
    try:
        r = session.get(f"https://{PORTAL_HOST}/a79.htm", timeout=8)
        content = r.text

        for key, pattern in [
            ("ip", r"ss5=['\"]([^'\"]+)['\"]"),
            ("ipv6", r"myv6ip=['\"]([^'\"]+)['\"]"),
            ("mac", r"ss1=['\"]([^'\"]+)['\"]"),
            ("ac_ip", r"ss6=['\"]([^'\"]+)['\"]"),
            ("ac_name", r"AC=['\"]([^'\"]*)['\"]"),
            ("vlan", r"vlanid=['\"]([^'\"]+)['\"]"),
            ("v4serip", r"v4serip=['\"]([^'\"]+)['\"]"),
        ]:
            m = re.search(pattern, content)
            if m:
                info[key] = m.group(1).strip()
    except requests.RequestException:
        pass

    # Fallback to local detection
    if not info.get("ip"):
        info["ip"] = get_local_ip()
    if not info.get("mac") or info["mac"] == "000000000000":
        info["mac"] = get_local_mac()
    if not info.get("ac_ip"):
        info["ac_ip"] = AUTH_SERVER

    return info


# --- Connectivity Detection ----------------------------------------------------

CAPTIVE_PORTAL_MARKERS = [
    "portal.csu.edu.cn",
    "/a79.htm",
    "Dr.COMWebLogin",
]

def is_online(session=None, timeout=5):
    """
    Check if already authenticated.
    A captive portal intercepts HTTP and redirects to login page.
    We detect this by NOT following redirects and checking for 3xx.
    Returns (online: bool, detail: str)
    """
    close_session = False
    if session is None:
        session = get_session()
        close_session = True
    try:
        for url in CHECK_URLS:
            try:
                r = session.get(url, timeout=timeout, allow_redirects=False)

                # If redirected (3xx) -> captive portal is intercepting
                if 300 <= r.status_code < 400:
                    location = r.headers.get("Location", "").lower()
                    for marker in CAPTIVE_PORTAL_MARKERS:
                        if marker.lower() in location:
                            return False, "Captive portal detected (redirect to portal)"
                    # Any redirect on HTTP likely means captive portal
                    if url.startswith("http://"):
                        return False, f"Redirected (status {r.status_code}), likely captive portal"
                    # HTTPS redirect is unusual, could be captive too
                    return False, "Redirected from HTTPS, likely captive portal"

                # 204 No Content -> no captive portal (Android/MIUI check)
                if r.status_code == 204:
                    return True, "Online (generate_204 returned 204)"

                # 200 with actual content -> online
                if r.status_code == 200:
                    text_lower = r.text.lower()
                    # Check portal markers in body (defense in depth)
                    for marker in CAPTIVE_PORTAL_MARKERS:
                        if marker.lower() in text_lower:
                            return False, "Captive portal detected (portal page in response)"
                    # Good response, not a portal page -> online
                    return True, "Online"

            except requests.ConnectionError:
                continue
            except requests.RequestException:
                continue

        return False, "Cannot reach internet"
    finally:
        if close_session:
            session.close()


# --- Login ----------------------------------------------------------------------

def _login_request(session, url, params, method="get"):
    """Send a login request and parse JSONP/JSON response."""
    try:
        # Add JSONP callback only for endpoints that expect it
        if "portal/login" in url:
            params["callback"] = "dr" + str(int(time.time() * 1000) % 100000 + 1000)
        if method == "get":
            r = session.get(url, params=params, timeout=15)
        else:
            r = session.post(url, data=params, timeout=15)
        text = r.text

        try:
            resp = parse_json_like(text)
            if isinstance(resp, dict):
                result = resp.get("result")
                if result == 1 or result == "ok":
                    return True, resp
                elif result == 0:
                    return False, resp
                return None, resp
        except (json.JSONDecodeError, ValueError):
            pass

        if "Dr.COMWebLoginID_3" in text:
            return True, {"msg": "Login successful"}
        elif "Dr.COMWebLoginID_2" in text:
            return False, {"msg": "Login failed (Dr.COMWebLoginID_2)"}
        return None, {"raw": text[:500]}
    except requests.RequestException as e:
        return None, {"error": str(e)}


def get_local_ipv6():
    """Get the IPv6 address used for the default route."""
    try:
        import subprocess
        result = None
        if platform.system() == "Windows":
            result = subprocess.run(
                ["netsh", "interface", "ipv6", "show", "addresses"],
                capture_output=True, text=True, encoding="utf-8", errors="replace"
            )
        else:
            result = subprocess.run(
                ["ip", "-6", "addr", "show"],
                capture_output=True, text=True, encoding="utf-8", errors="replace"
            )
        if result and result.stdout:
            for line in result.stdout.splitlines():
                line = line.strip()
                if any(prefix in line for prefix in ["2001:", "2409:", "2408:", "240e:"]):
                    parts = line.split()
                    for p in parts:
                        if ":" in p and not p.startswith("fe80"):
                            return p.split("%")[0]
    except Exception:
        pass
    return ""


def do_login(session, username, password, isp="campus"):
    """
    Perform WiFi authentication using the current CSU portal flow.
    Returns (success: bool, message: str)
    """
    isp_config = ISP_OPTIONS.get(isp, ISP_OPTIONS["campus"])
    suffix = isp_config["suffix"]
    account = username + suffix

    info = fetch_portal_info(session)
    client_ip = info.get("ip", get_local_ip())
    client_mac = info.get("mac", get_local_mac())
    client_ipv6 = get_local_ipv6()

    if not client_ip:
        return False, "Cannot determine local IP address. Are you connected to CSU WiFi?"

    # The live CSU page calls Custom/online_data first, then portal/login.
    custom_url = f"https://{PORTAL_HOST}:{AUTH_PORT_HTTPS}/eportal/portal/Custom/online_data"
    custom_data = {
        "username": username,
        "password": password,
        "ip": client_ip,
        "wlan_ac_name": "",
        "wlan_ac_ip": AUTH_SERVER,  # 10.1.1.1 from page var ss6
        "mac": client_mac,
        "login_method": "1",
    }
    _login_request(session, custom_url, custom_data, method="get")

    base_data = {
        "login_method": "1",
        "user_password": password,
        "wlan_user_ip": client_ip,
        "wlan_user_ipv6": client_ipv6,
        "wlan_user_mac": client_mac,
        "wlan_ac_ip": AUTH_SERVER,  # 10.1.1.1 from page var ss6
        "wlan_ac_name": "",
        "jsVersion": "4.X",
        "terminal_type": "1",
        "lang": "zh-cn",
    }

    url = f"https://{PORTAL_HOST}:{AUTH_PORT_HTTPS}/eportal/portal/login"
    data = dict(base_data, user_account=account)
    ok, resp = _login_request(session, url, data, method="get")
    if ok is True:
        return True, str(resp.get("msg") or "Authentication completed")

    last_login_msg = str(resp.get("msg") or resp.get("error") or resp)

    if client_ipv6:
        base_data["wlan_user_ipv6"] = ""
        data = dict(base_data, user_account=account)
        ok, resp = _login_request(session, url, data, method="get")
        if ok is True:
            return True, str(resp.get("msg") or "Authentication completed")
        last_login_msg = str(resp.get("msg") or resp.get("error") or resp)

    return False, f"Login failed: {last_login_msg}"


# --- Logout ---------------------------------------------------------------------

def _logout_request(session, url, params=None):
    """Send a logout request and parse the portal response."""
    request_params = dict(params or {})
    if "/eportal/portal/logout" in url:
        request_params.setdefault("callback", "dr" + str(int(time.time() * 1000) % 100000 + 1000))
    try:
        response = session.get(url, params=request_params or None, timeout=15, allow_redirects=True)
    except requests.RequestException as exc:
        return None, f"request failed: {exc}"

    try:
        data = parse_json_like(response.text)
    except (json.JSONDecodeError, ValueError):
        text = response.text.lower()
        if "logout succeed" in text or "success" in text:
            return True, "logout request completed"
        return None, response.text[:200].strip() or f"HTTP {response.status_code}"

    if isinstance(data, dict):
        message = str(data.get("msg") or data.get("message") or "logout request completed")
        result = data.get("result")
        if result in (1, "1", "ok", True):
            return True, message
        if result in (0, "0", False):
            return False, message
        return None, message
    return None, "unexpected logout response"


def do_logout(session):
    """
    Cancel WiFi authentication.
    Returns (success: bool, message: str)
    """
    config = fetch_portal_config(session)
    info = fetch_portal_info(session)
    logout_data = {
        "login_method": config.get("login_method") or "1",
        "user_account": "drcom",
        "user_password": "123",
        "ac_logout": config.get("ac_logout") or "1",
        "register_mode": config.get("register_mode") or "1",
        "wlan_user_ip": info.get("ip") or get_local_ip(),
        "wlan_user_ipv6": info.get("ipv6") or "",
        "wlan_vlan_id": info.get("vlan") or "0",
        "wlan_user_mac": info.get("mac") or get_local_mac(),
        "wlan_ac_ip": info.get("ac_ip") or AUTH_SERVER,
        "wlan_ac_name": info.get("ac_name") or "",
        "jsVersion": "4.X",
    }

    message = "logout request completed"
    after = portal_status(session)
    initial_session_ids = {
        str(item.get("online_session"))
        for item in (after.get("online_sessions") or [])
        if item.get("online_session") is not None
    }
    saw_logged_out = after["campus_auth"] == "logged_out"

    for _ in range(6):
        candidates = [(PORTAL_LOGOUT_URL, logout_data)]
        sessions = after.get("online_sessions") or []
        if sessions:
            online_session = sessions[0].get("online_session")
            exit_id = sessions[0].get("exit_id") or "1"
            if online_session:
                candidates.append((PORTAL_LOGOUT_URL, {"online_session": online_session, "exit_id": exit_id}))
        candidates.append((PORTAL_LOGOUT_URL, {}))

        recognized = False
        for logout_url, params in candidates:
            ok, msg = _logout_request(session, logout_url, params)
            if ok is True:
                recognized = True
                message = msg
                break
            if ok is False:
                message = msg

        if not recognized:
            ok, msg = _logout_request(session, PORTAL_DRCOM_LOGOUT_URL)
            if ok is True:
                message = msg
            else:
                return False, f"Logout request failed: {msg}"

        # CSU may briefly recreate a session after Radius logout. Treat logout
        # as successful only after the empty online_list state stays stable.
        time.sleep(1)
        after = portal_status(session)
        if after["campus_auth"] == "logged_out":
            saw_logged_out = True
            time.sleep(2)
            confirm = portal_status(session)
            if confirm["campus_auth"] == "logged_out":
                return True, message
            after = confirm

    if after["campus_auth"] == "logged_in":
        current_session_ids = {
            str(item.get("online_session"))
            for item in (after.get("online_sessions") or [])
            if item.get("online_session") is not None
        }
        if saw_logged_out or (initial_session_ids and not current_session_ids.issubset(initial_session_ids)):
            return (
                False,
                f"{message}; a new campus session was recreated after logout. "
                "Close any CSU portal/logout browser pages or disable portal auto-login, then run logout again.",
            )
        return False, f"{message}; online_list still shows logged_in"
    return False, f"{message}; cannot verify logout: {after.get('message')}"


# --- Status ---------------------------------------------------------------------

def do_status(session):
    """Check and display connection status."""
    portal = portal_status(session)
    online, detail = is_online(session)

    if online:
        status = "online"
        message = detail
    elif portal["campus_auth"] == "logged_in":
        status = "portal_logged_in_probe_failed"
        message = f"campus authentication is active, but internet probe failed: {detail}"
    elif portal["campus_auth"] == "logged_out":
        status = "wifi_connected_auth_required"
        message = "campus authentication is logged out"
    else:
        status = "offline"
        message = detail

    print(f"status: {status}")
    print(f"internet_probe: {'online' if online else 'offline'}")
    print_portal_status(portal, include_message=portal["campus_auth"] == "unknown")
    if not online:
        print(f"detail: {message}")
    return online or portal["campus_auth"] == "logged_in"


# --- CLI ------------------------------------------------------------------------

def cmd_connect(args):
    """Handle connect command."""
    username = args.username
    password = args.password
    isp = args.isp

    # Load from config if not provided
    if not username or not password or not isp:
        config = load_config()
        if not username:
            username = config.get("username", "")
        if not password:
            password = config.get("password", "")
        if not isp:
            isp = config.get("isp", "")

    session = get_session()

    if not username:
        print("Error: Username is required. Use --username or connect once with --save.")
        sys.exit(1)
    if not password:
        print("Error: Password is required. Use --password or connect once with --save.")
        sys.exit(1)
    if not isp:
        print("Error: ISP is required. Use --isp campus|telecom|unicom|mobile or save it with --save.")
        sys.exit(1)
    if isp not in ISP_OPTIONS:
        print(f"Error: Invalid ISP '{isp}'. Options: {', '.join(ISP_OPTIONS.keys())}")
        sys.exit(1)

    current = portal_status(session)
    if current["campus_auth"] == "logged_in":
        print("Already authenticated:")
        print_portal_status(current)
        if args.save:
            config = load_config()
            config["username"] = username
            config["password"] = password
            config["isp"] = isp
            save_config(config)
            print(f"Saved credentials to {CONFIG_FILE}")
        return

    print("Authenticating to CSU WiFi...")
    success, message = do_login(session, username, password, isp)

    if success:
        print(f"SUCCESS: {message}")
        # Save credentials if requested
        if args.save:
            config = load_config()
            config["username"] = username
            config["password"] = password
            config["isp"] = isp
            save_config(config)
            print(f"Saved credentials to {CONFIG_FILE}")
    elif looks_like_already_logged_in_message(message):
        current = portal_status(session)
        if current["campus_auth"] == "logged_in":
            print("Already authenticated:")
            print_portal_status(current)
            if args.save:
                config = load_config()
                config["username"] = username
                config["password"] = password
                config["isp"] = isp
                save_config(config)
                print(f"Saved credentials to {CONFIG_FILE}")
        else:
            print(f"FAILED: {message}")
            sys.exit(1)
    else:
        print(f"FAILED: {message}")
        sys.exit(1)


def cmd_logout(args):
    """Handle logout command."""
    session = get_session()

    print("Cancelling authentication...")
    success, message = do_logout(session)

    if success:
        print(f"SUCCESS: {message}")
    else:
        print(f"FAILED: {message}")
        sys.exit(1)


def cmd_status(args):
    """Handle status command."""
    session = get_session()
    do_status(session)


def cmd_daemon(args):
    """Handle daemon reconnect command."""
    username = args.username
    password = args.password
    isp = args.isp
    interval = args.interval

    if not username or not password or not isp:
        config = load_config()
        if not username:
            username = config.get("username", "")
        if not password:
            password = config.get("password", "")
        if not isp:
            isp = config.get("isp", "")

    if not username:
        print("Error: Username is required.")
        sys.exit(1)
    if not password:
        print("Error: Password is required.")
        sys.exit(1)
    if not isp:
        print("Error: ISP is required. Use --isp campus|telecom|unicom|mobile or save it with connect --save.")
        sys.exit(1)
    if isp not in ISP_OPTIONS:
        print(f"Error: Invalid ISP '{isp}'. Options: {', '.join(ISP_OPTIONS.keys())}")
        sys.exit(1)

    print("CSU WiFi daemon started")
    print(f"  ISP     : {ISP_OPTIONS.get(isp, ISP_OPTIONS['campus'])['name']}")
    print(f"  Interval: {interval}s")
    print("  Press Ctrl+C to stop.\n")

    running = True

    def signal_handler(sig, frame):
        nonlocal running
        running = False
        print("\nStopping auto-reconnect...")

    signal.signal(signal.SIGINT, signal_handler)

    session = get_session()
    consecutive_failures = 0

    while running:
        online, detail = is_online(session)
        timestamp = time.strftime("%H:%M:%S")

        if online:
            if consecutive_failures > 0:
                print(f"[{timestamp}] Reconnected!")
                consecutive_failures = 0
        else:
            consecutive_failures += 1
            print(f"[{timestamp}] Offline ({detail}, failure #{consecutive_failures}), authenticating...")
            success, message = do_login(session, username, password, isp)
            if success:
                print(f"[{timestamp}]   Login: {message}")
                consecutive_failures = 0
            else:
                print(f"[{timestamp}]   Login failed: {message}")
                # Exponential backoff on repeated failures
                wait = min(interval * (1.5 ** (consecutive_failures - 1)), 300)
                print(f"[{timestamp}]   Waiting {int(wait)}s before retry...")
                time.sleep(wait)
                continue

        time.sleep(interval)


# --- Autostart ------------------------------------------------------------------

def get_daemon_command_parts(interval=30):
    """Build the daemon command as argv parts for the current runtime."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "daemon", "-i", str(interval)]
    return [sys.executable, str(Path(__file__).resolve()), "daemon", "-i", str(interval)]


def get_daemon_command(interval=30):
    """Build the daemon command string for the current platform."""
    parts = get_daemon_command_parts(interval)
    if platform.system() == "Windows":
        return subprocess.list2cmdline(parts)
    return shlex.join(parts)


def get_startup_script_path():
    appdata = os.environ.get("APPDATA")
    if not appdata:
        print("Error: APPDATA is not set; cannot locate the Windows Startup folder.")
        sys.exit(1)
    return (
        Path(appdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / AUTOSTART_STARTUP_SCRIPT
    )


def get_systemd_service_path():
    return Path.home() / ".config" / "systemd" / "user" / AUTOSTART_SYSTEMD_SERVICE


def default_autostart_method():
    system = platform.system()
    if system == "Windows":
        return "startup"
    if system == "Linux":
        return "systemd"
    print(f"Error: autostart is not supported on {system}.")
    sys.exit(1)


def resolve_autostart_method(method):
    return default_autostart_method() if method == "auto" else method


def ensure_method_supported(method):
    system = platform.system()
    if method in ("startup", "task") and system != "Windows":
        print(f"Error: --method {method} is Windows-only.")
        sys.exit(1)
    if method == "systemd" and system != "Linux":
        print("Error: --method systemd is Linux-only.")
        sys.exit(1)


def run_schtasks(args):
    return subprocess.run(
        ["schtasks.exe", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def run_systemctl(args):
    return subprocess.run(
        ["systemctl", "--user", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def write_systemd_service(interval):
    command = get_daemon_command(interval)
    service_path = get_systemd_service_path()
    service_path.parent.mkdir(parents=True, exist_ok=True)
    working_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    service_path.write_text(
        "\n".join([
            "[Unit]",
            "Description=CSU WiFi auto reconnect daemon",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=simple",
            f"WorkingDirectory={working_dir}",
            f"ExecStart={command}",
            "Restart=always",
            "RestartSec=10",
            "",
            "[Install]",
            "WantedBy=default.target",
            "",
        ]),
        encoding="utf-8",
    )
    return service_path, command


def cmd_autostart(args):
    """Manage daemon autostart for the current platform."""
    if not args.action:
        print("Error: autostart action is required: install, uninstall, or status")
        sys.exit(1)

    task_name = getattr(args, "task_name", AUTOSTART_TASK_NAME)
    method = getattr(args, "method", "all")
    if method != "all":
        method = resolve_autostart_method(method)
        ensure_method_supported(method)

    if args.action == "install":
        config = load_config()
        missing = [key for key in ("username", "password", "isp") if not config.get(key)]
        if missing:
            print("Error: Saved credentials are required before installing autostart.")
            print("Run: csu-wifi connect -u USERNAME -p PASSWORD --isp ISP --save")
            sys.exit(1)

        command = get_daemon_command(args.interval)
        if method == "startup":
            startup_script = get_startup_script_path()
            startup_script.parent.mkdir(parents=True, exist_ok=True)
            startup_script.write_text(
                f"@echo off\r\nstart \"\" /min {command}\r\n",
                encoding="utf-8",
            )
            print(f"SUCCESS: autostart installed ({startup_script})")
            print(f"Command: {command}")
            return

        if method == "systemd":
            service_path, command = write_systemd_service(args.interval)
            reload_result = run_systemctl(["daemon-reload"])
            if reload_result.returncode != 0:
                print(reload_result.stderr.strip() or reload_result.stdout.strip())
                sys.exit(reload_result.returncode)
            enable_result = run_systemctl(["enable", "--now", AUTOSTART_SYSTEMD_SERVICE])
            if enable_result.returncode != 0:
                print(enable_result.stderr.strip() or enable_result.stdout.strip())
                print("Tip: make sure this Linux session supports systemd --user.")
                sys.exit(enable_result.returncode)
            print(f"SUCCESS: autostart service installed ({service_path})")
            print(f"Command: {command}")
            return

        result = run_schtasks([
            "/Create",
            "/TN", task_name,
            "/SC", "ONLOGON",
            "/TR", command,
            "/RL", "LIMITED",
            "/F",
        ])
        if result.returncode != 0:
            output = result.stderr.strip() or result.stdout.strip()
            print(output)
            print("Tip: run from an elevated terminal, or use: csu-wifi autostart install --method startup")
            sys.exit(result.returncode)
        print(f"SUCCESS: autostart task installed ({task_name})")
        print(f"Command: {command}")
        return

    if args.action == "uninstall":
        removed = False
        if method in ("startup", "all"):
            if platform.system() == "Windows":
                startup_script = get_startup_script_path()
                if startup_script.exists():
                    startup_script.unlink()
                    removed = True
                    print(f"Removed startup script: {startup_script}")
        if method in ("task", "all"):
            if platform.system() == "Windows":
                result = run_schtasks(["/Delete", "/TN", task_name, "/F"])
                if result.returncode == 0:
                    removed = True
                    print(f"Removed scheduled task: {task_name}")
                elif method == "task":
                    output = result.stderr.strip() or result.stdout.strip()
                    print(output or f"Task not found: {task_name}")
                    sys.exit(result.returncode)
        if method in ("systemd", "all"):
            if platform.system() == "Linux":
                run_systemctl(["disable", "--now", AUTOSTART_SYSTEMD_SERVICE])
                service_path = get_systemd_service_path()
                if service_path.exists():
                    service_path.unlink()
                    removed = True
                    print(f"Removed systemd user service: {service_path}")
                run_systemctl(["daemon-reload"])
        if not removed:
            print("autostart: not installed")
        return

    if args.action == "status":
        if method in ("startup", "all"):
            if platform.system() == "Windows":
                startup_script = get_startup_script_path()
                if startup_script.exists():
                    print(f"startup: installed ({startup_script})")
                else:
                    print(f"startup: not installed ({startup_script})")
        if method in ("task", "all"):
            if platform.system() == "Windows":
                result = run_schtasks(["/Query", "/TN", task_name, "/FO", "LIST", "/V"])
                if result.returncode != 0:
                    print(f"task: not installed ({task_name})")
                else:
                    print(result.stdout.strip())
        if method in ("systemd", "all"):
            if platform.system() == "Linux":
                service_path = get_systemd_service_path()
                file_state = "installed" if service_path.exists() else "not installed"
                active_result = run_systemctl(["is-active", AUTOSTART_SYSTEMD_SERVICE])
                enabled_result = run_systemctl(["is-enabled", AUTOSTART_SYSTEMD_SERVICE])
                active = active_result.stdout.strip() or "inactive"
                enabled = enabled_result.stdout.strip() or "disabled"
                print(f"systemd: {file_state} ({service_path})")
                print(f"active: {active}")
                print(f"enabled: {enabled}")
        return


# --- Main -----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CSU (Central South University) Campus WiFi CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  csu-wifi connect -u USERNAME -p PASSWORD
  csu-wifi connect -u USERNAME -p PASSWORD --isp telecom --save
  csu-wifi autostart install
  csu-wifi autostart uninstall
  csu-wifi autostart status
  csu-wifi logout
  csu-wifi status
  csu-wifi daemon
        """,
    )
    parser.add_argument("-V", "--version", action="version", version=f"csu-wifi v{VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- connect --
    connect_parser = subparsers.add_parser("connect", help="Authenticate to campus WiFi")
    connect_parser.add_argument("-u", "--username", help="Username (student ID)")
    connect_parser.add_argument("-p", "--password", help="Password")
    connect_parser.add_argument(
        "--isp",
        choices=list(ISP_OPTIONS.keys()),
        default=None,
        help="ISP provider, required unless saved config has one",
    )
    connect_parser.add_argument("--save", action="store_true", help="Save credentials for future use")

    # -- logout --
    subparsers.add_parser("logout", help="Cancel authentication")

    # -- status --
    subparsers.add_parser("status", help="Check connection status")

    # -- daemon --
    daemon_parser = subparsers.add_parser("daemon", help="Auto-reconnect mode")
    daemon_parser.add_argument("-u", "--username", help="Username (student ID)")
    daemon_parser.add_argument("-p", "--password", help="Password")
    daemon_parser.add_argument(
        "--isp",
        choices=list(ISP_OPTIONS.keys()),
        default=None,
        help="ISP provider, required unless saved config has one",
    )
    daemon_parser.add_argument(
        "-i", "--interval",
        type=int,
        default=30,
        help="Check interval in seconds (default: 30)",
    )

    # -- autostart --
    autostart_parser = subparsers.add_parser("autostart", help="Manage daemon autostart")
    autostart_sub = autostart_parser.add_subparsers(dest="action", help="Autostart actions")

    autostart_install = autostart_sub.add_parser("install", help="Install daemon autostart")
    autostart_install.add_argument(
        "-i", "--interval",
        type=int,
        default=30,
        help="Daemon check interval in seconds (default: 30)",
    )
    autostart_install.add_argument(
        "--method",
        choices=("auto", "startup", "task", "systemd"),
        default="auto",
        help="Autostart method: auto uses startup on Windows and systemd on Linux",
    )
    autostart_install.add_argument(
        "--task-name",
        default=AUTOSTART_TASK_NAME,
        help=f"Windows task name for --method task (default: {AUTOSTART_TASK_NAME})",
    )

    autostart_uninstall = autostart_sub.add_parser("uninstall", help="Remove daemon autostart")
    autostart_uninstall.add_argument(
        "--method",
        choices=("auto", "startup", "task", "systemd", "all"),
        default="all",
        help="Autostart method to remove (default: all)",
    )
    autostart_uninstall.add_argument(
        "--task-name",
        default=AUTOSTART_TASK_NAME,
        help=f"Windows task name for --method task/all (default: {AUTOSTART_TASK_NAME})",
    )

    autostart_status = autostart_sub.add_parser("status", help="Show daemon autostart status")
    autostart_status.add_argument(
        "--method",
        choices=("auto", "startup", "task", "systemd", "all"),
        default="all",
        help="Autostart method to inspect (default: all)",
    )
    autostart_status.add_argument(
        "--task-name",
        default=AUTOSTART_TASK_NAME,
        help=f"Windows task name for --method task/all (default: {AUTOSTART_TASK_NAME})",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Dispatch
    commands = {
        "connect": cmd_connect,
        "logout": cmd_logout,
        "status": cmd_status,
        "daemon": cmd_daemon,
        "autostart": cmd_autostart,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)


if __name__ == "__main__":
    main()
