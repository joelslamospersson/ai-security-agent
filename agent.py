import sys
import os
import json
import time
import logging
import re
import glob

# --------
# AI Security Agent
# --------

CONFIG_FILE = ".env"
DEBUG_MODE = True

BAN_LIST = "data/ban_list.json"
WHITELIST = "data/whitelist.json"
QUARANTINE_LIST = "data/quarantine_list.json"
IP_REPUTATION_LIST = "data/ip_reputation_list.json"

PATTERN_LIST = "data/training/pattern_list.json"
BOTNET_SIGNATURES = "data/training/botnet_signatures.json"

DISCORD_WEBHOOKS = "data/discord_webhooks.json"
AGENT_LOGS = "agent.log"

patterns = {}
banlist_cache = None
banlist_last_save = 0
BANLIST_SAVE_INTERVAL = 30  # seconds

logging.basicConfig(
    filename=AGENT_LOGS,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# ---------------- UTILS ----------------
# These helper functions are generic and provide persistent
# storage + cleanup features for the agent state.

# load_json: open a file and parse JSON, with safe fallback to {}.
# - auto-creates missing files
# - auto-recovers if file content is invalid JSON by resetting to {}
# This allows the agent to self-heal corrupted data files.
def load_json(file):
    if not os.path.exists(file):
        os.makedirs(os.path.dirname(file), exist_ok=True)
        with open(file, "w") as f:
            json.dump({}, f)

    try:
        with open(file, "r") as f:
            data = f.read().strip()
            # Return empty dict for empty files
            return json.loads(data) if data else {}
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in {file}, resetting.")
        save_json(file, {})
        return {}


# save_json: store dict back to file with pretty formatting for readability.
# Used by ban list updates and cleanup.
def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)


def get_banlist():
    """Return cached banlist; load once when first needed."""
    global banlist_cache
    if banlist_cache is None:
        banlist_cache = load_json(BAN_LIST)
    return banlist_cache


def persist_banlist(force=False):
    """Write cached banlist to disk periodically."""
    global banlist_cache, banlist_last_save
    if banlist_cache is None:
        return
    now = time.time()
    if force or (now - banlist_last_save) > BANLIST_SAVE_INTERVAL:
        save_json(BAN_LIST, banlist_cache)
        banlist_last_save = now


# clean_expired_bans: maintain ban list by evicting IPs whose ban has expired.
# Also persists changes so on restart the agent does not re-ban expired entries.
# This keeps ban list bounded and avoids growing forever.
def clean_expired_bans(banlist):
    now = time.time()
    expired = [ip for ip, d in banlist.items() if d.get("ban_until") and now > d["ban_until"]]
    for ip in expired:
        del banlist[ip]
        logging.info(f"Expired ban removed: {ip}")
    if expired:
        persist_banlist(force=True)

# ---------------- BRAIN ----------------
# Intelligence layer of the agent.
# It scans each log line (or event string) against all known patterns,
# and returns a struct describing threat details for further action.

def compile_patterns():
    """Compile patterns once to avoid repeated regex compilation."""
    for category, plist in patterns.items():
        for p in plist:
            if "compiled" not in p:
                try:
                    p["compiled"] = re.compile(p["pattern"], re.IGNORECASE)
                except re.error:
                    # fallback to exact string match if given pattern is invalid regex
                    p["compiled"] = re.compile(re.escape(p["pattern"]), re.IGNORECASE)


def brain(event):
    logging.info(f"Analyzing: {event}")
    for category, plist in patterns.items():
        for p in plist:
            matcher = p.get("compiled")
            if matcher is None:
                matcher = re.compile(p.get("pattern", ""), re.IGNORECASE)
                p["compiled"] = matcher

            if matcher.search(event):
                logging.warning(f"Threat match: {p['pattern']} ({category})")
                return {
                    "threat": True,
                    "pattern": p["pattern"],
                    "severity": p.get("severity", 0),
                    "ban_seconds": p.get("ban_seconds", 3600)
                }
    return {"threat": False}

# ---------------- ACTIONS ----------------

def actions(result, source_ip=None):
    if not result["threat"]:
        return

    banlist = get_banlist()

    if source_ip:
        ban_until = time.time() + result["ban_seconds"]
        banlist[source_ip] = {
            "reason": result["pattern"],
            "timestamp": time.time(),
            "ban_until": ban_until,
            "severity": result["severity"]
        }
        persist_banlist()
        logging.info(f"BANNED {source_ip} for {result['pattern']}")

    clean_expired_bans(banlist)

# ---------------- LOG SOURCES ----------------
# Static log paths for Linux variants + expandable discovery.
# These are the primary signal sources for threats (SSH, sudo, core syslog, networking).
LINUX_SECURITY_LOGS = {
    "auth": [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/faillog",
        "/var/log/lastlog",
        "/var/log/tallylog",
    ],
    "system": [
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/dmesg",
    ],
    "firewall": [
        "/var/log/ufw.log",
        "/var/log/firewalld",
        "/var/log/iptables.log",
    ],
    "fail2ban": [
        "/var/log/fail2ban.log",
    ],
    "nginx": [
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/nginx/*access.log",
        "/var/log/nginx/*error.log",
    ],
    "apache": [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
    ],
    "cron": [
        "/var/log/cron",
        "/var/log/syslog",
    ],
    "packages": [
        "/var/log/dpkg.log",
        "/var/log/apt/history.log",
        "/var/log/yum.log",
        "/var/log/pacman.log",
    ],
    "audit": [
        "/var/log/audit/audit.log",
    ]
}

# Common directories to search for application-specific logs.
WEB_LOG_DIRS = ["/var/www", "/srv", "/opt"]
WEB_LOG_KEYWORDS = ["access.log", "error.log", "app.log"]

# Optional generic blacklist for directories and files to exclude from monitoring:
BLACKLIST_PATHS = ["/home", "/var/www/phpmyadmin", "/var/www/html", "venv", "node_modules"]
BLACKLIST_FILES = []

# IPv4 pattern used for extracting candidate source addresses from log lines.
IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"
def is_blacklisted(path):
    """Return True if a path should be excluded from monitoring."""
    abs_path = os.path.abspath(path)

    # exact file blacklist
    for bad_file in BLACKLIST_FILES:
        if os.path.abspath(bad_file) == abs_path:
            return True

    # prefix blacklist for directories or file path segments
    for bad_prefix in BLACKLIST_PATHS:
        if abs_path.startswith(os.path.abspath(bad_prefix)):
            return True

    # generic web root skip under /var/www
    if abs_path.startswith("/var/www"):
        rel = os.path.relpath(abs_path, "/var/www")
        first = rel.split(os.sep)[0] if rel else ""
        if first in ["html", "public_html", "www", "htdocs", "phpmyadmin", "php_adm"]:
            return True

    return False


def open_log_file(path):
    """Open a log file and capture inode to detect rotation."""
    f = open(path, "r", errors="ignore")
    inode = os.fstat(f.fileno()).st_ino
    return {
        "path": path,
        "file": f,
        "gen": follow(f),
        "inode": inode,
    }


def discover_logs():
    log_files = set()

    # Known system logs
    for paths in LINUX_SECURITY_LOGS.values():
        for path in paths:
            for match in glob.glob(path):
                if not os.path.exists(match):
                    continue
                if is_blacklisted(match):
                    continue
                log_files.add(match)

    # Discover web app logs
    for base in WEB_LOG_DIRS:
        if not os.path.exists(base):
            continue
        for root, dirs, files in os.walk(base):
            # avoid scanning known noisy directories
            dirs[:] = [d for d in dirs if d not in ["node_modules", "venv", ".git"]]
            if is_blacklisted(root):
                continue
            for file in files:
                p = os.path.join(root, file)
                if is_blacklisted(p):
                    continue
                if any(k in file.lower() for k in WEB_LOG_KEYWORDS):
                    log_files.add(p)

    logging.info(f"Discovered {len(log_files)} log files")
    return sorted(log_files)

# ---------------- MONITOR ----------------

def extract_ip(line):
    match = re.search(IP_REGEX, line)
    if match:
        ip = match.group(0)
        if all(0 <= int(o) <= 255 for o in ip.split(".")):
            return ip
    return None

def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line

def monitor():
    # Build list of candidate logs and show what we will watch.
    log_files = discover_logs()

    if not log_files:
        logging.warning("No log files found; monitor is idling.")
        print("[!] No logs to monitor")
        return

    print("\n[ AI-Security-Agent ] Monitoring logs:")
    for f in log_files:
        print(" •", f)
    print()

    # Keep a list of file entry objects for tailing and rotation detection.
    file_handles = []
    for path in log_files:
        try:
            entry = open_log_file(path)
            file_handles.append(entry)
        except Exception as e:
            logging.warning(f"Cannot open {path}: {e}")

    if not file_handles:
        logging.warning("No files opened; monitor cannot proceed.")
        return

    # Main loop reads each file in round-robin style; each line is a potential event.
    while True:
        for entry in file_handles:
            path = entry["path"]

            # Re-open if file rotated (inode changed)
            try:
                if os.path.exists(path):
                    current_inode = os.stat(path).st_ino
                    if current_inode != entry["inode"]:
                        logging.info(f"Log rotation detected, reopening {path}")
                        entry["file"].close()
                        new_entry = open_log_file(path)
                        entry.update(new_entry)
                else:
                    continue
            except Exception as e:
                logging.warning(f"Failed to stat {path} in monitor loop: {e}")
                continue

            # Attempt to read the next line; if no data, move on.
            try:
                line = next(entry["gen"])
            except StopIteration:
                continue
            except Exception as e:
                logging.warning(f"Error reading from {path}: {e}")
                continue

            ip = extract_ip(line)
            if not ip:
                continue

            event = f"{path} :: {line.strip()}"
            result = brain(event)
            actions(result, source_ip=ip)

        # Sleep for a short interval to reduce CPU used by the control loop.
        time.sleep(0.1)

# ---------------- MAIN ----------------

def main():
    global patterns
    print("Starting AI-Security Agent...")
    patterns = load_json(PATTERN_LIST)
    compile_patterns()

    try:
        monitor()
    except KeyboardInterrupt: # Graceful shutdown on Ctrl+C
        logging.info("AI-Security Agent stopped by user.")
        print("[+] Agent stopped by user.")

if __name__ == "__main__":
    main()
