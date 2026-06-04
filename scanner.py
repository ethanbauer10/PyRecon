#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║               PyRecon - Recon & Enumeration Suite            ║
║            Final Year University Project | Python 3.10+      ║
╚══════════════════════════════════════════════════════════════╝

Modules:
  1. Port Scanner  → async TCP discovery + Nmap chaining
  2. Directory Bruteforce → multi-threaded HTTP fuzzing + wildcard detection
  3. Subdomain Discovery  → Host header vhost probing (like ffuf)
  4. Exit

Install dependencies:
  pip install requests dnspython
  sudo apt install nmap
"""

# ── Standard library imports ────────────────────────────────────────────────
import asyncio                     # Async I/O framework for speed mode port scanning
import socket                      # Low-level networking for hostname resolution and accuracy mode
import subprocess                  # Used to invoke Nmap as an external process
import sys                         # System utilities: exit, stdout write
import time                        # Timing scans and adding retry delays
import os                          # OS utilities: clear screen, check file paths
import threading                   # Threading primitives: Lock for thread-safe shared state
import random                      # Used to generate random paths for wildcard detection
import string                      # Used to generate random strings for wildcard detection
from datetime import datetime      # Timestamps shown at scan start
from concurrent.futures import ThreadPoolExecutor  # Managed thread pool for accuracy mode, dir brute, subdomain

# ── Optional third-party imports (checked at runtime) ───────────────────────
try:
    import requests                                          # HTTP library for directory bruteforcing
    from requests.adapters import HTTPAdapter               # Allows customising connection pool settings
    from urllib3.util.retry import Retry                    # Retry policy for resilient HTTP requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Suppress SSL warnings for IP-based requests
    REQUESTS_OK = True                                      # Flag: requests is available
except ImportError:
    REQUESTS_OK = False                                     # Flag: requests is missing, warn user

try:
    import dns.resolver                                     # DNS resolution library for subdomain discovery
    DNS_OK = True                                           # Flag: dnspython is available
except ImportError:
    DNS_OK = False                                          # Flag: dnspython is missing


# ── ANSI escape codes for terminal colour output ─────────────────────────────
class C:
    RED     = "\033[91m"   # Errors and warnings
    GREEN   = "\033[92m"   # Successes and open ports
    YELLOW  = "\033[93m"   # Info messages and accuracy mode highlights
    MAGENTA = "\033[95m"   # User prompt indicators
    CYAN    = "\033[96m"   # Section headers and tool titles
    WHITE   = "\033[97m"   # Bold white for section titles
    BOLD    = "\033[1m"    # Bold text
    DIM     = "\033[2m"    # Dimmed/secondary text
    RESET   = "\033[0m"    # Reset all formatting back to terminal default


# ── Banner printed at startup and on menu return ─────────────────────────────
def banner():
    os.system("cls" if os.name == "nt" else "clear")       # Clear screen: cls on Windows, clear on Unix
    print(f"""{C.CYAN}{C.BOLD}
  ██████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝ ╚████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔═══╝   ╚██╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║        ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝        ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.RESET}{C.DIM}  Recon & Enumeration Suite  ·  Final Year Project  ·  Python{C.RESET}
""")


# ── Helper print functions for consistent output formatting ──────────────────
def section(title: str):
    """Print a styled section divider with a title."""
    print(f"\n{C.CYAN}{'─'*55}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}{title}{C.RESET}")
    print(f"{C.CYAN}{'─'*55}{C.RESET}\n")

def ok(msg):   print(f"  {C.GREEN}[+]{C.RESET} {msg}")      # Success message
def info(msg): print(f"  {C.YELLOW}[i]{C.RESET} {msg}")     # Informational message
def warn(msg): print(f"  {C.RED}[!]{C.RESET} {msg}")        # Warning or error message

def prompt(msg: str, default: str = "") -> str:
    """Display a styled input prompt and return the user's input, or the default if blank."""
    hint = f" [{default}]" if default else ""
    val = input(f"  {C.MAGENTA}[?]{C.RESET} {msg}{hint}: ").strip()
    return val if val else default

def progress_bar(done: int, total: int, width: int = 38) -> str:
    """Build a text progress bar string showing completion percentage."""
    pct = int((done / total) * width)
    bar = "█" * pct + "░" * (width - pct)
    return f"[{bar}] {done}/{total}"


# ── Curated list of the most commonly open ports ─────────────────────────────
TOP_PORTS = sorted({
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 27017, 6379, 5432, 1433,
    2049, 161, 162, 389, 636, 88, 464, 3268, 3269, 5985, 5986, 4444,
    9200, 9300, 11211, 6667, 7001, 7002, 8009, 8161, 8180, 9090, 10000,
    10443, 20000, 32768, 49000, 50000, 49152, 49153, 49154, 49155, 49156
})


# ════════════════════════════════════════════════════════════════
#  MODULE 1 — PORT SCANNER
# ════════════════════════════════════════════════════════════════

BATCH_SIZE = 2000   # Number of ports scanned per batch — balances memory and throughput

async def _check_port_speed(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> int | None:
    """
    Attempt a single async TCP connection to host:port.
    Returns the port number if open, None if closed or timed out.
    """
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port                                     # Connection succeeded — port is open
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None                                     # Timeout = filtered, Refused = closed


async def _speed_scan(host: str, ports: list, timeout: float, concurrency: int) -> list:
    """
    Speed mode: splits ports into batches and scans each batch with
    asyncio concurrency capped by a Semaphore to avoid hitting OS fd limits.
    """
    sem = asyncio.Semaphore(concurrency)
    open_ports = []
    done = 0
    total = len(ports)

    batches = [ports[i:i + BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]

    for batch in batches:
        tasks = [asyncio.create_task(_check_port_speed(host, p, timeout, sem)) for p in batch]

        for task in asyncio.as_completed(tasks):
            result = await task
            done += 1

            if result is not None:
                open_ports.append(result)
                sys.stdout.write("\033[2K\r")              # Erase progress bar before printing discovery
                print(f"  {C.GREEN}[+]{C.RESET} Open port discovered: {C.BOLD}{result}{C.RESET}")

            sys.stdout.write(f"\r  {progress_bar(done, total)}")
            sys.stdout.flush()

    sys.stdout.write("\033[2K\r")
    sys.stdout.flush()
    print()
    return sorted(open_ports)


def _check_port_accuracy(args: tuple) -> int | None:
    """
    Blocking TCP connect with retries.
    Breaks immediately on ConnectionRefusedError (definitively closed).
    Retries on OSError (transient — e.g. too many open files).
    """
    host, port, timeout, retries = args
    for attempt in range(retries):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except (ConnectionRefusedError, socket.timeout):
            break
        except OSError:
            if attempt < retries - 1:
                time.sleep(0.3)
    return None


def _accuracy_scan(host: str, ports: list, timeout: float, retries: int, workers: int) -> list:
    """
    Accuracy mode: thread pool with blocking connects and retries.
    More reliable than async against firewalled or high-latency targets.
    """
    open_ports = []
    done = 0
    total = len(ports)
    args_list = [(host, p, timeout, retries) for p in ports]

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for port, result in zip(ports, executor.map(_check_port_accuracy, args_list)):
            done += 1
            if result is not None:
                open_ports.append(result)
                sys.stdout.write("\033[2K\r")
                print(f"  {C.GREEN}[+]{C.RESET} Open port discovered: {C.BOLD}{result}{C.RESET}")

            if done % 100 == 0 or done == total:
                sys.stdout.write(f"\r  {progress_bar(done, total)}")
                sys.stdout.flush()

    sys.stdout.write("\033[2K\r")
    sys.stdout.flush()
    print()
    return sorted(open_ports)


def _run_nmap(host: str, open_ports: list, flags: str):
    """
    Chain open ports into Nmap for service/version enumeration.
    Constraining Nmap to confirmed open ports makes it much faster
    than running a full -p- scan.
    """
    ports_arg = ",".join(map(str, open_ports))
    cmd = ["nmap", "-p", ports_arg] + flags.split() + [host]

    section("Nmap Deep Enumeration")
    print(f"  {C.DIM}$ {' '.join(cmd)}{C.RESET}\n")
    print("─" * 55)

    try:
        subprocess.run(cmd, text=True)
    except FileNotFoundError:
        warn("Nmap not found — install it: sudo apt install nmap")
        info(f"Run manually: nmap -p {ports_arg} {flags} {host}")


def parse_ports(s: str) -> list:
    """Parse port string into sorted list. Supports ranges, lists, or combinations."""
    ports = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def menu_port_scan():
    """Interactive entry point for the port scanner module."""
    section("Port Scanner → Nmap")

    target = prompt("Target IP or hostname")
    if not target:
        warn("No target provided.")
        return

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        warn(f"Cannot resolve: {target}")
        return

    ok(f"Resolved {target} → {ip}")

    print(f"\n  {C.BOLD}Scan Mode:{C.RESET}")
    print(f"    {C.GREEN}[1]{C.RESET} Speed    — async, scans all 65k ports rapidly")
    print(f"    {C.YELLOW}[2]{C.RESET} Accuracy — threaded + retries, reliable for firewalled hosts")
    mode_choice = prompt("Choose mode", "1")
    mode = "speed" if mode_choice != "2" else "accuracy"

    print(f"\n  {C.BOLD}Port Range:{C.RESET}")
    print(f"    {C.DIM}Examples: 1-65535 | 1-1024 | 22,80,443 | top{C.RESET}")
    port_input = prompt("Ports", "1-65535")

    if port_input.lower() == "top":
        ports = TOP_PORTS
        info(f"Using {len(ports)} common ports")
    else:
        try:
            ports = parse_ports(port_input)
        except ValueError:
            warn("Invalid port format.")
            return

    no_nmap = prompt("Skip Nmap after discovery? (y/N)", "N").lower() == "y"
    nmap_flags = "-sV -sC -A"
    if not no_nmap:
        nmap_flags = prompt("Nmap flags", "-sV -sC -A")

    print()
    info(f"Target: {target} ({ip})  |  Mode: {mode.upper()}  |  Ports: {len(ports)}")
    info(f"Started: {datetime.now().strftime('%H:%M:%S')}")
    print()

    t0 = time.time()

    if mode == "speed":
        open_ports = asyncio.run(_speed_scan(ip, ports, timeout=2.0, concurrency=500))
    else:
        open_ports = _accuracy_scan(ip, ports, timeout=3.0, retries=2, workers=150)

    elapsed = time.time() - t0
    print(f"\n  {C.BOLD}Scan finished in {elapsed:.2f}s{C.RESET}")

    if not open_ports:
        warn("No open ports found.")
        info("Try accuracy mode, increase timeout, or verify the target is reachable.")
    else:
        ok(f"Open ports ({len(open_ports)}): {C.BOLD}{', '.join(map(str, open_ports))}{C.RESET}")
        if not no_nmap:
            _run_nmap(ip, open_ports, nmap_flags)

    input(f"\n  {C.DIM}Press Enter to return to menu...{C.RESET}")


# ════════════════════════════════════════════════════════════════
#  MODULE 2 — DIRECTORY BRUTEFORCE
# ════════════════════════════════════════════════════════════════

def _build_http_session() -> "requests.Session":
    """
    Create a requests Session with connection pooling and retry policy.
    Reusing a Session avoids the overhead of a new TCP handshake per request.
    """
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=100)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; PyRecon/1.0)"})
    return session


def _detect_wildcard(base_url: str, session: "requests.Session", timeout: float) -> tuple:
    """
    Probe 3 random paths that cannot exist on any real server.
    Follows redirects to fingerprint the final landing page by status code
    and content length. Used to filter false positives during scanning.
    """
    baseline_codes = set()
    baseline_lengths = set()

    for _ in range(3):
        junk = ''.join(random.choices(string.ascii_lowercase, k=12))
        url = f"{base_url.rstrip('/')}/{junk}"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code != 404:
                baseline_codes.add(r.status_code)
                baseline_lengths.add(len(r.content))      # Fingerprint by content length
        except Exception:
            pass

    if baseline_codes:
        warn(f"Wildcard response detected — server returns {baseline_codes} for all paths")
        info(f"Baseline content length(s): {baseline_lengths} bytes — filtering matches...")

    return baseline_codes, baseline_lengths


def _check_directory(base_url: str, word: str, session: "requests.Session",
                     extensions: list, timeout: float,
                     found: list, lock: threading.Lock, counter: list, total: int,
                     wildcard_codes: set, wildcard_lengths: set):
    """
    Test a single wordlist entry and its extension variants against the target.
    Filters wildcard responses by comparing content length against baseline.
    Thread-safe via Lock for shared state.
    """
    paths = [word] + [f"{word}{ext}" for ext in extensions]

    for path in paths:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)

            # Wildcard filter: skip if status + content length match the baseline
            if wildcard_codes and r.status_code in wildcard_codes:
                content_len = len(r.content)
                if any(abs(content_len - bl) <= 50 for bl in wildcard_lengths):
                    continue                                # False positive — skip

            if r.status_code not in (404, 400, 410):
                colour = C.GREEN if r.status_code == 200 else C.YELLOW
                with lock:
                    found.append((r.status_code, url))
                    sys.stdout.write("\033[2K\r")
                    print(f"  {colour}[{r.status_code}]{C.RESET} {url}")
        except Exception:
            pass

    with lock:
        counter[0] += 1
        if counter[0] % 50 == 0 or counter[0] == total:
            sys.stdout.write(f"\r  {progress_bar(counter[0], total)}")
            sys.stdout.flush()


def menu_dir_brute():
    """Interactive entry point for the directory bruteforce module."""
    section("Directory Bruteforce")

    if not REQUESTS_OK:
        warn("'requests' library not installed. Run: pip install requests")
        input(f"\n  {C.DIM}Press Enter to return...{C.RESET}")
        return

    url = prompt("Target URL (e.g. http://10.10.10.5)")
    if not url:
        warn("No URL provided.")
        return
    if not url.startswith("http"):
        url = "http://" + url

    wordlist = prompt("Path to wordlist", "/usr/share/wordlists/dirb/common.txt")
    if not os.path.isfile(wordlist):
        warn(f"Wordlist not found: {wordlist}")
        info("Try: /usr/share/seclists/Discovery/Web-Content/common.txt")
        return

    ext_input = prompt("Extensions to append (comma-separated, or blank for none)", ".php,.html,.txt")
    extensions = []
    if ext_input:
        for e in ext_input.split(","):
            e = e.strip()
            if e:
                extensions.append(e if e.startswith(".") else f".{e}")

    threads = int(prompt("Threads", "50"))
    timeout = float(prompt("Request timeout (s)", "5"))

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        warn(f"Could not read wordlist: {e}")
        return

    info(f"Loaded {len(words)} words  |  Extensions: {extensions or 'none'}  |  Threads: {threads}")
    print()

    session = _build_http_session()
    wildcard_codes, wildcard_lengths = _detect_wildcard(url, session, timeout)

    found = []
    lock = threading.Lock()
    counter = [0]
    total = len(words)
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for word in words:
            executor.submit(
                _check_directory, url, word, session,
                extensions, timeout, found, lock, counter, total,
                wildcard_codes, wildcard_lengths
            )

    sys.stdout.write("\033[2K\r")
    elapsed = time.time() - t0
    print(f"\n  {C.BOLD}Finished in {elapsed:.2f}s{C.RESET}")

    if not found:
        warn("No paths discovered.")
        if wildcard_codes:
            info("All responses matched wildcard baseline and were filtered.")
            info("Try browsing the target manually to confirm its behaviour.")
    else:
        section(f"Discovered Paths ({len(found)})")
        for status, path in sorted(found, key=lambda x: x[0]):
            colour = C.GREEN if status == 200 else C.YELLOW
            print(f"  {colour}[{status}]{C.RESET} {path}")

    input(f"\n  {C.DIM}Press Enter to return to menu...{C.RESET}")


# ════════════════════════════════════════════════════════════════
#  MODULE 3 — SUBDOMAIN DISCOVERY
# ════════════════════════════════════════════════════════════════

def _get_baseline_response(ip: str, domain: str, scheme: str, timeout: float) -> tuple:
    """
    Fetch the default vhost response by connecting to the IP with the
    base domain as the Host header. This gives us a baseline status code
    and content length to filter against — subdomains that return the same
    response as the default vhost are not real virtual hosts.
    """
    try:
        r = requests.get(
            f"{scheme}://{ip}",
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; PyRecon/1.0)",
                "Host": domain                             # Base domain as Host header
            },
            verify=False
        )
        return (r.status_code, len(r.content))            # Return status and length as baseline
    except Exception:
        return (None, None)


def _probe_vhost(subdomain: str, ip: str, scheme: str, timeout: float) -> tuple | None:
    """
    Probe a candidate subdomain by connecting to the target IP directly
    and setting the subdomain as the Host header.

    This mirrors exactly how ffuf performs vhost discovery:
      - Connect to the known IP (bypasses DNS entirely)
      - Set Host: <subdomain> so the web server routes to the right vhost
      - Compare the response against the baseline default vhost response

    Returns (subdomain, status_code, content_length) or None on failure.
    """
    try:
        r = requests.get(
            f"{scheme}://{ip}",                            # Connect to IP, not the subdomain hostname
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; PyRecon/1.0)",
                "Host": subdomain                          # Virtual host name goes in Host header
            },
            verify=False                                   # Ignore SSL cert errors for IP-based requests
        )
        return (subdomain, r.status_code, len(r.content))
    except Exception:
        return None


def _check_subdomain(domain: str, word: str, ip: str, scheme: str,
                     timeout: float, baseline_status: int, baseline_length: int,
                     found: list, lock: threading.Lock, counter: list, total: int):
    """
    Check a single subdomain candidate using Host header probing.
    Filters responses that match the baseline default vhost by comparing
    status code and content length — a real subdomain returns something
    meaningfully different from the default page.
    """
    sub = f"{word}.{domain}"                               # e.g. crm.board.htb
    result = _probe_vhost(sub, ip, scheme, timeout)

    if result:
        _, status, length = result

        # Skip if response matches the default vhost baseline
        # (same status code AND content length within 50 bytes)
        if status == baseline_status and abs(length - baseline_length) <= 50:
            pass                                           # Default vhost response — not a real subdomain
        elif status not in (400, 404, 410):
            colour = C.GREEN if status == 200 else C.YELLOW
            with lock:
                found.append((sub, status))
                sys.stdout.write("\033[2K\r")
                print(f"  {colour}[{status}]{C.RESET} {C.BOLD}{sub}{C.RESET}  ({length} bytes)")

    with lock:
        counter[0] += 1
        if counter[0] % 50 == 0 or counter[0] == total:
            sys.stdout.write(f"\r  {progress_bar(counter[0], total)}")
            sys.stdout.flush()


def menu_subdomain():
    """Interactive entry point for the subdomain discovery module."""
    section("Subdomain Discovery")

    if not REQUESTS_OK:
        warn("'requests' library not installed. Run: pip install requests")
        input(f"\n  {C.DIM}Press Enter to return...{C.RESET}")
        return

    domain = prompt("Target domain (e.g. board.htb)")
    if not domain:
        warn("No domain provided.")
        return
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

    # Resolve base domain to IP — all probes connect to this IP with Host headers
    try:
        ip = socket.gethostbyname(domain)
        ok(f"Resolved {domain} → {ip}")
        info("Using Host header vhost probing — DNS not required for subdomains")
    except socket.gaierror:
        warn(f"Cannot resolve {domain} — is it in /etc/hosts?")
        input(f"\n  {C.DIM}Press Enter to return...{C.RESET}")
        return

    scheme_choice = prompt("Scheme: [1] HTTP  [2] HTTPS", "1")
    scheme = "https" if scheme_choice == "2" else "http"

    wordlist = prompt("Path to subdomain wordlist",
                      "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    if not os.path.isfile(wordlist):
        for fallback in ["/usr/share/wordlists/dnsmap.txt",
                         "/usr/share/amass/wordlists/subdomains.lst"]:
            if os.path.isfile(fallback):
                wordlist = fallback
                info(f"Using fallback wordlist: {fallback}")
                break
        else:
            warn(f"Wordlist not found: {wordlist}")
            info("Install SecLists: sudo apt install seclists")
            return

    threads = int(prompt("Threads", "50"))
    timeout = float(prompt("Timeout (s)", "5"))

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        warn(f"Could not read wordlist: {e}")
        return

    # Fetch baseline response for default vhost before scanning
    info("Fetching baseline response for default vhost...")
    baseline_status, baseline_length = _get_baseline_response(ip, domain, scheme, timeout)

    if baseline_status:
        info(f"Baseline: status={baseline_status}  length={baseline_length} bytes — filtering matches")
    else:
        warn("Could not fetch baseline — all results will be shown unfiltered")
        baseline_status, baseline_length = 200, 0

    info(f"Loaded {len(words)} words  |  Threads: {threads}  |  Target: {ip} ({scheme})")
    print()

    found = []
    lock = threading.Lock()
    counter = [0]
    total = len(words)
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for word in words:
            executor.submit(
                _check_subdomain,
                domain, word, ip, scheme, timeout,
                baseline_status, baseline_length,
                found, lock, counter, total
            )

    sys.stdout.write("\033[2K\r")
    elapsed = time.time() - t0
    print(f"\n  {C.BOLD}Finished in {elapsed:.2f}s{C.RESET}")

    if not found:
        warn("No subdomains discovered.")
        info("Try a larger wordlist or check the target is reachable.")
    else:
        section(f"Discovered Subdomains ({len(found)})")
        for sub, status in found:
            colour = C.GREEN if status == 200 else C.YELLOW
            print(f"  {colour}[{status}]{C.RESET} {C.BOLD}{sub}{C.RESET}")

    input(f"\n  {C.DIM}Press Enter to return to menu...{C.RESET}")


# ════════════════════════════════════════════════════════════════
#  MAIN MENU
# ════════════════════════════════════════════════════════════════

def main_menu():
    """Main loop — displays menu and routes to selected module."""
    while True:
        banner()

        deps = []
        deps.append(f"{C.GREEN}requests✓{C.RESET}" if REQUESTS_OK else f"{C.RED}requests✗{C.RESET}")
        deps.append(f"{C.GREEN}dnspython✓{C.RESET}" if DNS_OK else f"{C.RED}dnspython✗{C.RESET}")
        print(f"  {C.DIM}Dependencies: {' | '.join(deps)}{C.RESET}")
        if not REQUESTS_OK:
            print(f"  {C.DIM}Install missing: pip install requests dnspython{C.RESET}")

        print(f"""
  {C.BOLD}Select a tool:{C.RESET}

  {C.GREEN} [1] {C.RESET} {C.BOLD}Port Scanner{C.RESET}
       {C.DIM}Async port discovery → chains into Nmap for service enumeration{C.RESET}
       {C.DIM}Speed mode (RustScan-style) or Accuracy mode (reliable, threaded){C.RESET}

  {C.CYAN} [2] {C.RESET} {C.BOLD}Directory Bruteforce{C.RESET}
       {C.DIM}Multi-threaded HTTP fuzzing with wildcard detection and filtering{C.RESET}

  {C.MAGENTA} [3] {C.RESET} {C.BOLD}Subdomain Discovery{C.RESET}
       {C.DIM}Host header vhost probing — works without DNS, like ffuf{C.RESET}

  {C.RED} [4] {C.RESET} {C.BOLD}Exit{C.RESET}
""")

        choice = input(f"  {C.YELLOW}→{C.RESET} Enter choice: ").strip()

        if choice == "1":
            menu_port_scan()
        elif choice == "2":
            menu_dir_brute()
        elif choice == "3":
            menu_subdomain()
        elif choice == "4":
            banner()
            print(f"  {C.CYAN}Exiting PyRecon. Stay legal. 👋{C.RESET}\n")
            sys.exit(0)
        else:
            warn("Invalid option. Please enter 1, 2, 3, or 4.")
            time.sleep(1)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}[!]{C.RESET} Interrupted by user. Exiting.\n")
        sys.exit(0)
