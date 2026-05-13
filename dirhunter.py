#!/usr/bin/env python3
import asyncio
import aiohttp
import sys
import signal
import json
import time
from datetime import datetime
from collections import defaultdict
import hashlib

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

EXTENSIONS = ["", ".php", ".html", ".bak", ".old", ".txt", ".json", ".env"]
IGNORE_STATUS = [404]
SENSITIVE_KEYWORDS = [
    "backup", "db", "database", "config", "env", "secret", 
    "password", "credential", "key", "token", ".git", ".env"
]
MAX_RETRIES = 2
RETRY_DELAY = 1
WILDCARD_THRESHOLD = 0.9

stop = False
results = []
sensitive_items = []
status_distribution = defaultdict(int)
wildcard_signature = None
request_count = 0
total_requests = 0
semaphore = None

def signal_handler(sig, frame):
    global stop
    print(f"\n{RED}[!] Stopping...{RESET}")
    stop = True

def validate_url(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    if url.endswith('/'):
        url = url[:-1]
    return url

def load_wordlist(path):
    try:
        with open(path, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"{GREEN}[+] Loaded {len(words)} entries{RESET}")
        return words
    except FileNotFoundError:
        print(f"{RED}[-] Wordlist not found: {path}{RESET}")
        return None
    except Exception as e:
        print(f"{RED}[-] Error: {e}{RESET}")
        return None

def smart_mutate(word):
    variants = [word]
    if '.' in word or word.startswith('.'):
        return variants
    for ext in EXTENSIONS:
        if ext:
            variants.append(word + ext)
    for pattern in [".bak", ".old", "~"]:
        variants.append(word + pattern)
    variants.append(word.capitalize())
    variants.append(word.upper())
    return list(set(variants))

def is_sensitive(url):
    url_lower = url.lower()
    return any(kw in url_lower for kw in SENSITIVE_KEYWORDS)

def get_status_color(status):
    if 200 <= status <= 299:
        return GREEN
    elif 300 <= status <= 399:
        return BLUE
    elif status == 403:
        return YELLOW
    elif status == 404:
        return RED
    elif 500 <= status <= 599:
        return MAGENTA
    return CYAN

def get_status_category(status):
    if 200 <= status <= 299:
        return "FOUND"
    elif 300 <= status <= 399:
        return "REDIRECT"
    elif status == 403:
        return "FORBIDDEN"
    elif status == 401:
        return "AUTH"
    elif 400 <= status <= 499:
        return "ERROR"
    elif 500 <= status <= 599:
        return "SERVER"
    return "INFO"

def compute_signature(response_text, status):
    normalized = ' '.join(response_text.split())
    content_hash = hashlib.md5(normalized.encode()).hexdigest()[:16]
    length = len(response_text)
    return f"{status}|{length}|{content_hash}"

def is_wildcard_response(signature):
    global wildcard_signature
    if wildcard_signature is None:
        return False
    parts1 = wildcard_signature.split('|')
    parts2 = signature.split('|')
    if parts1[0] != parts2[0]:
        return False
    len1 = int(parts1[1])
    len2 = int(parts2[1])
    if len1 == 0:
        return False
    similarity = 1 - (abs(len1 - len2) / len1)
    return similarity > WILDCARD_THRESHOLD

async def detect_wildcard(session, base_url, test_words):
    global wildcard_signature
    print(f"{YELLOW}[*] Detecting wildcard patterns...{RESET}")
    signatures = []
    for word in test_words[:5]:
        try:
            url = base_url + word
            async with session.get(url, timeout=5, ssl=False) as response:
                text = await response.text()
                signature = compute_signature(text, response.status)
                signatures.append(signature)
        except:
            continue
    if signatures:
        from collections import Counter
        most_common = Counter(signatures).most_common(1)[0]
        if most_common[1] >= 3:
            wildcard_signature = most_common[0]
            print(f"{YELLOW}[!] Wildcard detected - filtering{RESET}")
            return True
    print(f"{GREEN}[+] No wildcard detected{RESET}")
    return False

async def test_path(session, base_url, path, semaphore):
    global request_count, total_requests, stop
    if stop:
        return None
    async with semaphore:
        url = base_url + path
        for attempt in range(MAX_RETRIES):
            try:
                await asyncio.sleep(0)
                async with session.get(url, timeout=5, ssl=False, allow_redirects=False) as response:
                    text = await response.text()
                    status = response.status
                    signature = compute_signature(text, status)
                    status_distribution[status] += 1
                    request_count += 1
                    if is_wildcard_response(signature):
                        return None
                    if status not in IGNORE_STATUS:
                        color = get_status_color(status)
                        category = get_status_category(status)
                        sensitive_flag = is_sensitive(url)
                        if sensitive_flag:
                            print(f"[{category}] [SENSITIVE] {url} ({color}{status}{RESET})")
                        else:
                            print(f"[{category}] {url} ({color}{status}{RESET})")
                        return {
                            'url': url,
                            'status': status,
                            'sensitive': sensitive_flag,
                            'content_length': len(text)
                        }
                    return None
            except:
                await asyncio.sleep(RETRY_DELAY)
        return None

async def run_scan(base_url, paths, concurrency):
    global semaphore, request_count, total_requests
    semaphore = asyncio.Semaphore(concurrency)
    request_count = 0
    total_requests = len(paths)
    connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=concurrency)
    async with aiohttp.ClientSession(connector=connector, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }) as session:
        await detect_wildcard(session, base_url, ["random123", "nonexistent456", "fakescan789"])
        print(f"\n[+] Scanning {total_requests} paths... (Ctrl+C to stop)\n")
        tasks = [asyncio.create_task(test_path(session, base_url, path, semaphore)) for path in paths]
        results_list = []
        for task in asyncio.as_completed(tasks):
            if stop:
                break
            result = await task
            if result:
                results_list.append(result)
        return results_list

def save_report(target, results, sensitive, status_dist, duration, total_tested):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{timestamp}.json"
    report = {
        "target": target,
        "duration": round(duration, 2),
        "total_tested": total_tested,
        "found": len(results),
        "sensitive": len(sensitive),
        "status_distribution": dict(status_dist),
        "findings": [{"url": r['url'], "status": r['status'], "sensitive": r['sensitive']} for r in results]
    }
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n{GREEN}[+] Saved: {filename}{RESET}")

def main():
    global stop, results, sensitive_items, status_distribution
    
    signal.signal(signal.SIGINT, signal_handler)
    
    target = input("Target URL (use FUZZ): ").strip()
    target = validate_url(target)
    
    if 'FUZZ' in target:
        base_url = target.split('FUZZ')[0]
    else:
        base_url = target if target.endswith('/') else target + '/'
    
    print(f"[+] Target: {base_url}")
    
    wordlist_path = input("Wordlist: ").strip()
    words = load_wordlist(wordlist_path)
    if not words:
        sys.exit(1)
    
    print("[+] Generating paths...")
    all_paths = set()
    for word in words:
        for variant in smart_mutate(word):
            all_paths.add(variant)
    all_paths = list(all_paths)
    print(f"[+] Total paths: {len(all_paths)}")
    
    try:
        concurrency = int(input("Concurrency (10-200, default 50): ").strip() or "50")
        concurrency = max(10, min(200, concurrency))
    except:
        concurrency = 50
    
    start_time = time.time()
    
    try:
        results = asyncio.run(run_scan(base_url, all_paths, concurrency))
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Interrupted{RESET}")
    
    duration = time.time() - start_time
    sensitive_items = [r for r in results if r['sensitive']]
    
    if results:
        print(f"\n[+] Found {len(results)} items ({len(sensitive_items)} sensitive)")
    else:
        print(f"\n[+] No items found")
    
    print(f"[+] Time: {duration:.2f}s | Rate: {len(all_paths)/duration:.1f} req/s")
    
    if results:
        print(f"\n[+] Results:")
        for r in results[:20]:
            color = get_status_color(r['status'])
            sens = " [SENSITIVE]" if r['sensitive'] else ""
            print(f"    {color}[{r['status']}]{RESET} {r['url']}{sens}")
        if len(results) > 20:
            print(f"    ... and {len(results)-20} more")
    
    save_report(base_url, results, sensitive_items, status_distribution, duration, len(all_paths))

if __name__ == "__main__":
    main()
