# WebFuzz — Async Web Directory Scanner

A fast, asynchronous Python web directory and file fuzzer with wildcard detection, smart path mutation, and sensitive path flagging.

---

## Features

- Async scanning via `aiohttp` for high concurrency and low overhead
- Smart path mutation that auto-generates variants with common extensions (`.php`, `.bak`, `.env`, `.html`, etc.)
- Wildcard/catch-all response detection and automatic filtering
- Sensitive path flagging for keywords like `config`, `env`, `secret`, `.git`, `password`, `token`, etc.
- Automatic retry logic (up to 2 retries per failed request)
- HTTP status distribution tracking across the scan
- JSON report export saved to a timestamped file

---

## Requirements

- Python 3.8+
- `aiohttp`

Install dependencies:

```bash
pip install aiohttp
```

---

## Usage

```bash
python webfuzz.py
```

You will be prompted for the following inputs:

| Prompt | Description |
|---|---|
| Target URL | The base URL to scan. Use `FUZZ` as a placeholder (e.g. `http://example.com/FUZZ`) or just provide the base URL directly. |
| Wordlist | Path to a plaintext wordlist file (one word per line). |
| Concurrency | Number of concurrent requests. Accepts 10–200, defaults to 50. |

---

## How It Works

**Path Mutation**

For each word in the wordlist, the scanner generates multiple path variants by appending common extensions and suffixes:

```
admin → admin, admin.php, admin.html, admin.bak, admin.old, admin.txt, admin.json, admin.env, admin~, Admin, ADMIN
```

**Wildcard Detection**

Before scanning, the tool sends requests to random non-existent paths and computes response signatures (status code + content length + content hash). If three or more responses share the same signature, a wildcard is detected and all matching responses are filtered out during the scan.

**Sensitive Path Flagging**

Any discovered URL containing the following keywords is flagged as sensitive in the output and report:

```
backup, db, database, config, env, secret, password, credential, key, token, .git, .env
```

---

## Output

Discovered paths are printed to the console in real time with color-coded status categories:

| Category | Status Codes |
|---|---|
| FOUND | 200–299 |
| REDIRECT | 300–399 |
| FORBIDDEN | 403 |
| AUTH | 401 |
| ERROR | 400–499 |
| SERVER | 500–599 |

Paths flagged as sensitive are marked with `[SENSITIVE]` in the output.

---

## Report

After the scan completes, a JSON report is saved to the current directory:

```
scan_YYYYMMDD_HHMMSS.json
```

Report structure:

```json
{
  "target": "http://example.com/",
  "duration": 12.45,
  "total_tested": 3200,
  "found": 14,
  "sensitive": 3,
  "status_distribution": {
    "200": 10,
    "301": 2,
    "403": 2
  },
  "findings": [
    {
      "url": "http://example.com/admin",
      "status": 200,
      "sensitive": false
    },
    {
      "url": "http://example.com/.env",
      "status": 200,
      "sensitive": true
    }
  ]
}
```

---

## Configuration

The following constants can be edited directly in the script to adjust behavior:

| Constant | Default | Description |
|---|---|---|
| `EXTENSIONS` | `["", ".php", ".html", ".bak", ".old", ".txt", ".json", ".env"]` | Extensions appended during mutation |
| `IGNORE_STATUS` | `[404]` | Status codes to suppress from output |
| `SENSITIVE_KEYWORDS` | *(see above)* | Keywords used to flag sensitive paths |
| `MAX_RETRIES` | `2` | Number of retries on request failure |
| `RETRY_DELAY` | `1` | Seconds to wait between retries |
| `WILDCARD_THRESHOLD` | `0.9` | Similarity threshold for wildcard filtering |

---

## Stopping the Scan

Press `Ctrl+C` at any time to gracefully stop the scan. Results collected up to that point will still be saved to the JSON report.

---

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Do not use it against systems you do not own or have explicit permission to test.
