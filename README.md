# TCP Port Scanner

A beginner-friendly threaded TCP port scanner written in Python. It resolves a target, scans selected TCP ports concurrently, identifies common services, optionally grabs banners, and saves the scan results as JSON.

> Use this only on systems you own or have clear permission to test.

## Features

- Scan single ports, comma-separated lists, and ranges
- Configurable timeout and thread count
- Common TCP service detection
- Optional banner grabbing for text-based services
- IPv4 and IPv6-aware target resolution
- Clean terminal summary
- JSON report output

## Requirements

- Python 3.10 or newer

This project uses only Python standard library modules, so no extra packages are required.

## Usage

```powershell
python GPT_port_scanner.py -t <target> -p <ports>
```

Examples:

```powershell
python GPT_port_scanner.py -t 127.0.0.1 -p 1-1000
python GPT_port_scanner.py -t example.com -p 22,80,443
python GPT_port_scanner.py -t 192.168.1.1 -p 20-100 --threads 200 --timeout 0.5
python GPT_port_scanner.py -t 127.0.0.1 -p 1-100 --no-banners --show-closed
```

## Options

| Option | Description | Default |
| --- | --- | --- |
| `-t`, `--target` | Target IP address or domain | Required |
| `-p`, `--ports` | Ports to scan, such as `22,80,443` or `1-1000` | Required |
| `--timeout` | Connection timeout in seconds | `0.75` |
| `--threads` | Maximum concurrent scans | `100` |
| `--no-banners` | Skip banner grabbing | Off |
| `--show-closed` | Print closed ports in the summary | Off |
| `-o`, `--output` | JSON output filename | `scan_results.json` |
| `-v`, `--verbose` | Print each port result as it finishes | Off |

## Example Output

```text
========================================================
                    PORT SCANNER REPORT
========================================================
Target:         127.0.0.1
Resolved IP:    127.0.0.1
Ports selected: 5
Port span:      1 -> 5
Threads:        5
Timeout:        0.1s
Banner grab:    off

========================================================
                       SUMMARY
========================================================

[OPEN PORTS]

No open ports found

[SCAN STATISTICS]

Total scan time: 0.12s
Ports scanned:   5
Open ports:      0
Closed ports:    5
Errors:          0
```

## JSON Report

By default, the scanner writes results to `scan_results.json`.

Example structure:

```json
{
    "target": "127.0.0.1",
    "ip": "127.0.0.1",
    "started_at": "2026-05-21T12:00:00",
    "scan_duration_seconds": 0.12,
    "timeout_seconds": 0.1,
    "threads": 5,
    "banner_grabbing": false,
    "results": [
        {
            "port": 80,
            "state": "open",
            "service": "HTTP",
            "banner": "HTTP/1.0 200 OK",
            "duration": 0.0042
        }
    ]
}
```

## Safety Notes

Port scanning can be noisy and may violate rules on networks you do not control. Keep scans limited to your own machines, labs, or targets where you have explicit authorization.

## Project Structure

```text
tcp-port-scanner/
├── GPT_port_scanner.py
├── README.md
└── .gitignore
```
