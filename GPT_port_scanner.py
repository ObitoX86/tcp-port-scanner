import argparse
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MSRPC",
    139: "NETBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-PROXY",
    8443: "HTTPS-ALT",
}


def resolve_target(target):
    """Return the best socket address for a hostname or IP."""
    try:
        info = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None

    family, _, _, _, sockaddr = info[0]
    return {
        "family": family,
        "ip": sockaddr[0],
        "scope_id": sockaddr[3] if family == socket.AF_INET6 else 0,
    }


def parse_ports(port_expression):
    """Parse strings like '22,80,1000-1010' into sorted unique ports."""
    ports = set()
    invalid_parts = []

    for raw_part in port_expression.split(","):
        part = raw_part.strip()
        if not part:
            continue

        if "-" in part:
            try:
                start_text, end_text = part.split("-", 1)
                start = int(start_text.strip())
                end = int(end_text.strip())
            except ValueError:
                invalid_parts.append(part)
                continue

            if start > end:
                start, end = end, start

            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                invalid_parts.append(part)

    valid_ports = sorted(port for port in ports if 1 <= port <= 65535)
    out_of_range = sorted(port for port in ports if port < 1 or port > 65535)

    return valid_ports, invalid_parts, out_of_range


def guess_service(port):
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]

    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "UNKNOWN"


def grab_banner(sock, port, service, timeout):
    """Try a small, polite banner probe for common text protocols."""
    sock.settimeout(timeout)

    try:
        if service in {"HTTP", "HTTP-PROXY"}:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        elif service in {"HTTPS", "HTTPS-ALT"}:
            return "TLS service detected; banner probing skipped"
        elif service in {"SSH", "FTP", "SMTP", "POP3", "IMAP"}:
            pass
        else:
            sock.sendall(b"\r\n")

        banner = sock.recv(1024)
    except socket.timeout:
        return "No banner (timeout)"
    except OSError:
        return "No banner"

    if not banner:
        return "No banner"

    return banner.decode(errors="replace").strip()


def scan_port(address, port, timeout, grab_banners):
    start_time = time.perf_counter()
    service = guess_service(port)
    connect_address = (address["ip"], port)

    if address["family"] == socket.AF_INET6:
        connect_address = (address["ip"], port, 0, address["scope_id"])

    try:
        with socket.socket(address["family"], socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex(connect_address)

            elapsed = round(time.perf_counter() - start_time, 4)
            if result != 0:
                return {
                    "port": port,
                    "state": "closed",
                    "service": service,
                    "banner": "",
                    "duration": elapsed,
                }

            banner = grab_banner(sock, port, service, timeout) if grab_banners else ""
            elapsed = round(time.perf_counter() - start_time, 4)
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
                "duration": elapsed,
            }
    except OSError as error:
        return {
            "port": port,
            "state": "error",
            "service": service,
            "banner": "",
            "duration": round(time.perf_counter() - start_time, 4),
            "error": str(error),
        }


def build_parser():
    parser = argparse.ArgumentParser(
        description="Threaded TCP port scanner for hosts you own or have permission to test.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address or domain")
    parser.add_argument("-p", "--ports", required=True, help="Ports, e.g. 22,80,443 or 1-1000")
    parser.add_argument("--timeout", type=float, default=0.75, help="Connection timeout in seconds")
    parser.add_argument("--threads", type=int, default=100, help="Maximum concurrent scans")
    parser.add_argument("--no-banners", action="store_true", help="Skip banner grabbing")
    parser.add_argument("--show-closed", action="store_true", help="Print closed ports in the summary")
    parser.add_argument("-o", "--output", default="scan_results.json", help="JSON output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print each port result as it finishes")
    return parser


def print_header(target, address, ports, args):
    print("\n" + "=" * 56)
    print("                    PORT SCANNER REPORT")
    print("=" * 56)
    print(f"Target:         {target}")
    print(f"Resolved IP:    {address['ip']}")
    print(f"Ports selected: {len(ports)}")
    print(f"Port span:      {ports[0]} -> {ports[-1]}")
    print(f"Threads:        {args.threads}")
    print(f"Timeout:        {args.timeout}s")
    print(f"Banner grab:    {'off' if args.no_banners else 'on'}")


def print_summary(results, scan_duration, show_closed):
    open_results = [item for item in results if item["state"] == "open"]
    closed_results = [item for item in results if item["state"] == "closed"]
    error_results = [item for item in results if item["state"] == "error"]

    print("\n" + "=" * 56)
    print("                       SUMMARY")
    print("=" * 56)

    print("\n[OPEN PORTS]\n")
    if open_results:
        for item in open_results:
            print(f" -> {item['port']:>5}/tcp  {item['service']}")
            if item["banner"]:
                first_line = item["banner"].splitlines()[0]
                print(f"        banner: {first_line[:120]}")
    else:
        print("No open ports found")

    if show_closed:
        print("\n[CLOSED PORTS]\n")
        for item in closed_results:
            print(f" -> {item['port']}")

    if error_results:
        print("\n[ERRORS]\n")
        for item in error_results:
            print(f" -> {item['port']}: {item.get('error', 'unknown error')}")

    print("\n[SCAN STATISTICS]\n")
    print(f"Total scan time: {scan_duration:.2f}s")
    print(f"Ports scanned:   {len(results)}")
    print(f"Open ports:      {len(open_results)}")
    print(f"Closed ports:    {len(closed_results)}")
    print(f"Errors:          {len(error_results)}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    if args.threads <= 0:
        parser.error("--threads must be greater than 0")

    ports, invalid_parts, out_of_range = parse_ports(args.ports)
    if invalid_parts:
        print(f"Warning: ignored invalid port entries: {', '.join(invalid_parts)}")
    if out_of_range:
        print(f"Warning: ignored out-of-range ports: {', '.join(map(str, out_of_range))}")
    if not ports:
        parser.error("no valid ports selected")

    address = resolve_target(args.target)
    if address is None:
        parser.error(f"could not resolve target: {args.target}")

    print_header(args.target, address, ports, args)
    print("\nScanning... press Ctrl+C to stop.\n")

    results = []
    started_at = time.perf_counter()
    workers = min(args.threads, len(ports))

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {
                executor.submit(scan_port, address, port, args.timeout, not args.no_banners): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                result = future.result()
                results.append(result)

                if args.verbose or result["state"] == "open":
                    label = result["state"].upper()
                    print(f"[{label:<6}] {result['port']:>5}/tcp  {result['service']}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Writing partial results...")

    results.sort(key=lambda item: item["port"])
    scan_duration = time.perf_counter() - started_at

    print_summary(results, scan_duration, args.show_closed)

    output = {
        "target": args.target,
        "ip": address["ip"],
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "scan_duration_seconds": round(scan_duration, 2),
        "timeout_seconds": args.timeout,
        "threads": workers,
        "banner_grabbing": not args.no_banners,
        "results": results,
    }

    with open(args.output, "w", encoding="utf-8") as file:
        json.dump(output, file, indent=4)

    print("\n" + "=" * 56)
    print(f"Scan saved to {args.output}")
    print("Scan complete")
    print("=" * 56)


if __name__ == "__main__":
    main()
