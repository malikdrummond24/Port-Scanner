import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
from cve_lookup import lookup_cves

from colorama import Fore, Style, init
init(autoreset=True)


COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
}

TIMEOUT = 1


def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            try:
                banner = s.recv(1024).decode().strip()
                return banner if banner else "No banner"
            except:
                return "No banner"
    except:
        return None


def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port)
                service = COMMON_PORTS.get(port, "Unknown")
                print(f"{Fore.GREEN}[+] Open port {port} ({service}) - Banner: {banner}{Style.RESET_ALL}")
                return (port, banner)
    except:
        pass
    return None


def scan_target(ip, ports, max_threads=100):
    print(f"[*] Scanning {ip}...")
    open_ports = []
    with ThreadPoolExecutor(max_threads) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports


def parse_ports(port_range):
    try:
        start, end = map(int, port_range.split('-'))
        if start < 1 or end > 65535 or start > end:
            raise ValueError
        return list(range(start, end + 1))
    except:
        print("Invalid port range. Use format like 20-100.")
        exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port Scanner with Banner Grabbing and CVE Lookup")
    parser.add_argument("--ip", required=True, help="Target IP or hostname to scan")
    parser.add_argument("--ports", help="Custom port range (e.g. 20-100)", default=None)
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")

    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.ip)
    except socket.gaierror:
        print("Invalid hostname.")
        exit()

    if args.ports:
        custom_ports = parse_ports(args.ports)
        results = scan_target(target_ip, ports=custom_ports, max_threads=args.threads)
    else:
        results = scan_target(target_ip, ports=COMMON_PORTS.keys(), max_threads=args.threads)

    print(f"\n{Fore.CYAN}Scan complete.{Style.RESET_ALL}")

    for port, banner in results:
        print(f"\n{Fore.CYAN}[PORT {port}] Banner: {banner}{Style.RESET_ALL}")
        cves = lookup_cves(banner)
        if cves:
            print(f"{Fore.RED}Top CVEs found:{Style.RESET_ALL}")
            for cve_id, summary in cves:
                print(f"{Fore.YELLOW} - {cve_id}: {summary}{Style.RESET_ALL}")
        else:
            print(f"{Fore.LIGHTBLACK_EX}No CVEs found.{Style.RESET_ALL}")

