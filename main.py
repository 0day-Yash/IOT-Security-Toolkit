import argparse
from toolkit import scanning, vulnerability_assessment, exploitation

def main():
    parser = argparse.ArgumentParser(description="IoT Security Analysis and Exploitation Toolkit")
    
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan network and devices")
    scan_parser.add_argument("ip_range", help="IP range to scan")

    vuln_parser = subparsers.add_parser("vuln", help="Vulnerability assessment")
    vuln_parser.add_argument("ip", help="IP address of the device")
    vuln_parser.add_argument("service", help="Service to check for vulnerabilities")
    vuln_parser.add_argument("version", help="Service version")

    exploit_parser = subparsers.add_parser("exploit", help="Exploit vulnerabilities")
    exploit_parser.add_argument("ip", help="IP address of the device")
    exploit_parser.add_argument("service", help="Service to exploit")
    exploit_parser.add_argument("version", help="Service version")

    args = parser.parse_args()

    if args.command == "scan":
        devices = scanning.network_scan(args.ip_range)
        print("Devices found:", devices)
        for ip in devices:
            services = scanning.detect_services(ip)
            print(f"Services on {ip}:", services)
    
    elif args.command == "vuln":
        cve_results = vulnerability_assessment.search_cve(args.service, args.version)
        print("CVE Results:", cve_results)
    
    elif args.command == "exploit":
        exploits = exploitation.fetch_exploit(args.service, args.version)
        if exploits:
            payload = exploitation.generate_payload(args.ip, exploits[0])
            exploitation.exploit_target(args.ip, exploits[0], payload)
            print(f"Exploited {args.ip} with {exploits[0]}")
        else:
            print("No exploits found")

if __name__ == "__main__":
    main()

