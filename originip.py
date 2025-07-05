import argparse
import requests
import json
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def fetch_viewdns_ips(domain, api_key):
    """Fetch IPs from ViewDNS.info API"""
    url = f"https://api.viewdns.info/iphistory/?domain={domain}&apikey={api_key}&output=json"
    try:
        response = requests.get(url)
        data = response.json()
        
        # Debug: Print raw API response
        print("[DEBUG] ViewDNS Response:", json.dumps(data, indent=2))
        
        # Extract unique IPs
        ips = set()
        if data.get("response", {}).get("records"):
            for record in data["response"]["records"]:
                if "ip" in record:
                    ips.add(record["ip"])
        return list(ips)
        
    except Exception as e:
        print(f"[!] ViewDNS Error: {str(e)}")
        return []


def fetch_securitytrails_ips(domain, api_key):
    """Fetch IPs from SecurityTrails with proper error handling"""
    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    headers = {"APIKEY": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        # Extract all unique IPs
        ips = set()
        for record in data.get("records", []):
            for value in record.get("values", []):
                if "ip" in value:
                    ips.add(value["ip"])
        return list(ips)
    except requests.exceptions.HTTPError as e:
        print(f"[!] SecurityTrails HTTP Error: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        print(f"[!] SecurityTrails Error: {str(e)}")
    return []



def test_ip(ip, domain, port, timeout=3):
    """Test if an IP hosts the domain"""
    headers = {"Host": domain}
    try:
        response = requests.get(
            f"http://{ip}:{port}",
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )
        return {
            "ip": ip,
            "port": port,
            "status": response.status_code,
            "origin_server": response.status_code == 200,
            "error": None
        }
    except Exception as e:
        return {"ip": ip, "port": port, "status": None, "origin_server": False, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Find origin servers by testing historical IPs.")
    
    # Required arguments
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    
    # Data source selection
    parser.add_argument(
        "-s", "--source",
        choices=[ "securitytrails", "viewdns"],
        required=True,
        help="Data source: securitytrails or viewdns"
    )
    
    # API credentials (conditionally required)
    parser.add_argument("--api-key", help="API key (for viewdns/SecurityTrails)")
    
    
    # Testing options
    parser.add_argument("-p", "--port", type=int, default=80, help="Port to test (default: 80)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Threads for scanning (default: 5)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("-a", "--addresses", nargs="+", help="Manual IP addresses to test")
    
    args = parser.parse_args()
    
    # Fetch historical IPs based on selected source
    ips = []
    
    if args.source == "securitytrails":
        if not args.api_key:
            parser.error("SecurityTrails requires --api-key")
        ips = fetch_securitytrails_ips(args.domain, args.api_key)
    
    elif args.source == "viewdns":
        if not args.api_key:
            print("[!] ViewDNS requires --api-key")
            return
            
        print(f"[*] Querying ViewDNS for {args.domain}...")
        ips = fetch_viewdns_ips(args.domain, args.api_key)
        
        if not ips:
            print("[!] No IPs found from ViewDNS")
            return
        
    if args.addresses:
        ips = args.addresses if not ips else ips + args.addresses

    if not ips:
        print("[!] No IPs found. Try another source.")
        return
    
    print(f"[*] Testing {len(ips)} IPs from {args.source}...")
    
    # Threaded IP testing
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(test_ip, ip, args.domain, args.port) for ip in ips]
        for future in futures:
            results.append(future.result())
    
    # Print and save results
    print("\nResults:")
    for result in results:
        print(f"{result['ip']}:{result['port']} -> Status: {result['status']}, Origin: {result['origin_server']}")
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nSaved to {args.output}")

if __name__ == "__main__":
    main()