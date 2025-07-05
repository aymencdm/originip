# OriginIP - Origin Server Discovery Tool

A powerful reconnaissance tool for bug bounty hunters and penetration testers to discover origin IP addresses of domains by testing historical DNS records from various sources.

## Features

- **Multiple Data Sources**: Supports SecurityTrails and ViewDNS.info APIs
- **Historical IP Discovery**: Fetches historical DNS A records to find previous IP addresses
- **Origin Server Detection**: Tests historical IPs to identify active origin servers
- **Concurrent Testing**: Multi-threaded scanning for faster results
- **Flexible Input**: Support for manual IP addresses alongside API sources
- **JSON Export**: Save results for further analysis

## Installation

### Prerequisites
- Python 3.6+
- Required packages: `requests`, `urllib3`

### Clone the Repository
```bash
git clone https://github.com/aymencdm/originip.git
cd originip
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

**Using SecurityTrails:**
```bash
python originip.py -d example.com -s securitytrails --api-key YOUR_API_KEY
```

**Using ViewDNS.info:**
```bash
python originip.py -d example.com -s viewdns --api-key YOUR_API_KEY
```

### Advanced Options

```bash
python originip.py -d example.com -s securitytrails --api-key YOUR_API_KEY \
  -p 443 \
  -t 10 \
  -o results.json \
  -a 192.168.1.1 192.168.1.2
```

### Command Line Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `-d, --domain` | Target domain (e.g., example.com) | Yes |
| `-s, --source` | Data source: `securitytrails` or `viewdns` | Yes |
| `--api-key` | API key for the selected service | Yes |
| `-p, --port` | Port to test (default: 80) | No |
| `-t, --threads` | Number of threads for scanning (default: 5) | No |
| `-o, --output` | Save results to JSON file | No |
| `-a, --addresses` | Manual IP addresses to test | No |

## API Setup

### SecurityTrails
1. Sign up at [SecurityTrails](https://securitytrails.com/)
2. Get your API key from the dashboard
3. Free tier includes 50 queries per month

### ViewDNS.info
1. Sign up at [ViewDNS.info](https://viewdns.info/)
2. Get your API key from account settings
3. Free tier includes 250 queries per month

## Example Output

```
[*] Testing 15 IPs from securitytrails...

Results:
203.0.113.1:80 -> Status: 200, Origin: True
203.0.113.2:80 -> Status: 403, Origin: False
203.0.113.3:80 -> Status: None, Origin: False
198.51.100.1:80 -> Status: 200, Origin: True
...

Saved to results.json
```

## Use Cases

- **Bug Bounty**: Discover origin servers behind CDNs like Cloudflare, AWS CloudFront
- **Penetration Testing**: Find direct access to web applications
- **Security Research**: Analyze infrastructure changes over time
- **OSINT**: Gather intelligence on target infrastructure

## Legal Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap

- [ ] Add support for more DNS history providers
- [ ] Implement SSL certificate historical data analysis
- [ ] Add subdomain enumeration integration
- [ ] Create web interface
- [ ] Add passive DNS lookup options

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v1.0.0
- Initial release
- SecurityTrails and ViewDNS.info support
- Multi-threaded scanning
- JSON export functionality

## Support

If you find this tool useful, consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs via Issues
- 💡 Suggesting new features
- 🔧 Contributing code improvements

## Credits

Created by [aymen benlamari] for the bug bounty and security research community.

---

**Happy Hunting! 🎯**
