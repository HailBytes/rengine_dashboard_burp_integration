# reNgine Dashboard to Burp Suite Integration Tool

A Python tool that seamlessly integrates reNgine reconnaissance data with Burp Suite Professional for enhanced web application security testing workflows.

## Features

- **Dashboard Integration**: Works with reNgine web dashboard deployments
- **SSL/TLS Support**: Handles self-signed certificates common in private deployments
- **Comprehensive Data Export**: Extracts subdomains, endpoints, and URLs from reNgine scans
- **Smart Filtering**: Identifies interesting endpoints (admin panels, APIs, etc.)
- **Burp Suite Integration**: 
  - Automatic scope configuration
  - Target import via REST API
  - Manual import file generation
- **Flexible Authentication**: Supports both authenticated and unauthenticated reNgine instances
- **Detailed Reporting**: Generates integration reports and CSV summaries

## Requirements

- Python 3.6+
- reNgine instance (accessible via web dashboard)
- Burp Suite Professional (for API integration)
- Required Python packages: `requests`, `urllib3`

## Installation

1. Clone this repository:
```bash
git clone https://github.com/HailBytes/rengine-burp-integration.git
cd rengine-burp-integration
```

2. Install dependencies:
```bash
pip3 install requests urllib3
```

3. Make the script executable:
```bash
chmod +x rengine_dashboard_burp_integration.py
```

## Usage

### Basic Usage (Files Only)
```bash
python3 rengine_dashboard_burp_integration.py <RENGINE_URL> <PROJECT_SLUG> <SCAN_ID>
```

### With Authentication
```bash
python3 rengine_dashboard_burp_integration.py <RENGINE_URL> <PROJECT_SLUG> <SCAN_ID> \
  --rengine-user <USERNAME> --rengine-pass <PASSWORD>
```

### With Burp Suite API Integration
```bash
python3 rengine_dashboard_burp_integration.py <RENGINE_URL> <PROJECT_SLUG> <SCAN_ID> \
  --rengine-user <USERNAME> --rengine-pass <PASSWORD> \
  --burp-api-key <BURP_API_KEY>
```

### Example
```bash
python3 rengine_dashboard_burp_integration.py https://rengine.company.com hailbytes-test-lab 6 \
  --rengine-user rengine --rengine-pass mypassword \
  --burp-api-key abc123def456
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `rengine_url` | reNgine dashboard URL | Required |
| `project_slug` | reNgine project slug | Required |
| `scan_id` | Scan ID to export | Required |
| `--rengine-user` | reNgine username | None |
| `--rengine-pass` | reNgine password | None |
| `--burp-api-url` | Burp REST API URL | `http://localhost:8090` |
| `--burp-api-key` | Burp API key | None |
| `--output-dir` | Output directory | `./rengine_burp_integration` |
| `--files-only` | Generate files only, skip API import | False |

## Output Files

The tool generates several files for Burp Suite integration:

- **burp_scope.txt**: Domain scope for Burp Suite
- **burp_targets.txt**: Live URLs for scanning
- **burp_priority_targets.txt**: High-priority endpoints (admin, API, etc.)
- **scan_summary.csv**: Comprehensive data overview
- **integration_report.txt**: Summary report

## SSL Certificate Handling

This tool is designed to work with self-signed SSL certificates commonly used in private reNgine deployments. SSL verification is automatically disabled to ensure compatibility.

## Burp Suite Setup

### Enable REST API
1. Open Burp Suite Professional
2. Go to Settings → Extensions → APIs
3. Enable "REST API" 
4. Generate an API key
5. Note the API endpoint (default: `http://localhost:8090`)

### Manual Import (if not using API)
1. Open Burp Suite Professional
2. Go to Target → Site map
3. Right-click and select "Add to scope" → "Load from file"
4. Import the generated scope and target files

## Troubleshooting

### SSL Certificate Errors
The tool automatically handles self-signed certificates. If you encounter SSL issues:
- Ensure you're using the correct protocol (HTTP vs HTTPS)
- Try using HTTP port 8082 if available
- Verify the reNgine URL is accessible in your browser

### Authentication Issues
- Verify username and password are correct
- Check if the reNgine instance requires authentication
- Ensure the user has appropriate permissions

### No Data Exported
- Verify the scan ID exists and has completed
- Check that the project slug is correct
- Ensure the scan contains the expected data types

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

### Professional Support
For enterprise support, deployment assistance, and custom integrations, contact [HailBytes](https://hailbytes.com/contact-us/).

### Community Support
Join our Discord community for questions, discussions, and community support: [HailBytes Discord](https://discord.gg/R4SUDQaUPG)

## Related Projects

- [reNgine](https://github.com/yogeshojha/rengine) - Automated reconnaissance framework
- [Burp Suite](https://portswigger.net/burp) - Web application security testing platform

## Disclaimer

This tool is for authorized security testing only. Users are responsible for complying with applicable laws and regulations.
