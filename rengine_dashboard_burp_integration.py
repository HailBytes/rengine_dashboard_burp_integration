#!/usr/bin/env python3
"""
reNgine Dashboard to Local Burp Suite Integration
For testers accessing reNgine via web dashboard and running Burp Suite locally
FIXED VERSION - Handles SSL certificate issues
"""

import requests
import json
import csv
import time
import sys
import os
from urllib.parse import urlparse, urljoin
from pathlib import Path
import argparse
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(InsecureRequestWarning)

class ReNgineDashboardBurpIntegrator:
    def __init__(self, rengine_url, rengine_username=None, rengine_password=None, 
                 burp_api_url="http://localhost:8090", burp_api_key=None):
        """
        Initialize the integrator for dashboard-based reNgine access
        
        Args:
            rengine_url (str): reNgine dashboard URL (e.g., https://rengine.company.com)
            rengine_username (str): reNgine username (if auth required)
            rengine_password (str): reNgine password (if auth required)
            burp_api_url (str): Local Burp REST API endpoint
            burp_api_key (str): Burp API key for authentication
        """
        self.rengine_url = rengine_url.rstrip('/')
        self.rengine_session = requests.Session()
        
        # DISABLE SSL VERIFICATION - Critical fix for self-signed certs
        self.rengine_session.verify = False
        
        # Set longer timeouts
        self.rengine_session.timeout = 30
        
        # Add user agent to avoid potential blocking
        self.rengine_session.headers.update({
            'User-Agent': 'reNgine-Burp-Integrator/1.0'
        })
        
        self.burp_api_url = burp_api_url.rstrip('/')
        self.burp_api_key = burp_api_key
        
        # Setup Burp headers
        self.burp_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if burp_api_key:
            self.burp_headers['API-KEY'] = burp_api_key
        
        # Authenticate to reNgine if credentials provided
        if rengine_username and rengine_password:
            self.authenticate_rengine(rengine_username, rengine_password)
    
    def authenticate_rengine(self, username, password):
        """
        Authenticate to reNgine dashboard
        
        Args:
            username (str): reNgine username
            password (str): reNgine password
            
        Returns:
            bool: Authentication success status
        """
        try:
            print(f"Attempting to authenticate to {self.rengine_url}...")
            
            # Get login page for CSRF token
            login_page = self.rengine_session.get(
                f"{self.rengine_url}/login/", 
                verify=False,  # Explicitly disable SSL verification
                timeout=30,
                allow_redirects=True
            )
            
            print(f"Login page status: {login_page.status_code}")
            print(f"Login page URL: {login_page.url}")
            
            if login_page.status_code != 200:
                print(f"Failed to access login page: {login_page.status_code}")
                return False
            
            # Extract CSRF token (adjust based on reNgine's implementation)
            csrf_token = None
            if 'csrfmiddlewaretoken' in login_page.text:
                import re
                csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', login_page.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                    print(f"Found CSRF token: {csrf_token[:10]}...")
                else:
                    print("CSRF token pattern found but could not extract value")
            else:
                print("No CSRF token found in login page")
            
            # Prepare login data
            login_data = {
                'username': username,
                'password': password,
            }
            if csrf_token:
                login_data['csrfmiddlewaretoken'] = csrf_token
            
            print(f"Submitting login for user: {username}")
            
            # Submit login
            response = self.rengine_session.post(
                f"{self.rengine_url}/login/",
                data=login_data,
                headers={'Referer': f"{self.rengine_url}/login/"},
                verify=False,  # Explicitly disable SSL verification
                timeout=30,
                allow_redirects=True
            )
            
            print(f"Login response status: {response.status_code}")
            print(f"Final URL after login: {response.url}")
            
            # Check if authentication was successful
            if response.status_code == 200:
                if 'dashboard' in response.url.lower() or 'dashboard' in response.text.lower():
                    print("Successfully authenticated to reNgine")
                    return True
                elif 'login' in response.url.lower():
                    print("Authentication failed - still on login page")
                    print("Response text preview:", response.text[:500])
                    return False
                else:
                    print("Authentication appears successful (different redirect)")
                    return True
            else:
                print(f"Authentication failed with status: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Error authenticating to reNgine: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def download_scan_results(self, project_slug, scan_id, output_dir="./rengine_exports"):
        """
        Download scan results from reNgine dashboard
        
        Args:
            project_slug (str): reNgine project slug
            scan_id (int): Scan ID to export
            output_dir (str): Local directory to save exports
            
        Returns:
            dict: Paths to downloaded files
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        exported_files = {}
        export_types = {
            'subdomains': f"{self.rengine_url}/export/subdomains/{scan_id}",
            'endpoints': f"{self.rengine_url}/export/endpoints/{scan_id}",
            'urls': f"{self.rengine_url}/export/urls/{scan_id}"
        }
        
        for export_type, url in export_types.items():
            try:
                print(f"Downloading {export_type} from {url}...")
                response = self.rengine_session.get(
                    url, 
                    verify=False,  # Explicitly disable SSL verification
                    timeout=60,    # Longer timeout for large exports
                    allow_redirects=True
                )
                
                print(f"Response status for {export_type}: {response.status_code}")
                
                if response.status_code == 200:
                    filename = f"{export_type}_scan_{scan_id}.txt"
                    filepath = os.path.join(output_dir, filename)
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(response.text)
                    
                    exported_files[export_type] = filepath
                    
                    # Count lines for feedback
                    lines = [line.strip() for line in response.text.split('\n') if line.strip()]
                    print(f"Downloaded {len(lines)} {export_type} to {filepath}")
                    
                elif response.status_code == 404:
                    print(f"Export endpoint not found for {export_type} (scan may not have this data)")
                elif response.status_code == 403:
                    print(f"Access denied for {export_type} - check authentication")
                else:
                    print(f"Failed to download {export_type}: HTTP {response.status_code}")
                    print(f"Response preview: {response.text[:200]}...")
                    
            except Exception as e:
                    print(f"Error downloading {export_type}: {e}")
        
        return exported_files
    
    def fetch_scan_metadata(self, project_slug, scan_id):
        """
        Fetch additional scan metadata from reNgine API
        
        Args:
            project_slug (str): reNgine project slug  
            scan_id (int): Scan ID
            
        Returns:
            dict: Scan metadata
        """
        try:
            # Try to get scan details via API
            api_url = f"{self.rengine_url}/api/{project_slug}/scan/{scan_id}/"
            print(f"Fetching metadata from: {api_url}")
            
            response = self.rengine_session.get(
                api_url, 
                verify=False,  # Explicitly disable SSL verification
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Could not fetch scan metadata: HTTP {response.status_code}")
                # Try alternative API endpoints
                alt_urls = [
                    f"{self.rengine_url}/api/scan/{scan_id}/",
                    f"{self.rengine_url}/scan/{project_slug}/{scan_id}/",
                ]
                
                for alt_url in alt_urls:
                    try:
                        print(f"Trying alternative URL: {alt_url}")
                        alt_response = self.rengine_session.get(alt_url, verify=False, timeout=30)
                        if alt_response.status_code == 200:
                            return alt_response.json()
                    except:
                        continue
                
                return {}
                
        except Exception as e:
            print(f"Error fetching scan metadata: {e}")
            return {}
    
    def parse_exported_files(self, exported_files):
        """
        Parse exported files and organize data
        
        Args:
            exported_files (dict): Dictionary of file paths
            
        Returns:
            dict: Organized scan data
        """
        scan_data = {
            'subdomains': [],
            'endpoints': [],
            'urls': [],
            'live_subdomains': [],
            'interesting_endpoints': []
        }
        
        for data_type, filepath in exported_files.items():
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f.readlines() if line.strip()]
                    scan_data[data_type] = lines
                    print(f"Parsed {len(lines)} {data_type}")
        
        # Filter for live subdomains (those with HTTP/HTTPS)
        scan_data['live_subdomains'] = [
            url for url in scan_data.get('urls', []) 
            if url.startswith(('http://', 'https://'))
        ]
        
        # Filter for interesting endpoints (admin, api, etc.)
        interesting_keywords = ['admin', 'api', 'login', 'dashboard', 'panel', 'config', 'backup']
        scan_data['interesting_endpoints'] = [
            endpoint for endpoint in scan_data.get('endpoints', [])
            if any(keyword in endpoint.lower() for keyword in interesting_keywords)
        ]
        
        return scan_data
    
    def create_burp_import_files(self, scan_data, output_dir="./burp_imports"):
        """
        Create properly formatted files for Burp Suite import
        
        Args:
            scan_data (dict): Organized scan data
            output_dir (str): Directory for Burp import files
            
        Returns:
            dict: Paths to Burp import files
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        import_files = {}
        
        # Create scope file (unique domains/subdomains)
        scope_domains = list(set(scan_data['subdomains'] + 
                                [urlparse(url).netloc for url in scan_data['live_subdomains']]))
        
        scope_file = os.path.join(output_dir, "burp_scope.txt")
        with open(scope_file, 'w') as f:
            for domain in scope_domains:
                if domain:  # Skip empty domains
                    f.write(f"https://{domain}\n")
        import_files['scope'] = scope_file
        
        # Create target URLs file (live endpoints)
        targets_file = os.path.join(output_dir, "burp_targets.txt")
        with open(targets_file, 'w') as f:
            for url in scan_data['live_subdomains'] + scan_data['endpoints']:
                if url.startswith(('http://', 'https://')):
                    f.write(f"{url}\n")
        import_files['targets'] = targets_file
        
        # Create high-priority targets (interesting endpoints)
        priority_file = os.path.join(output_dir, "burp_priority_targets.txt")
        with open(priority_file, 'w') as f:
            for endpoint in scan_data['interesting_endpoints']:
                f.write(f"{endpoint}\n")
        import_files['priority'] = priority_file
        
        # Create CSV for manual review
        csv_file = os.path.join(output_dir, "scan_summary.csv")
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'URL', 'Notes'])
            
            for subdomain in scan_data['subdomains']:
                writer.writerow(['Subdomain', subdomain, ''])
            
            for endpoint in scan_data['interesting_endpoints']:
                writer.writerow(['Interesting Endpoint', endpoint, 'High Priority'])
                
            for url in scan_data['live_subdomains'][:50]:  # Limit for readability
                writer.writerow(['Live URL', url, 'Active'])
        
        import_files['csv'] = csv_file
        
        print(f"\nCreated Burp import files in {output_dir}:")
        for file_type, filepath in import_files.items():
            file_size = os.path.getsize(filepath)
            print(f"  - {file_type}: {filepath} ({file_size} bytes)")
        
        return import_files
    
    def import_to_burp_via_api(self, scan_data, max_targets=100):
        """
        Import data directly to Burp via REST API
        
        Args:
            scan_data (dict): Organized scan data
            max_targets (int): Maximum targets to import (to avoid overloading)
            
        Returns:
            bool: Success status
        """
        try:
            print(f"\nImporting data to Burp Suite via REST API...")
            
            # Step 1: Add scope
            scope_targets = scan_data['live_subdomains'][:max_targets]
            for target in scope_targets:
                try:
                    response = requests.put(
                        f"{self.burp_api_url}/burp/target/scope?url={target}",
                        headers=self.burp_headers,
                        timeout=10
                    )
                    if response.status_code in [200, 201]:
                        print(f"Added {target} to scope")
                    else:
                        print(f"Failed to add {target}: HTTP {response.status_code}")
                except Exception as e:
                    print(f"Error adding {target}: {e}")
            
            # Step 2: Import priority targets
            if scan_data['interesting_endpoints']:
                priority_targets = scan_data['interesting_endpoints'][:20]  # Top 20
                try:
                    payload = {"urls": priority_targets}
                    response = requests.post(
                        f"{self.burp_api_url}/burp/target/sitemap",
                        headers=self.burp_headers,
                        data=json.dumps(payload),
                        timeout=30
                    )
                    if response.status_code in [200, 201]:
                        print(f"Imported {len(priority_targets)} priority endpoints")
                    else:
                        print(f"Failed to import priority endpoints: HTTP {response.status_code}")
                except Exception as e:
                    print(f"Error importing priority endpoints: {e}")
            
            print("Burp import completed!")
            return True
            
        except Exception as e:
            print(f"Error during Burp import: {e}")
            return False
    
    def generate_integration_report(self, scan_data, scan_metadata, output_dir):
        """
        Generate a summary report of the integration
        
        Args:
            scan_data (dict): Scan data
            scan_metadata (dict): Scan metadata
            output_dir (str): Output directory
        """
        report_file = os.path.join(output_dir, "integration_report.txt")
        
        with open(report_file, 'w') as f:
            f.write("reNgine -> Burp Suite Integration Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Scan ID: {scan_metadata.get('id', 'Unknown')}\n")
            f.write(f"Target Domain: {scan_metadata.get('domain', 'Unknown')}\n")
            f.write(f"Scan Date: {scan_metadata.get('start_scan_date', 'Unknown')}\n\n")
            
            f.write("Data Summary:\n")
            f.write(f"- Total Subdomains: {len(scan_data['subdomains'])}\n")
            f.write(f"- Live URLs: {len(scan_data['live_subdomains'])}\n")
            f.write(f"- Total Endpoints: {len(scan_data['endpoints'])}\n")
            f.write(f"- Interesting Endpoints: {len(scan_data['interesting_endpoints'])}\n\n")
            
            f.write("Next Steps:\n")
            f.write("1. Review imported targets in Burp Suite Target tab\n")
            f.write("2. Configure scan settings in Burp Dashboard\n")
            f.write("3. Start with spider/crawl on priority targets\n")
            f.write("4. Run active scans on interesting endpoints\n")
            f.write("5. Review findings and generate reports\n")
        
        print(f"Integration report saved to: {report_file}")


def main():
    parser = argparse.ArgumentParser(description='Integrate reNgine dashboard with local Burp Suite')
    parser.add_argument('rengine_url', help='reNgine dashboard URL (e.g., https://rengine.company.com)')
    parser.add_argument('project_slug', help='reNgine project slug')
    parser.add_argument('scan_id', type=int, help='Scan ID to export')
    parser.add_argument('--rengine-user', help='reNgine username (if authentication required)')
    parser.add_argument('--rengine-pass', help='reNgine password (if authentication required)')
    parser.add_argument('--burp-api-url', default='http://localhost:8090', help='Burp REST API URL')
    parser.add_argument('--burp-api-key', help='Burp API key')
    parser.add_argument('--output-dir', default='./rengine_burp_integration', help='Output directory')
    parser.add_argument('--files-only', action='store_true', help='Only generate files, skip API import')
    
    args = parser.parse_args()
    
    print("Starting reNgine Dashboard -> Burp Suite Integration (SSL-Fixed Version)")
    print(f"reNgine URL: {args.rengine_url}")
    print(f"Project: {args.project_slug}")
    print(f"Scan ID: {args.scan_id}")
    print("-" * 60)
    
    # Initialize integrator
    integrator = ReNgineDashboardBurpIntegrator(
        rengine_url=args.rengine_url,
        rengine_username=args.rengine_user,
        rengine_password=args.rengine_pass,
        burp_api_url=args.burp_api_url,
        burp_api_key=args.burp_api_key
    )
    
    # Create output directory
    output_dir = args.output_dir
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    try:
        # Step 1: Download scan results
        print("\nDownloading scan results from reNgine...")
        exported_files = integrator.download_scan_results(
            args.project_slug, 
            args.scan_id, 
            os.path.join(output_dir, "exports")
        )
        
        if not exported_files:
            print("No data exported from reNgine. Check credentials and scan ID.")
            print("\nTroubleshooting tips:")
            print("1. Verify the scan ID exists and has completed")
            print("2. Check if authentication was successful")
            print("3. Try accessing the export URLs manually in your browser")
            return
        
        # Step 2: Parse the data
        print("\nParsing exported data...")
        scan_data = integrator.parse_exported_files(exported_files)
        
        # Step 3: Fetch metadata
        scan_metadata = integrator.fetch_scan_metadata(args.project_slug, args.scan_id)
        
        # Step 4: Create Burp import files
        print("\nCreating Burp Suite import files...")
        import_files = integrator.create_burp_import_files(
            scan_data, 
            os.path.join(output_dir, "burp_imports")
        )
        
        # Step 5: Import to Burp (if not files-only mode)
        if not args.files_only and args.burp_api_key:
            integrator.import_to_burp_via_api(scan_data)
        elif not args.files_only:
            print("\nSkipping API import - no Burp API key provided")
            print("Use --burp-api-key to enable direct import")
        
        # Step 6: Generate report
        integrator.generate_integration_report(
            scan_data, 
            scan_metadata, 
            output_dir
        )
        
        print(f"\nIntegration completed successfully!")
        print(f"All files saved to: {output_dir}")
        
        if args.files_only or not args.burp_api_key:
            print("\nManual Import Instructions:")
            print("1. Open Burp Suite Professional")
            print("2. Go to Target -> Site map")
            print(f"3. Import scope from: {import_files['scope']}")
            print(f"4. Import targets from: {import_files['targets']}")
            print(f"5. Start with priority targets: {import_files['priority']}")
        
    except Exception as e:
        print(f"\nIntegration failed: {e}")
        import traceback
        traceback.print_exc()
        
        print("\nTroubleshooting suggestions:")
        print("1. Check if reNgine is accessible in your browser")
        print("2. Verify username/password are correct")
        print("3. Ensure the scan ID exists and has completed")
        print("4. Try running with --files-only first to test basic connectivity")


if __name__ == "__main__":
    main()