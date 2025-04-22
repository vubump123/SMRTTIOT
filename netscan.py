import socket
import ipaddress
import subprocess
import concurrent.futures
import platform
import time
from datetime import datetime
import re
import requests
from mac_vendor_lookup import MacLookup
import nmap
import pandas as pd
import io
import os
import threading

# Default CSV URL for IoT default passwords
CSV_URL = "https://raw.githubusercontent.com/Edd13Mora/IoTPass/main/DefaultCreds-Cheat-Sheet.csv"

class DefaultPasswordChecker:
    def __init__(self):
        self.df = None
        self.load_status = "Not loaded"
        self.device_ports = {}
        
    def load_default_passwords(self, url=CSV_URL, local_file=None, status_callback=None):
        """
        Downloads and loads the CSV file from the GitHub repository into a pandas DataFrame.
        
        Args:
            url: URL to download the CSV from
            local_file: Path to local file if available
            status_callback: Function to call with status updates
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if status_callback:
                status_callback("Loading default password database...")
                
            if local_file and os.path.exists(local_file):
                # Try to load from local file first
                if status_callback:
                    status_callback(f"Loading password database from local file: {local_file}")
                try:
                    self.df = pd.read_csv(local_file)
                    if status_callback:
                        status_callback(f"Successfully loaded database from: {local_file}")
                except Exception as e:
                    if status_callback:
                        status_callback(f"Error loading from local file: {str(e)}. Will try downloading instead.")
                    # If local file is corrupt or unreadable, we'll download a fresh copy
                    self.df = None
            
            # If we couldn't load from local file, download from URL
            if self.df is None:
                # Download from URL
                if status_callback:
                    status_callback(f"Downloading password database from: {url}")
                try:
                    response = requests.get(url, timeout=10)  # Add timeout
                    response.raise_for_status()  # Raise an exception for any HTTP errors
                    
                    # Parse the CSV data
                    self.df = pd.read_csv(io.StringIO(response.text))
                    
                    # Save a local copy for future use
                    if local_file:
                        try:
                            # Make sure the directory exists
                            directory = os.path.dirname(os.path.abspath(local_file))
                            if directory:
                                os.makedirs(directory, exist_ok=True)
                                
                            self.df.to_csv(local_file, index=False)
                            if status_callback:
                                status_callback(f"Default password database saved to: {local_file}")
                        except Exception as e:
                            if status_callback:
                                status_callback(f"Warning: Could not save database to {local_file}: {str(e)}")
                except requests.exceptions.RequestException as e:
                    if status_callback:
                        status_callback(f"Error downloading from {url}: {str(e)}")
                    return False
                except Exception as e:
                    if status_callback:
                        status_callback(f"Error processing downloaded data: {str(e)}")
                    return False
            
            if self.df is None:
                # If we still don't have data, return failure
                if status_callback:
                    status_callback("Failed to load password database from any source")
                return False
                
            # Clean up column names (remove whitespace, etc.)
            self.df.columns = self.df.columns.str.strip()
            
            num_records = len(self.df)
            if status_callback:
                status_callback(f"Successfully loaded {num_records} default credentials")
            
            self.load_status = f"Loaded {num_records} default credentials"
            return True
            
        except Exception as e:
            error_msg = f"Error loading password database: {str(e)}"
            if status_callback:
                status_callback(error_msg)
            self.load_status = error_msg
            return False

    def check_manual_password(self, password, status_callback=None):
        """
        Checks if a provided password is in the list of default passwords.
        
        Args:
            password: Password to check
            status_callback: Function to call with status updates
            
        Returns:
            bool: True if password is a default one, False otherwise
        """
        if self.df is None:
            if status_callback:
                status_callback("Error: Password database not loaded")
            return False, "Database not loaded"
        
        # Make sure 'Password' column exists (could be named differently)
        password_cols = [col for col in self.df.columns if 'password' in col.lower()]
        if not password_cols:
            if status_callback:
                status_callback("Error: No password column found in database")
            return False, "No password column found"
        
        password_col = password_cols[0]
        
        # Check if password is in the default passwords list
        result = password in self.df[password_col].astype(str).values
        
        if result:
            if status_callback:
                status_callback(f"WARNING: The password '{password}' is a known default password!")
            return True, "Default password detected"
        else:
            if status_callback:
                status_callback(f"Password '{password}' is not found in the default password list.")
            return False, "Password not in default list"

    def check_device_passwords(self, devices, username_col='username', password_col='password;', status_callback=None):
        """
        Checks each device against the default password database with improved error handling.
        
        Args:
            devices: List of device dictionaries from netscan
            username_col, password_col: Column names in the default credentials database
            status_callback: Function to call with status updates
            
        Returns:
            dict: Results of password checks for each device
        """
        if self.df is None:
            if status_callback:
                status_callback("Error: Password database not loaded. Attempting to load now...")
            try:
                self.load_default_passwords(status_callback=status_callback)
            except:
                if status_callback:
                    status_callback("Failed to load password database. Cannot check credentials.")
                return {}
                
        if self.df is None:  # Still None after load attempt
            if status_callback:
                status_callback("Error: Password database not loaded")
            return {}
            
        results = {}
        
        # Make sure username and password columns exist, using column name detection
        all_cols = list(self.df.columns)
        username_col = next((col for col in all_cols if 'user' in col.lower()), None)
        password_col = next((col for col in all_cols if 'pass' in col.lower()), None)
        
        if not username_col or not password_col:
            if status_callback:
                status_callback(f"Error: Could not identify username/password columns in database. Found: {all_cols}")
            return {}
            
        if status_callback:
            status_callback(f"Using columns '{username_col}' and '{password_col}' for credential checking")
        
        for device in devices:
            device_ip = device.get('ip', 'Unknown')
            vendor = device.get('vendor', '').lower()
            
            if not vendor:
                if status_callback:
                    status_callback(f"Skipping device {device_ip}: No vendor information")
                continue
                    
            if status_callback:
                status_callback(f"Checking default credentials for {device_ip} ({vendor})")
                    
            # Filter the default passwords by vendor - more flexible search that looks at all columns
            try:
                # Convert all values to string for safe searching
                string_df = self.df.astype(str)
                
                # Look for vendor name in any column
                filtered_df = self.df[string_df.apply(lambda row: any(vendor in str(val).lower() for val in row), axis=1)]
                
                if filtered_df.empty:
                    # Try with partial matching - look for parts of the vendor name (3+ chars)
                    if len(vendor) >= 3:
                        vendor_parts = [part for part in vendor.split() if len(part) >= 3]
                        for part in vendor_parts:
                            part_filtered = self.df[string_df.apply(lambda row: any(part in str(val).lower() for val in row), axis=1)]
                            if not part_filtered.empty:
                                filtered_df = part_filtered
                                if status_callback:
                                    status_callback(f"Found credentials using partial vendor match: '{part}'")
                                break
            except Exception as e:
                if status_callback:
                    status_callback(f"Error filtering credentials for {device_ip}: {str(e)}")
                filtered_df = pd.DataFrame()
            
            if filtered_df.empty:
                if status_callback:
                    status_callback(f"No default credentials found for vendor: {vendor}")
                results[device_ip] = {
                    'device': device,
                    'check_result': 'No default credentials found for this vendor',
                    'default_credentials': []
                }
            else:
                # Get list of default credentials for this vendor
                default_creds = []
                
                try:
                    for _, row in filtered_df.iterrows():
                        username = str(row.get(username_col, "admin"))  # Default to admin if missing
                        password = str(row.get(password_col, ""))      # Empty string if missing
                        
                        # Skip entries with empty usernames or passwords
                        if username and password:
                            default_creds.append({
                                'username': username,
                                'password': password
                            })
                except Exception as e:
                    if status_callback:
                        status_callback(f"Error processing credential row: {str(e)}")
                
                if status_callback:
                    status_callback(f"Found {len(default_creds)} default credentials for vendor: {vendor}")
                    
                results[device_ip] = {
                    'device': device,
                    'check_result': f'Found {len(default_creds)} default credentials for this vendor',
                    'default_credentials': default_creds
                }
                    
        return results

    def attempt_login(self, device_ip, username, password, ports=None, status_callback=None):
        """
        Attempts to log into a device using the provided credentials.
        """
        if status_callback:
            status_callback(f"Attempting login to {device_ip} with {username}:{password}")
    
    # Use provided ports list or fall back to stored device ports
    # Fix the issue with device_ports being a list instead of a dictionary
        if ports is not None:
            device_ports = ports
        elif isinstance(self.device_ports, dict) and device_ip in self.device_ports:
            device_ports = self.device_ports[device_ip]
        else:
            device_ports = []
    
        if not device_ports:
            if status_callback:
                status_callback(f"No open ports known for {device_ip}. Trying common ports.")
        # Try common ports as fallback
            device_ports = [(22, 'ssh'), (23, 'telnet'), (80, 'http'), (8080, 'http')]
        
        # Organize ports by protocol for more efficient checking
        ssh_ports = [p for p, s in device_ports if p == 22 or 'ssh' in str(s).lower()]
        telnet_ports = [p for p, s in device_ports if p == 23 or 'telnet' in str(s).lower()] 
        http_ports = [p for p, s in device_ports if p in (80, 8080, 8000, 443, 8443) or 'http' in str(s).lower()]
        
        # If no protocol-specific ports found, add defaults
        if not ssh_ports and 22 not in [p for p, _ in device_ports]:
            ssh_ports = [22]
        if not telnet_ports and 23 not in [p for p, _ in device_ports]:
            telnet_ports = [23]
        if not http_ports and not any(p in [80, 8080] for p, _ in device_ports):
            http_ports = [80, 8080]
        
        # Prioritize protocols by security (SSH, HTTP, Telnet)
        protocols_to_try = []
        
        # Try SSH first (most secure)
        for port in ssh_ports:
            protocols_to_try.append(('ssh', port))
        
        # Try HTTP next
        for port in http_ports:
            protocols_to_try.append(('http', port))
        
        # Try Telnet last (least secure)
        for port in telnet_ports:
            protocols_to_try.append(('telnet', port))
        
        # Try each protocol
        for proto, port in protocols_to_try:
            if status_callback:
                status_callback(f"Trying {proto} on port {port}...")
            
            try:
                if proto == 'ssh':
                    result, msg = self._try_ssh_login(device_ip, username, password, port, status_callback)
                elif proto == 'telnet':
                    result, msg = self._try_telnet_login(device_ip, username, password, port, status_callback)
                elif proto == 'http':
                    result, msg = self._try_http_login(device_ip, username, password, port, status_callback)
                else:
                    if status_callback:
                        status_callback(f"Unsupported protocol: {proto}")
                    continue
                
                if result:
                    return True, f"Successfully logged in via {proto} on port {port}: {msg}"
            except Exception as e:
                if status_callback:
                    status_callback(f"Error trying {proto} login on port {port}: {str(e)}")
        
        return False, "Login failed with all available protocols"

    def _try_ssh_login(self, ip, username, password, port=22, status_callback=None):
        """Attempts SSH login"""
        try:
            import paramiko
        
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
            if status_callback:
                status_callback(f"Connecting to {ip}:{port} via SSH...")
            
            client.connect(
                hostname=ip,
                port=port,
                username=username,
                password=password,
                timeout=5
            )
        
            if status_callback:
                status_callback("SSH login successful!")
            
        # Execute a simple command to verify access
            stdin, stdout, stderr = client.exec_command('echo "Login successful"')
            output = stdout.read().decode()
        
            client.close()
            return True, "SSH login successful"
    
        except ImportError:
            return False, "Paramiko library not installed. Install with: pip install paramiko"
        except Exception as e:
            return False, f"SSH login failed: {str(e)}"

    def _try_telnet_login(self, ip, username, password, port=23, status_callback=None):
        """Attempts Telnet login"""
        try:
            import telnetlib
        
            if status_callback:
                status_callback(f"Connecting to {ip}:{port} via Telnet...")
            
            tn = telnetlib.Telnet(ip, port, timeout=5)
        
        # Handle login prompt (this may need customization based on device)
            tn.read_until(b"login: ", timeout=5)
            tn.write(username.encode('ascii') + b"\n")
        
            tn.read_until(b"Password: ", timeout=5)
            tn.write(password.encode('ascii') + b"\n")
        
        # Read response to check for successful login
            response = tn.read_some()
            tn.close()
        
            if b"Login failed" in response or b"incorrect" in response.lower():
                return False, "Telnet login failed: Incorrect credentials"
        
            if status_callback:
                status_callback("Telnet login successful!")
            
            return True, "Telnet login successful"
    
        except Exception as e:
            return False, f"Telnet login failed: {str(e)}"

    def _try_http_login(self, ip, username, password, port=80, status_callback=None):
        """Attempts HTTP login (basic authentication)"""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
        
            if status_callback:
                status_callback(f"Connecting to {ip}:{port} via HTTP...")
            
        # Try basic auth first
            response = requests.get(
                f"http://{ip}:{port}",
                auth=HTTPBasicAuth(username, password),
                timeout=5
            )
        
            if response.status_code == 200:
                if status_callback:
                    status_callback("HTTP Basic Auth successful!")
                return True, "HTTP Basic Auth successful"
        
        # Try form-based login (this is very device-specific and would need customization)
        # This is just a simple example
            login_url = f"http://{ip}:{port}/login"
            data = {
                'username': username,
                'password': password
            }
        
            response = requests.post(login_url, data=data, timeout=5)
        
        # Check if login was successful (this logic would need customization)
            if "login successful" in response.text.lower() or "welcome" in response.text.lower():
                if status_callback:
                    status_callback("HTTP Form login successful!")
                return True, "HTTP Form login successful"
        
            return False, "HTTP login failed"
    
        except Exception as e:
            return False, f"HTTP login failed: {str(e)}"
        
    def brute_force_device(self, device, status_callback=None):
        """
        Checks a device against default credentials for its vendor.
        
        Args:
            device: Device dictionary from netscan
            status_callback: Function to call with status updates
            
        Returns:
            tuple: (success, results)
        """
        if self.df is None:
            if status_callback:
                status_callback("Error: Password database not loaded")
            return False, "Database not loaded"
            
        device_ip = device.get('ip', 'Unknown')
        vendor = device.get('vendor', '').lower()
        
        if not vendor:
            if status_callback:
                status_callback(f"Cannot check device {device_ip}: No vendor information")
            return False, "No vendor information available"
            
        if status_callback:
            status_callback(f"Looking for default credentials for {device_ip} ({vendor})")
            
        # Find default credentials for this vendor using improved matching
        try:
            # Convert all values to string for safe searching
            string_df = self.df.astype(str)
            
            # Look for vendor name in any column
            filtered_df = self.df[string_df.apply(lambda row: any(vendor in str(val).lower() for val in row), axis=1)]
            
            if filtered_df.empty:
                # Try with partial matching - look for parts of the vendor name (3+ chars)
                if len(vendor) >= 3:
                    vendor_parts = [part for part in vendor.split() if len(part) >= 3]
                    for part in vendor_parts:
                        part_filtered = self.df[string_df.apply(lambda row: any(part in str(val).lower() for val in row), axis=1)]
                        if not part_filtered.empty:
                            filtered_df = part_filtered
                            if status_callback:
                                status_callback(f"Found credentials using partial vendor match: '{part}'")
                            break
        except Exception as e:
            if status_callback:
                status_callback(f"Error filtering credentials for {device_ip}: {str(e)}")
            return False, f"Error processing database: {str(e)}"
            
        if filtered_df.empty:
            if status_callback:
                status_callback(f"No default credentials found for vendor: {vendor}")
            return False, "No default credentials found"
        
        # Get column names
        all_cols = list(self.df.columns)
        username_col = next((col for col in all_cols if 'user' in col.lower()), None)
        password_col = next((col for col in all_cols if 'pass' in col.lower()), None)
        
        if not username_col or not password_col:
            if status_callback:
                status_callback(f"Error: Could not identify username/password columns in database. Found: {all_cols}")
            return False, "Column names not found in database"
        
        results = []
        
        for _, row in filtered_df.iterrows():
            try:
                default_username = str(row.get(username_col, "admin"))  # Default to admin if missing
                default_password = str(row.get(password_col, ""))      # Empty string if missing
                
                # Skip entries with empty passwords
                if not default_password:
                    continue
                    
                if status_callback:
                    status_callback(f"Default credential found - Username: {default_username}, Password: {default_password}")
                    
                results.append({
                    'username': default_username,
                    'password': default_password,
                    'vendor': vendor
                })
            except Exception as e:
                if status_callback:
                    status_callback(f"Error processing credential row: {str(e)}")
            
        return (True, results) if results else (False, "No valid credentials found")

# Global instance for easy import
password_checker = DefaultPasswordChecker()

# Function to load passwords in background
def load_passwords_async(callback=None, local_file="default_passwords.csv"):
    """
    Load the default password database in a background thread
    """
    def _load_thread():
        success = password_checker.load_default_passwords(local_file=local_file, 
                                                         status_callback=callback)
        if callback and success:
            callback("Default password database loaded successfully")
            
    thread = threading.Thread(target=_load_thread)
    thread.daemon = True
    thread.start()
    return thread

def scan_iot_devices(network_range='10.0.0.0/24', timeout=1, max_workers=100, 
                    export_all=True, export_iot=True,
                    all_devices_file='all_devices.txt', 
                    iot_devices_file='iot_devices.txt',
                    check_default_passwords=False,
                    password_db_file="default_passwords.csv",
                    credential_report_file="credential_report.txt",
                    progress_callback=None, 
                    status_callback=None):
    """
    Comprehensive function to scan a network for IoT devices with GUI callbacks.
    
    Args:
        network_range (str): CIDR notation of the network to scan (e.g., '192.168.1.0/24')
        timeout (float): Timeout for ping and port scan operations in seconds
        max_workers (int): Maximum number of concurrent workers for scanning
        export_all (bool): Whether to export all devices to a file
        export_iot (bool): Whether to export IoT devices to a file
        all_devices_file (str): Filename for all devices report
        iot_devices_file (str): Filename for IoT devices report
        check_default_passwords (bool): Whether to check for default passwords
        password_db_file (str): File path for the password database
        credential_report_file (str): File path for the credential report
        progress_callback (function): Callback function for progress updates (percentage)
        status_callback (function): Callback function for status message updates
        
    Returns:
        tuple: (iot_devices, all_devices, credential_results) - Lists and dict of discovered devices and credentials
    """
    # Initialize variables
    discovered_devices = []
    credential_results = {}
    start_time = time.time()
    
    # Helper function to update status
    def update_status(message):
        if status_callback:
            status_callback(message)
        else:
            print(message)
    
    # Helper function to update progress
    def update_progress(percent):
        if progress_callback:
            progress_callback(percent)
    
    # Common IoT manufacturers
    iot_manufacturers = [
        'espressif', 'raspberry', 'arduino', 'nest', 'ring', 'ecobee', 'philips', 'samsung',
        'xiaomi', 'huawei', 'broadlink', 'tp-link', 'sonoff', 'tuya', 'shelly', 'd-link',
        'hikvision', 'wyze', 'arlo', 'honeywell', 'amazon', 'google', 'belkin', 'wemo',
        'netatmo', 'lifx', 'sonos', 'ubiquiti', 'qnap', 'synology', 'asus'
    ]
    
    # Common IoT device ports
    iot_ports = {
        23: 'Telnet', 
        554: 'RTSP',
        1883: 'MQTT',
        5683: 'CoAP',
        8883: 'MQTT-SSL',
        8000: 'HTTP Alt',
        8080: 'HTTP Alt',
        9999: 'IoT Control',
        6668: 'IRC (IoT botnets)',
        49152: 'UPnP'
    }
    
    # Initialize the MAC vendor lookup database
    try:
        mac_lookup = MacLookup()
        mac_lookup.update_vendors()
    except:
        update_status("Warning: MAC vendor lookup database not available. Install with: pip install mac-vendor-lookup")
        mac_lookup = None
    
    # Initialize the nmap scanner
    nm = nmap.PortScanner()
    
    # Helper function to get MAC address for an IP
    def get_mac_address(ip):
        """Get the MAC address for an IP address using ARP."""
        if platform.system().lower() == 'windows':
            # Windows
            try:
                response = subprocess.check_output(['arp', '-a', str(ip)]).decode('utf-8')
                matches = re.findall(r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', response)
                if matches:
                    return matches[0]
            except:
                pass
        else:
            # Linux/Unix
            try:
                response = subprocess.check_output(['arp', '-n', str(ip)]).decode('utf-8')
                matches = re.findall(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', response)
                if matches:
                    return matches[0]
            except:
                pass
        return ""
    
    # Helper function to get vendor from MAC
    def get_vendor_from_mac(mac):
        """Get vendor name from MAC address."""
        if not mac or not mac_lookup:
            return ""
        
        try:
            return mac_lookup.lookup(mac)
        except:
            return ""
    
    # Helper function to check HTTP headers
    def check_http_headers(ip, port=80):
        """Check HTTP headers for IoT device signatures."""
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, timeout=timeout)
            headers = response.headers
            
            # Check for common IoT device headers
            server = headers.get('Server', '')
            if any(iot in server.lower() for iot in ['iot', 'camera', 'router', 'gateway', 'hub']):
                return {
                    'type': 'http_signature',
                    'server': server,
                    'page_title': extract_title(response.text)
                }
                
            # Check response body for IoT keywords
            if any(iot in response.text.lower() for iot in ['smart home', 'camera', 'thermostat', 'device', 'iot', 'router', 'gateway']):
                return {
                    'type': 'http_content',
                    'page_title': extract_title(response.text)
                }
                
        except:
            pass
        
        return None
    
    # Helper function to extract title from HTML
    def extract_title(html_content):
        """Extract title from HTML content."""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html_content)
        if match:
            return match.group(1).strip()
        return ""
    
    # Helper function to determine if device is IoT
    def is_iot_device(device_info):
        """Determine if a device is likely an IoT device based on gathered information."""
        confidence = 0
        reasons = []
        
        # Check manufacturer
        if 'vendor' in device_info and device_info['vendor']:
            vendor_lower = device_info['vendor'].lower()
            if any(mfr in vendor_lower for mfr in iot_manufacturers):
                confidence += 40
                reasons.append(f"Manufacturer ({device_info['vendor']}) is a known IoT vendor")
        
        # Check hostname for IoT keywords
        if 'hostname' in device_info and device_info['hostname']:
            hostname_lower = device_info['hostname'].lower()
            if any(keyword in hostname_lower for keyword in ['cam', 'camera', 'doorbell', 'thermostat', 'hub', 'sensor', 'bulb', 'light', 'plug', 'switch']):
                confidence += 30
                reasons.append(f"Hostname ({device_info['hostname']}) contains IoT keywords")
        
        # Check for IoT-specific ports
        if 'open_ports' in device_info:
            iot_specific_ports = [port for port, _ in device_info['open_ports'] if port in iot_ports]
            if iot_specific_ports:
                confidence += min(len(iot_specific_ports) * 10, 30)
                reasons.append(f"Device has IoT-specific ports: {', '.join(map(str, iot_specific_ports))}")
        
        # Check HTTP signature
        if 'http_info' in device_info:
            if device_info['http_info']:
                confidence += 30
                if 'page_title' in device_info['http_info'] and device_info['http_info']['page_title']:
                    reasons.append(f"HTTP page title suggests IoT: {device_info['http_info']['page_title']}")
                else:
                    reasons.append("HTTP signature suggests IoT device")
        
        # Check OS detection results
        if 'os_info' in device_info and device_info['os_info']:
            os_lower = device_info['os_info'].lower()
            if any(keyword in os_lower for keyword in ['embedded', 'linux', 'rtos', 'router', 'iot']):
                confidence += 20
                reasons.append(f"Operating system ({device_info['os_info']}) suggests IoT device")
        
        # Final determination
        is_iot = confidence >= 40  # Threshold of 40% confidence
        
        return (is_iot, confidence, reasons)
    
    # Helper function to ping an IP
    def ping(ip):
        """Ping an IP address to check if it's reachable."""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', str(int(timeout)), str(ip)]
        
        try:
            return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        except:
            return False
    
    # Helper function to get hostname
    def get_hostname(ip):
        """Try to resolve the hostname for an IP address."""
        try:
            return socket.gethostbyaddr(str(ip))[0]
        except:
            return ""
    
    # Helper function to scan a port
    def scan_port(ip, port):
        """Check if a specific port is open on an IP address."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                service = get_service_name(port)
                return (port, service)
        except:
            pass
        finally:
            sock.close()
        
        return None
    
    # Helper function to get service name
    def get_service_name(port):
        """Get the service name for a given port number."""
        try:
            return socket.getservbyport(port)
        except:
            return 'unknown'
    
    # Helper function to scan common ports
    def scan_common_ports(ip):
        """Scan common IoT device ports on an IP address."""
        # Common IoT device ports + standard ports
        ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            80,    # HTTP
            81,    # Alternate HTTP
            443,   # HTTPS
            554,   # RTSP
            1883,  # MQTT
            5683,  # CoAP
            8000,  # Alternative HTTP
            8080,  # Alternative HTTP
            8443,  # Alternative HTTPS
            8883,  # MQTT over SSL
            9000,  # Alternative HTTP
            9999,  # IoT Control
            6668,  # IRC (IoT botnets)
            49152  # UPnP
        ]
        
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports), max_workers)) as executor:
            future_to_port = {executor.submit(scan_port, ip, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports
    
    # Helper function to export all devices
    def export_all_devices():
        """Export all discovered devices to a file."""
        with open(all_devices_file, 'w') as f:
            f.write(f"Network Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Network Range: {network_range}\n")
            f.write(f"Total Devices: {len(discovered_devices)}\n\n")
            
            for device in discovered_devices:
                f.write(f"IP: {device['ip']}\n")
                if device.get('hostname'):
                    f.write(f"Hostname: {device['hostname']}\n")
                if device.get('mac_address'):
                    f.write(f"MAC Address: {device['mac_address']}\n")
                if device.get('vendor'):
                    f.write(f"Vendor: {device['vendor']}\n")
                f.write(f"IoT Device: {'Yes' if device.get('is_iot', False) else 'No'}\n")
                if device.get('is_iot', False):
                    f.write(f"IoT Confidence: {device.get('iot_confidence', 0)}%\n")
                f.write("Open Ports:\n")
                for port, service in device.get('open_ports', []):
                    f.write(f"  - {port}/{service}\n")
                if device.get('os_info'):
                    f.write(f"OS: {device['os_info']}\n")
                f.write("\n")
                
        update_status(f"All devices exported to {all_devices_file}")
    
    # Helper function to export IoT devices
    def export_iot_devices():
        """Export only IoT devices to a file."""
        iot_devices = [device for device in discovered_devices if device.get('is_iot', False)]
        
        with open(iot_devices_file, 'w') as f:
            f.write(f"IoT Device Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Network Range: {network_range}\n")
            f.write(f"Total Devices: {len(discovered_devices)}\n")
            f.write(f"IoT Devices: {len(iot_devices)}\n\n")
            
            for device in iot_devices:
                f.write(f"IP: {device['ip']}\n")
                if device.get('hostname'):
                    f.write(f"Hostname: {device['hostname']}\n")
                if device.get('mac_address'):
                    f.write(f"MAC Address: {device['mac_address']}\n")
                if device.get('vendor'):
                    f.write(f"Vendor: {device['vendor']}\n")
                f.write(f"IoT Confidence: {device.get('iot_confidence', 0)}%\n")
                f.write("IoT Indicators:\n")
                for reason in device.get('iot_indicators', []):
                    f.write(f"  - {reason}\n")
                f.write("Open Ports:\n")
                for port, service in device.get('open_ports', []):
                    f.write(f"  - {port}/{service}\n")
                if device.get('os_info'):
                    f.write(f"OS: {device['os_info']}\n")
                f.write("\n")
                
        update_status(f"IoT devices exported to {iot_devices_file}")

    # Helper function to export credential report
    def export_credential_report():
        """Export default credential check results to a file."""
        with open(credential_report_file, 'w') as f:
            f.write(f"Default Credential Check Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Network Range: {network_range}\n")
            f.write(f"Devices Checked: {len(credential_results)}\n\n")
            
            for ip, result in credential_results.items():
                device = result.get('device', {})
                f.write(f"IP: {ip}\n")
                if device.get('hostname'):
                    f.write(f"Hostname: {device.get('hostname')}\n")
                if device.get('vendor'):
                    f.write(f"Vendor: {device.get('vendor')}\n")
                f.write(f"Check Result: {result.get('check_result', 'Unknown')}\n")
                
                default_creds = result.get('default_credentials', [])
                if default_creds:
                    f.write("Default Credentials:\n")
                    for cred in default_creds:
                        f.write(f"  - Username: {cred.get('username', 'N/A')}, Password: {cred.get('password', 'N/A')}\n")
                
                f.write("\n")
                
        update_status(f"Credential check results exported to {credential_report_file}")
    
    # MAIN SCANNING LOGIC STARTS HERE
    update_status(f"Starting IoT device scan on {network_range} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Generate all IP addresses in the range
    network = ipaddress.ip_network(network_range)
    all_hosts = list(network.hosts())
    
    # First, perform ping sweep to find active hosts
    active_hosts = []
    update_status(f"Scanning {len(all_hosts)} hosts...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping, ip): ip for ip in all_hosts}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_ip)):
            ip = future_to_ip[future]
            try:
                is_active = future.result()
                if is_active:
                    active_hosts.append(ip)
                    update_status(f"Host discovered: {ip} ({len(active_hosts)} found)")
            except Exception as exc:
                update_status(f"Error scanning {ip}: {exc}")
            
            # Update progress every iteration
            progress_percent = (i+1) / len(all_hosts) * 100
            update_progress(progress_percent)
            
            # Print progress every 10%
            if (i+1) % max(int(len(all_hosts) / 10), 1) == 0:
                update_status(f"Progress: {progress_percent:.1f}% complete")
    
    update_status(f"Found {len(active_hosts)} active hosts. Identifying IoT devices...")
    
    # Now gather information on active hosts
    all_devices = []
    iot_devices = []
    
    for idx, ip in enumerate(active_hosts):
        try:
            # Update progress for this phase
            update_progress((idx+1) / len(active_hosts) * 100)
            update_status(f"Analyzing device {idx+1}/{len(active_hosts)}: {ip}")
            
            # Basic information
            hostname = get_hostname(ip)
            mac_address = get_mac_address(ip)
            vendor = get_vendor_from_mac(mac_address)
            
            # Port scanning
            open_ports = scan_common_ports(ip)
            
            # HTTP check
            http_info = None
            if any(port == 80 for port, _ in open_ports):
                http_info = check_http_headers(ip)
            elif any(port == 8080 for port, _ in open_ports):
                http_info = check_http_headers(ip, 8080)
            
            # OS detection using nmap
            os_info = ""
            try:
                nm.scan(hosts=str(ip), arguments='-O --osscan-limit')
                if str(ip) in nm and 'osmatch' in nm[str(ip)]:
                    os_matches = nm[str(ip)]['osmatch']
                    if os_matches and len(os_matches) > 0:
                        os_info = os_matches[0]['name']
            except:
                pass
            
            # Compile device information
            device_info = {
                'ip': str(ip),
                'hostname': hostname,
                'mac_address': mac_address,
                'vendor': vendor,
                'open_ports': open_ports,
                'http_info': http_info,
                'os_info': os_info,
                'timestamp': datetime.now().isoformat()
            }
            
            # Determine if it's an IoT device
            is_iot, confidence, reasons = is_iot_device(device_info)
            device_info['is_iot'] = is_iot
            device_info['iot_confidence'] = confidence
            device_info['iot_indicators'] = reasons
            
            all_devices.append(device_info)
            discovered_devices.append(device_info)
            
            if is_iot:
                iot_devices.append(device_info)
                update_status(f"IoT device found: {ip} - {hostname or 'Unknown'} ({confidence}% confidence)")
                for reason in reasons:
                    update_status(f"  - {reason}")
            else:
                update_status(f"Device found (not IoT): {ip} - {hostname or 'Unknown'}")
            
        except Exception as e:
            update_status(f"Error processing {ip}: {e}")
    
    elapsed_time = time.time() - start_time
    update_status(f"Scan completed in {elapsed_time:.2f} seconds.")
    update_status(f"Discovered {len(all_devices)} total devices, {len(iot_devices)} identified as IoT devices.")
    
    # Export results if requested
    if export_all:
        export_all_devices()
    if export_iot:
        export_iot_devices()
    
    # Check for default credentials if requested
    if check_default_passwords:
        update_status("Checking for default credentials...")
        
        # Ensure password database is loaded
        if password_checker.df is None:
            update_status("Loading default password database...")
            success = password_checker.load_default_passwords(local_file=password_db_file, status_callback=update_status)
            if not success:
                update_status("Error: Could not load password database. Skipping credential check.")
                credential_results = {}
            else:
                update_status(f"Checking {len(iot_devices)} IoT devices for default credentials...")
                credential_results = password_checker.check_device_passwords(iot_devices, status_callback=update_status)
                
                # Export credential check results
                export_credential_report()
        else:
            update_status(f"Checking {len(iot_devices)} IoT devices for default credentials...")
            credential_results = password_checker.check_device_passwords(iot_devices, status_callback=update_status)
            
            # Export credential check results
            export_credential_report()
    else:
        credential_results = {}
    
    # Final update for GUI
    update_progress(100)
    
    return iot_devices, all_devices, credential_results

# Function to perform credential check only, for GUI separation
def check_device_credentials(devices, password_db_file="default_passwords.csv", 
                            credential_report_file="credential_report.txt",
                            status_callback=None):
    """
    Check devices against default password database.
    
    Args:
        devices: List of device dictionaries
        password_db_file: File path for the password database
        credential_report_file: File path for the credential report
        status_callback: Function to call with status updates
        
    Returns:
        dict: Results of credential checks
    """
    def update_status(message):
        if status_callback:
            status_callback(message)
        else:
            print(message)
            
    # Ensure password database is loaded
    if password_checker.df is None:
        update_status("Loading default password database...")
        password_checker.load_default_passwords(local_file=password_db_file, status_callback=update_status)
    
    if password_checker.df is None:
        update_status("Error: Failed to load password database")
        return {}
    
    # Now check for default credentials
    update_status(f"Checking {len(devices)} devices for default credentials...")
    credential_results = password_checker.check_device_passwords(
        devices, 
        status_callback=update_status
    )
    
    # Export results to a file
    if credential_results:
        try:
            with open(credential_report_file, 'w') as f:
                f.write(f"Default Credential Check Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Devices Checked: {len(credential_results)}\n\n")
                
                for ip, result in credential_results.items():
                    device = result.get('device', {})
                    f.write(f"IP: {ip}\n")
                    if device.get('hostname'):
                        f.write(f"Hostname: {device.get('hostname')}\n")
                    if device.get('vendor'):
                        f.write(f"Vendor: {device.get('vendor')}\n")
                    f.write(f"Check Result: {result.get('check_result', 'Unknown')}\n")
                    
                    default_creds = result.get('default_credentials', [])
                    if default_creds:
                        f.write("Default Credentials:\n")
                        for cred in default_creds:
                            f.write(f"  - Username: {cred.get('username', 'N/A')}, Password: {cred.get('password', 'N/A')}\n")
                    
                    f.write("\n")
                    
            update_status(f"Credential check results saved to {credential_report_file}")
        except Exception as e:
            update_status(f"Error saving credential report: {str(e)}")
    
    return credential_results
