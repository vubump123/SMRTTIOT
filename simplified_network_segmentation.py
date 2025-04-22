import ipaddress
import os
from datetime import datetime

class NetworkSegmentationChecker:
    """
    A tool to check if IoT devices are properly segmented from personal devices
    on a network, providing security recommendations for home users.
    """
    
    def __init__(self):
        pass
    
    def categorize_device(self, device):
        """
        Categorize a device primarily using the scanner's IoT classification.
        Only attempt to identify personal devices as a secondary step.
        
        Args:
            device: Dictionary containing device information
            
        Returns:
            str: Category of the device ('iot', 'personal', 'network', or 'unknown')
        """
        # First, trust the scanner's IoT classification
        if device.get('is_iot', False):
            return 'iot'
        
        # Extract useful information for categorization
        hostname = device.get('hostname', '').lower()
        vendor = device.get('vendor', '').lower()
        
        # Simple check for personal computing devices
        personal_keywords = ['pc', 'laptop', 'desktop', 'phone', 'mobile', 'tablet', 'mac', 'iphone', 'ipad', 'android']
        personal_vendors = ['apple', 'microsoft', 'dell', 'hp', 'lenovo', 'asus', 'acer']
        
        if any(keyword in hostname for keyword in personal_keywords) or any(v in vendor for v in personal_vendors):
            return 'personal'
        
        # Check if it's likely network infrastructure
        network_keywords = ['router', 'switch', 'access point', 'ap', 'gateway', 'modem']
        network_vendors = ['cisco', 'netgear', 'linksys', 'ubiquiti', 'aruba']
        
        if any(keyword in hostname for keyword in network_keywords) or any(v in vendor for v in network_vendors):
            return 'network'
        
        # If we can't determine, mark as unknown
        return 'unknown'
    
    def get_subnet(self, ip_address):
        """
        Identify the subnet of an IP address.
        
        Args:
            ip_address: String containing an IP address
            
        Returns:
            str: Subnet in CIDR notation (e.g., '192.168.1.0/24')
        """
        try:
            # Convert to IP address object
            ip = ipaddress.ip_address(ip_address)
            
            # For common home networks, assume a /24 subnet
            if ip.is_private:
                # Extract the first three octets
                subnet_prefix = '.'.join(ip_address.split('.')[:3]) + '.0/24'
                return subnet_prefix
            
            # For others, provide a reasonable guess
            return str(ip_address) + '/32'  # Single host subnet
            
        except:
            return None
    
    def analyze_segmentation(self, devices, status_callback=None):
        """
        Analyze network segmentation based on device categories and subnets.
        
        Args:
            devices: List of device dictionaries
            status_callback: Function for status updates
            
        Returns:
            dict: Results of segmentation analysis with recommendations
        """
        def update_status(message):
            if status_callback:
                status_callback(message)
            else:
                print(message)
        
        update_status("Analyzing network segmentation...")
        
        # Group devices by subnet
        subnets = {}
        device_categories = {}
        
        for device in devices:
            ip = device.get('ip')
            if not ip:
                continue
                
            # Categorize the device
            category = self.categorize_device(device)
            device_categories[ip] = category
            
            # Get subnet
            subnet = self.get_subnet(ip)
            if not subnet:
                continue
                
            # Add to subnet dictionary
            if subnet not in subnets:
                subnets[subnet] = []
            
            subnets[subnet].append({
                'ip': ip,
                'category': category,
                'hostname': device.get('hostname', ''),
                'vendor': device.get('vendor', '')
            })
        
        # Analyze segmentation
        results = {
            'timestamp': datetime.now().isoformat(),
            'properly_segmented': False,
            'subnets': {},
            'issues': [],
            'recommendations': []
        }
        
        # Check each subnet
        for subnet, subnet_devices in subnets.items():
            # Count devices by category in this subnet
            category_counts = {'iot': 0, 'personal': 0, 'network': 0, 'unknown': 0}
            for device in subnet_devices:
                category_counts[device['category']] += 1
            
            # Store subnet information
            results['subnets'][subnet] = {
                'devices': len(subnet_devices),
                'categories': category_counts,
                'mixed_use': (category_counts['iot'] > 0 and category_counts['personal'] > 0)
            }
            
            # Check if IoT and personal devices share this subnet
            if category_counts['iot'] > 0 and category_counts['personal'] > 0:
                results['properly_segmented'] = False
                results['issues'].append({
                    'subnet': subnet,
                    'issue': 'Mixed device types',
                    'details': f"Found {category_counts['iot']} IoT devices and {category_counts['personal']} personal devices on the same subnet"
                })
        
        # Generate recommendations
        if not results['properly_segmented']:
            results['recommendations'].append({
                'priority': 'high',
                'title': 'Separate IoT devices from personal devices',
                'description': ('For better security, place IoT devices on a separate network or VLAN. '
                               'This prevents compromised IoT devices from accessing your personal data.'),
                'implementation': [
                    'Create a guest network on your router and connect IoT devices to it',
                    'Some routers allow creating a dedicated "IoT network" or VLAN',
                    'Consider a separate access point just for IoT devices'
                ]
            })
        
        # Check if we found any IoT devices at all
        total_iot = sum(subnet['categories']['iot'] for subnet in results['subnets'].values())
        if total_iot == 0:
            results['recommendations'].append({
                'priority': 'info',
                'title': 'Limited IoT device detection',
                'description': ('No IoT devices were positively identified during the scan. '
                               'This could mean you have no IoT devices, or they were not detected correctly.'),
                'implementation': [
                    'Make sure all devices are powered on during the scan',
                    'Try running a more thorough scan with a longer timeout'
                ]
            })
        
        update_status(f"Segmentation analysis complete. Found {len(results['issues'])} issues.")
        return results
    
    def generate_segmentation_report(self, results, output_file=None):
        """
        Generate a user-friendly report of network segmentation issues.
        
        Args:
            results: Results from analyze_segmentation
            output_file: Optional file path to save the report
            
        Returns:
            str: Human-readable report
        """
        # Create the report
        report = []
        report.append("=" * 60)
        report.append("NETWORK SEGMENTATION SECURITY REPORT")
        report.append("=" * 60)
        report.append("")
        
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Overall status
        if results['properly_segmented']:
            report.append("✅ GOOD NEWS: Your network appears to be properly segmented!")
            report.append("   IoT devices and personal devices are on separate networks.")
        else:
            report.append("⚠️ SECURITY ISSUE: Your network is not properly segmented!")
            report.append("   IoT devices and personal devices are mixed on the same network.")
        
        report.append("")
        report.append("SUBNET DETAILS:")
        report.append("-" * 60)
        
        # Show each subnet
        for subnet, subnet_info in results['subnets'].items():
            report.append(f"Subnet: {subnet}")
            report.append(f"  Total Devices: {subnet_info['devices']}")
            
            # Device counts by category
            categories = subnet_info['categories']
            report.append(f"  IoT Devices: {categories['iot']}")
            report.append(f"  Personal Devices: {categories['personal']}")
            report.append(f"  Network Infrastructure: {categories['network']}")
            report.append(f"  Unclassified Devices: {categories['unknown']}")
            
            # Highlight mixed subnets
            if subnet_info['mixed_use']:
                report.append("  ⚠️ This subnet contains both IoT and personal devices!")
            
            report.append("")
        
        # List issues
        if results['issues']:
            report.append("SECURITY ISSUES:")
            report.append("-" * 60)
            
            for issue in results['issues']:
                report.append(f"• {issue['issue']} on subnet {issue['subnet']}")
                report.append(f"  {issue['details']}")
            
            report.append("")
        
        # Recommendations
        if results['recommendations']:
            report.append("RECOMMENDATIONS:")
            report.append("-" * 60)
            
            for rec in results['recommendations']:
                priority_marker = "🔴" if rec['priority'] == 'high' else "ℹ️"
                report.append(f"{priority_marker} {rec['title']}")
                report.append(f"  {rec['description']}")
                
                report.append("  Steps to implement:")
                for step in rec['implementation']:
                    report.append(f"  • {step}")
                
                report.append("")
        
        # End of report
        report.append("=" * 60)
        report.append("END OF SEGMENTATION REPORT")
        report.append("=" * 60)
        
        # Save to file if requested
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n'.join(report))
            except Exception as e:
                report.append(f"Error saving report to {output_file}: {str(e)}")
        
        return '\n'.join(report)
    
    def check_segmentation(self, devices, output_file=None, status_callback=None):
        """
        Complete segmentation check process - analyze and generate report.
        
        Args:
            devices: List of device dictionaries
            output_file: Optional file path to save the report
            status_callback: Function for status updates
            
        Returns:
            tuple: (results dictionary, report string)
        """
        # Analyze network segmentation
        results = self.analyze_segmentation(devices, status_callback)
        
        # Generate the report
        report = self.generate_segmentation_report(results, output_file)
        
        return results, report


# Example usage (not executed when imported)
if __name__ == "__main__":
    # Sample devices list (would come from your scanner)
    sample_devices = [
        {
            'ip': '192.168.1.1',
            'hostname': 'router.home',
            'vendor': 'NETGEAR',
            'open_ports': [(80, 'http'), (443, 'https')],
            'is_iot': False
        },
        {
            'ip': '192.168.1.100',
            'hostname': 'laptop-abc',
            'vendor': 'Dell Inc.',
            'open_ports': [(22, 'ssh')],
            'is_iot': False
        },
        {
            'ip': '192.168.1.101',
            'hostname': 'ring-doorbell',
            'vendor': 'Amazon Technologies',
            'open_ports': [(80, 'http'), (443, 'https')],
            'is_iot': True
        }
    ]
    
    # Run segmentation check
    checker = NetworkSegmentationChecker()
    results, report = checker.check_segmentation(sample_devices)
    
    # Print the report
    print(report)
