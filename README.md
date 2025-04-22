IoT Device Penetration Testing Toolkit (SMRT)

Members: Mozammil Khatri, Rudge Licanto, Selim Tahir, Vo Minh Thien, Tully McManus


Overview

The IoT Device Penetration Testing Toolkit (SMRT) is a Python-based application designed to help users identify and assess security vulnerabilities in IoT devices on their network. It provides functionalities such as network scanning, device identification, default credential testing, network segmentation analysis, and report generation to enhance the security posture of home or small business networks.

This toolkit is built with a user-friendly GUI using PyQt6, making it accessible for both technical and non-technical users to scan their networks, detect potential vulnerabilities, and receive actionable recommendations.

Features





Network Scanning: Scans a specified network range to identify all connected devices, focusing on IoT devices.



IoT Device Identification: Categorizes devices as IoT, personal, or network infrastructure using vendor, hostname, and port analysis.



Default Credential Testing: Checks for known default credentials on IoT devices to identify vulnerabilities.



Network Segmentation Analysis: Evaluates whether IoT devices are properly segmented from personal devices to prevent lateral movement in case of a compromise.



Security Report Generation: Generates detailed reports summarizing scan results, vulnerabilities, and recommendations.



User-Friendly GUI: Built with PyQt6, offering an intuitive interface for scanning, testing, and viewing results.



Cross-Platform Support: Works on Windows, macOS, and Linux.

Installation

Prerequisites





Python 3.8 or higher



PyQt6 (pip install PyQt6)



Other dependencies listed in requirements.txt

Steps





Clone the repository:

git clone https://github.com/vubump123/SMRTIOT.git
cd SMRTIOT



Install the required dependencies:

pip install -r requirements.txt



Run the application:

python SMRTGUI.py

Usage





Launch the Application:





Run SMRTGUI.py to start the GUI.



The main interface provides options for device scanning, network segmentation checking, and report generation.



Scan for Devices:





Navigate to the "Device Scan" tab.



Configure the network range (e.g., 192.168.1.0/24) and scan timeout in the "Settings" tab.



Click "Start Scan" to begin scanning for devices.



Results will be displayed in the UI and saved as text files (all_devices.txt, iot_devices.txt).



Test Default Credentials:





After scanning, click "Test Default Credentials" to check for known default passwords.



A warning will prompt for user consent before attempting logins.



Results will be displayed and saved in credential_report.txt.



Check Network Segmentation:





Go to the "Network Check" tab.



Click "Check Segmentation" to analyze if IoT devices are isolated from personal devices.



A detailed report will be saved as segmentation_report.txt.



Generate Security Report:





Navigate to the "Generate Report" tab.



Click "Generate Report" to create a consolidated security assessment.



The report will be saved as security_report.txt.

File Structure





SMRTGUI.py: Main GUI application file using PyQt6.



netscan.py: Handles network scanning, IoT device identification, and default credential checking.



simplified_network_segmentation.py: Performs network segmentation analysis and generates segmentation reports.



requirements.txt: Lists all required Python packages.



Output Files:





all_devices.txt: List of all discovered devices.



iot_devices.txt: List of identified IoT devices.



credential_report.txt: Results of default credential checks.



segmentation_report.txt: Network segmentation analysis report.



security_report.txt: Consolidated security assessment report.

Requirements

The toolkit relies on several Python libraries listed in requirements.txt. Key dependencies include:





PyQt6: For the graphical interface.



requests: For downloading the default password database.



pandas: For handling the default credentials CSV.



python-nmap: For port scanning and OS detection.



mac-vendor-lookup: For identifying device vendors via MAC addresses.



paramiko: For SSH login attempts.

Security Note

This toolkit attempts to log in to devices using default credentials, which may be illegal without explicit permission. Only use this tool on networks and devices you own or have permission to test. The application includes a warning prompt before attempting logins to ensure user awareness.

Limitations





The toolkit assumes a /24 subnet for home networks; larger or more complex networks may require adjustments.



Default credential testing relies on a publicly available database, which may not cover all devices.



Network scanning effectiveness depends on device responsiveness and network configuration.



Some features (e.g., login attempts) may require additional setup or dependencies (e.g., paramiko for SSH).

Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request. Ensure your code follows PEP 8 guidelines and includes appropriate documentation.
