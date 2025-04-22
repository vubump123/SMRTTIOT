import sys
import os
import platform
import subprocess
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout, QStackedWidget, QFrame, QTextEdit, QProgressBar,
    QFileDialog, QMessageBox, QScrollBar, QGroupBox, QFormLayout, QLineEdit, QSpinBox
)
from PyQt6.QtGui import QPixmap, QIcon
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal, QObject, QTimer
from netscan import scan_iot_devices, password_checker, CSV_URL
from simplified_network_segmentation import NetworkSegmentationChecker

class ScannerThread(QThread):
    result_ready = pyqtSignal(str)
    progress_update = pyqtSignal(int)
    status_update = pyqtSignal(str)
    files_created = pyqtSignal(str, str, str)  # Signal to indicate file paths (all, iot, credentials)
    error_occurred = pyqtSignal(str)  # Signal for error handling

    def __init__(self, save_directory=None, network_range='192.168.1.0/24', timeout=1):
        super().__init__()
        self.save_directory = save_directory or os.getcwd()  # Default to current directory if not specified
        self.network_range = network_range
        self.timeout = timeout
        self.device_ports = {}  # To store open ports by device IP
        self.result_data = None  # To store scan results for reuse

    def run(self):
        def update_progress(percent):
            self.progress_update.emit(int(percent))

        def update_status(message):
            self.status_update.emit(message)
            
        try:
            # Create file paths in the save directory
            all_devices_file = os.path.join(self.save_directory, 'all_devices.txt')
            iot_devices_file = os.path.join(self.save_directory, 'iot_devices.txt')
            credential_report_file = os.path.join(self.save_directory, 'credential_report.txt')
            password_db_file = os.path.join(self.save_directory, 'default_passwords.csv')
            
            # Call the scan function with export parameters set to True but credential checking DISABLED
            iot_devices, all_devices, credential_results = scan_iot_devices(
                self.network_range,
                timeout=self.timeout,
                export_all=True,
                export_iot=True,
                all_devices_file=all_devices_file,
                iot_devices_file=iot_devices_file,
                check_default_passwords=False,  # Changed to False - only check when explicitly requested
                password_db_file=password_db_file,
                credential_report_file=credential_report_file,
                progress_callback=update_progress,
                status_callback=update_status
            )
            
            # Store scan results for later use
            self.result_data = (iot_devices, all_devices, credential_results)
            
            # Store port information for each device
            for device in iot_devices:
                device_ip = device.get('ip', '')
                if device_ip:
                    self.device_ports[device_ip] = device.get('open_ports', [])

            # Create summary text for the UI
            result_text = f"Scan completed. Found {len(iot_devices)} IoT devices out of {len(all_devices)} total devices.\n\n"
            result_text += f"Reports saved to:\n- {all_devices_file}\n- {iot_devices_file}\n\n"

            # Include device information without credentials
            for device in iot_devices:
                result_text += f"IoT Device: {device['ip']} ({device.get('hostname', 'Unknown')})\n"
                result_text += f"  Vendor: {device.get('vendor', 'N/A')}\n"
                result_text += f"  Confidence: {device.get('iot_confidence', 0)}%\n"
                
                # Format ports nicely
                port_list = device.get('open_ports', [])
                if port_list:
                    port_str = ", ".join([f"{p}({s})" for p, s in port_list])
                    result_text += f"  Open Ports: {port_str}\n"
                else:
                    result_text += "  Open Ports: None detected\n"
                    
                result_text += "-"*40 + "\n"

            if not iot_devices:
                result_text += "No IoT devices found.\n"
            else:
                result_text += f"\nSecurity Summary:\n"
                result_text += f"- {len(iot_devices)} IoT devices detected\n"
                result_text += f"- Click 'Test Default Credentials' to check for vulnerable devices\n"

            # Emit signals
            self.result_ready.emit(result_text)
            self.files_created.emit(all_devices_file, iot_devices_file, credential_report_file)
        
        except Exception as e:
            import traceback
            error_msg = f"Error during scan: {str(e)}\n\n{traceback.format_exc()}"
            self.error_occurred.emit(error_msg)
            self.status_update.emit("Scan failed due to an error")

class ReportGeneratorThread(QThread):
    report_ready = pyqtSignal(str)
    status_update = pyqtSignal(str)
    error_occurred = pyqtSignal(str)  # Signal for error handling

    def __init__(self, save_directory=None, app_window=None):
        super().__init__()
        self.save_directory = save_directory or os.getcwd()
        self.app_window = app_window

    def run(self):
        def update_status(message):
            self.status_update.emit(message)
        
        try:
            update_status("Generating consolidated security report...")
            
            # Files to check
            all_devices_file = os.path.join(self.save_directory, 'all_devices.txt')
            iot_devices_file = os.path.join(self.save_directory, 'iot_devices.txt')
            credential_report_file = os.path.join(self.save_directory, 'credential_report.txt')
            
            # Check if necessary files exist
            if not os.path.exists(iot_devices_file):
                self.report_ready.emit("Error: IoT device scan results not found. Please run a scan first.")
                return
                
            # Create a comprehensive report
            report_file = os.path.join(self.save_directory, 'security_report.txt')
            
            with open(report_file, 'w') as f:
                f.write("=" * 60 + "\n")
                f.write("SMRT IoT SECURITY ASSESSMENT REPORT\n")
                f.write("=" * 60 + "\n\n")
                
                # Get timestamp from IoT devices file
                timestamp = "Unknown"
                try:
                    with open(iot_devices_file, 'r') as iot_f:
                        first_line = iot_f.readline().strip()
                        if "Results -" in first_line:
                            timestamp = first_line.split("-", 1)[1].strip()
                except:
                    pass
                
                f.write(f"Report Date: {timestamp}\n\n")
                
                # Summary section
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 60 + "\n")
                
                # Count devices
                total_devices = 0
                iot_count = 0
                try:
                    with open(iot_devices_file, 'r') as iot_f:
                        for line in iot_f:
                            if "Total Devices:" in line:
                                total_devices = int(line.split(":", 1)[1].strip())
                            if "IoT Devices:" in line:
                                iot_count = int(line.split(":", 1)[1].strip())
                                break
                except:
                    pass
                
                f.write(f"Total devices discovered: {total_devices}\n")
                f.write(f"IoT devices identified: {iot_count}\n")
                
                # Credential vulnerability count - use confirmed logins instead of potential ones
                # Get confirmed logins from the main window if available
                successful_logins = {}
                vulnerable_count = 0
                
                if self.app_window and hasattr(self.app_window, 'successful_logins'):
                    successful_logins = self.app_window.successful_logins
                    vulnerable_count = len(successful_logins)
                
                f.write(f"Devices with confirmed default credentials: {vulnerable_count}\n\n")
                
                # Risk assessment
                risk_level = "Low"
                if vulnerable_count > 0:
                    risk_level = "High" if vulnerable_count >= 3 else "Medium"
                
                f.write(f"Overall Security Risk: {risk_level}\n\n")
                
                # Recommendations
                f.write("SECURITY RECOMMENDATIONS\n")
                f.write("-" * 60 + "\n")
                
                if vulnerable_count > 0:
                    f.write("1. URGENT: Change default passwords on the following devices:\n")
                    for ip in successful_logins:
                        f.write(f"   - IP: {ip}\n")
                else:
                    f.write("1. Password Security: \n")
                    f.write("   - No devices with default credentials were confirmed during testing.\n")
                    f.write("   - Maintain good password hygiene by using strong, unique passwords for all devices.\n")
                
                f.write("\n2. General Security Recommendations:\n")
                f.write("   - Keep all IoT devices updated with the latest firmware\n")
                f.write("   - Configure a separate network segment for IoT devices\n")
                f.write("   - Disable unnecessary services and ports on all devices\n")
                f.write("   - Implement network monitoring to detect unusual traffic\n\n")
                
                # Detailed findings
                f.write("DETAILED FINDINGS\n")
                f.write("-" * 60 + "\n")
                
                # List IoT devices with their relevant info
                if os.path.exists(iot_devices_file):
                    try:
                        with open(iot_devices_file, 'r') as iot_f:
                            # Skip header part
                            header_done = False
                            device_text = ""
                            
                            for line in iot_f:
                                if not header_done:
                                    if line.strip() == "":
                                        header_done = True
                                    continue
                                
                                device_text += line
                            
                            f.write("IoT Devices:\n\n")
                            f.write(device_text)
                    except:
                        f.write("Could not retrieve IoT device details\n")
                
                # Include only confirmed credential findings instead of potential ones
                f.write("\nCredential Security Status:\n\n")
                
                # Create a dictionary of devices from the IoT devices file for easy lookup
                device_info = {}
                try:
                    current_ip = None
                    with open(iot_devices_file, 'r') as iot_f:
                        for line in iot_f:
                            if "IP:" in line:
                                current_ip = line.split(":", 1)[1].strip()
                                device_info[current_ip] = {'hostname': '', 'vendor': ''}
                            elif current_ip and "Hostname:" in line:
                                device_info[current_ip]['hostname'] = line.split(":", 1)[1].strip()
                            elif current_ip and "Vendor:" in line:
                                device_info[current_ip]['vendor'] = line.split(":", 1)[1].strip()
                except:
                    pass
                
                # Check all IoT devices and report on credential status
                for ip in device_info:
                    hostname = device_info[ip].get('hostname', '')
                    vendor = device_info[ip].get('vendor', '')
                    
                    f.write(f"IP: {ip}\n")
                    if hostname:
                        f.write(f"Hostname: {hostname}\n")
                    if vendor:
                        f.write(f"Vendor: {vendor}\n")
                    
                    if ip in successful_logins:
                        f.write("Status: VULNERABLE - Default credentials confirmed\n")
                        f.write("Working Credentials:\n")
                        for cred in successful_logins[ip]:
                            username = cred.get('username', '')
                            password = cred.get('password', '')
                            f.write(f"  - Username: {username}, Password: {password}\n")
                    else:
                        f.write("Status: No default credentials detected\n")
                    
                    f.write("\n")
                
                # Conclusion
                f.write("\n" + "=" * 60 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 60 + "\n")
            
            update_status(f"Report generated successfully and saved to {report_file}")
            self.report_ready.emit(f"Security assessment report generated successfully!\n\nSaved to: {report_file}\n\nSummary:\n- Total devices: {total_devices}\n- IoT devices: {iot_count}\n- Devices with confirmed default credentials: {vulnerable_count}\n- Overall risk: {risk_level}")
            
        except Exception as e:
            import traceback
            error_msg = f"Error generating report: {str(e)}\n\n{traceback.format_exc()}"
            self.error_occurred.emit(error_msg)
            self.report_ready.emit(f"Error generating report: {str(e)}")
            
class SegmentationCheckThread(QThread):
    check_complete = pyqtSignal(dict, str)  # Signal to return results and report
    status_update = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, devices, save_directory=None):
        super().__init__()
        self.devices = devices
        self.save_directory = save_directory or os.getcwd()
        
    def run(self):
        def update_status(message):
            self.status_update.emit(message)
            
        try:
            # Create segmentation checker
            checker = NetworkSegmentationChecker()
            
            # Generate the report file path
            report_file = os.path.join(self.save_directory, 'segmentation_report.txt')
            
            # Run the check
            update_status("Analyzing network segmentation...")
            results, report = checker.check_segmentation(
                self.devices, 
                output_file=report_file,
                status_callback=update_status
            )
            
            # Emit results
            self.check_complete.emit(results, report)
            
        except Exception as e:
            import traceback
            error_msg = f"Error during segmentation check: {str(e)}\n\n{traceback.format_exc()}"
            self.error_occurred.emit(error_msg)

class LoginAttemptThread(QThread):
    status_update = pyqtSignal(str)
    login_result = pyqtSignal(bool, str, str)  # success, ip, message
    
    def __init__(self, ip, username, password, device_ports):
        super().__init__()
        self.ip = ip
        self.username = username
        self.password = password
        password_checker.device_ports = device_ports
        
    def run(self):
        def update_status(message):
            self.status_update.emit(message)
            
        success, message = password_checker.attempt_login(
            self.ip, self.username, self.password,
            status_callback=update_status
        )
        
        self.login_result.emit(success, self.ip, message)

class CredentialCheckThread(QThread):
    status_update = pyqtSignal(str)
    progress_update = pyqtSignal(int)
    credential_result = pyqtSignal(bool, str, str, str, str)  # success, ip, vendor, username, password
    all_done = pyqtSignal(int)  # signal with total success count
    error_occurred = pyqtSignal(str)  # signal for error reporting
    
    def __init__(self, iot_devices, device_ports):
        super().__init__()
        self.iot_devices = iot_devices
        self.device_ports = device_ports
        self.stop_requested = False
        
    def run(self):
        success_count = 0
        total_devices = len(self.iot_devices)
        processed_count = 0
        
        try:
            for device in self.iot_devices:
                if self.stop_requested:
                    break
                    
                ip = device['ip']
                vendor = device.get('vendor', '')
                
                processed_count += 1
                progress_percent = int((processed_count / total_devices) * 100)
                self.progress_update.emit(progress_percent)
                
                if not vendor:
                    self.status_update.emit(f"Skipping {ip}: No vendor information")
                    continue
                
                # Find default credentials for this vendor
                try:
                    success, creds = password_checker.brute_force_device(
                        device, 
                        status_callback=lambda msg: self.status_update.emit(msg)
                    )
                except Exception as e:
                    self.status_update.emit(f"Error processing {ip}: {str(e)}")
                    continue
                
                if not success or not creds:
                    self.status_update.emit(f"No default credentials found for {ip} ({vendor})")
                    continue
                
                # Emit credential results for UI to handle
                for cred in creds:
                    username = cred.get('username', '')
                    password = cred.get('password', '')
                    if username and password:  # Only emit if we have both username and password
                        self.credential_result.emit(True, ip, vendor, username, password)
            
            self.all_done.emit(success_count)
            
        except Exception as e:
            import traceback
            error_msg = f"Error in credential check thread: {str(e)}\n{traceback.format_exc()}"
            self.error_occurred.emit(error_msg)
    
    def stop(self):
        self.stop_requested = True

class PasswordDatabaseWorker(QObject):
    update_status = pyqtSignal(str)
    finished = pyqtSignal()
    
    def update_database(self, save_directory):
        try:
            self.update_status.emit("Downloading...")
            local_file = os.path.join(save_directory, 'default_passwords.csv')
            
            success = password_checker.load_default_passwords(
                url=CSV_URL,
                local_file=local_file,
                status_callback=lambda msg: self.update_status.emit(msg)
            )
            
            if success:
                self.update_status.emit(password_checker.load_status)
            else:
                self.update_status.emit("Update failed")
        except Exception as e:
            self.update_status.emit(f"Error: {str(e)}")
        finally:
            self.finished.emit()

class MenuGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SMRT IoT Security Toolkit")
        self.setGeometry(100, 100, 1000, 600)
        self.setMinimumSize(800, 500)
        self.setWindowIcon(QIcon(os.path.join(os.path.dirname(__file__), "SMRTLogo.png")))
        self.setStyleSheet("background-color: white; font-family: 'Arial'; font-size: 14px;")

        # Store file paths
        self.all_devices_file = ""
        self.iot_devices_file = ""
        self.credential_report_file = ""
        
        self.successfull_logins = {}
        
        self.main_layout = QHBoxLayout(self)
        self.sidebar = QFrame()
        self.sidebar.setFixedWidth(90)
        self.sidebar.setStyleSheet("background-color: white; border-right: 2px solid #A3D5FF;")
        self.sidebar_layout = QVBoxLayout(self.sidebar)

        self.sidebar.mousePressEvent = self.toggle_sidebar

        self.logo_label = QPushButton()
        self.logo_label.setIcon(QIcon(os.path.join(os.path.dirname(__file__), "SMRTLogo.png")))
        self.logo_label.setIconSize(QSize(80, 80))
        self.logo_label.setStyleSheet("border: none; margin: 5px;")
        self.logo_label.clicked.connect(lambda: self.switch_page(0))
        self.sidebar_layout.addWidget(self.logo_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.button_style = """
            QPushButton {
                background-color: white;
                color: black;
                font-size: 14px;
                padding: 8px;
                border-radius: 5px;
                margin: 5px;
                border: 1px solid transparent;
                text-align: left;
            }
            QPushButton:hover { background-color: #E0F2FF; }
            QPushButton:pressed { background-color: #A3D5FF; border: 1px solid #A3D5FF; }
        """

        icon_size = QSize(32, 32)
        self.scan_button = QPushButton("  Device Scan")
        self.scan_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), "scan.jpg")))
        self.scan_button.setIconSize(icon_size)
        self.scan_button.setStyleSheet(self.button_style)
        self.scan_button.clicked.connect(lambda: self.switch_page(1))

        self.report_button = QPushButton("  Generate Report")
        self.report_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), "report.jpg")))
        self.report_button.setIconSize(icon_size)
        self.report_button.setStyleSheet(self.button_style)
        self.report_button.clicked.connect(lambda: self.switch_page(2))
        
        # Add segmentation button to sidebar
        self.segmentation_button = QPushButton("  Network Check")
        self.segmentation_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), "NetSeg.jpg")))
        self.segmentation_button.setIconSize(icon_size)
        self.segmentation_button.setStyleSheet(self.button_style)
        self.segmentation_button.clicked.connect(lambda: self.switch_page(4))  # The number might be different based on your existing tabs
        
        # Add Settings button
        self.settings_button = QPushButton("  Settings")
        self.settings_button.setIcon(QIcon(os.path.join(os.path.dirname(__file__), "SettingsIcon.jpg"))) # Reuse scan icon as placeholder
        self.settings_button.setIconSize(icon_size)
        self.settings_button.setStyleSheet(self.button_style)
        self.settings_button.clicked.connect(lambda: self.switch_page(3))

        self.sidebar_layout.addWidget(self.scan_button)
        self.sidebar_layout.addWidget(self.segmentation_button)
        self.sidebar_layout.addWidget(self.report_button)
        self.sidebar_layout.addWidget(self.settings_button)
        self.sidebar_layout.addStretch()

        self.collapse_button = QPushButton("Collapse")
        self.collapse_button.setStyleSheet("background-color: #A3D5FF; color: white; padding: 8px; border-radius: 5px;")
        self.collapse_button.clicked.connect(self.collapse_sidebar)
        self.collapse_button.setVisible(False)
        self.sidebar_layout.addWidget(self.collapse_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.main_content = QStackedWidget()
        self.pages = []

        for index, (title, text) in enumerate([
            ("SMRT IoT Security", "Welcome to the SMRT IoT Security Toolkit!\n\n"
                                  "This tool helps you check the security of smart devices connected to your network. "
                                  "Many home and business devices, like smart cameras, speakers, and doorbells, can have "
                                  "security risks if not properly set up.\n\n"
                                  "With this toolkit, you can:\n"
                                  "• Find all devices on your network\n"
                                  "• Automatically check for weak passwords\n"
                                  "• Create a simple security report\n\n"
                                  "Not sure where to start? Click a button on the left to begin!"),
            ("Device Scan", "🔍 Scanning network for connected devices..."),
            ("Generate Report", "📊 Generating a security report based on the results..."),
        ]):
            page = QWidget()
            layout = QVBoxLayout(page)

            header = QLabel()
            header.setStyleSheet("background-color: #E0F2FF; font-size: 20px; font-weight: bold; color: #2C3E50; padding: 5px;")
            header.setText(title)
            header.setAlignment(Qt.AlignmentFlag.AlignCenter)
            header.setFixedHeight(30)
            layout.addWidget(header)

            if index == 0:
                logo_image = QLabel()
                logo_image.setPixmap(QPixmap(os.path.join(os.path.dirname(__file__), "SMRTLogo.png")).scaled(180, 180, Qt.AspectRatioMode.KeepAspectRatio))
                logo_image.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(logo_image)

            if index == 1:  # Device Scan
                scan_layout = QVBoxLayout()

                self.scan_status = QLabel("Ready to scan network for IoT devices")
                self.scan_status.setStyleSheet("font-size: 16px; color: #333; padding: 5px;")
                scan_layout.addWidget(self.scan_status)

                self.progress_bar = QProgressBar()
                self.progress_bar.setRange(0, 100)
                self.progress_bar.setValue(0)
                self.progress_bar.setStyleSheet("QProgressBar {border: 2px solid #A3D5FF; border-radius: 5px; text-align: center;} QProgressBar::chunk {background-color: #A3D5FF;}")
                scan_layout.addWidget(self.progress_bar)

                self.scan_output = QTextEdit()
                self.scan_output.setReadOnly(True)
                # Hide scrollbars
                self.scan_output.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
                self.scan_output.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
                scan_layout.addWidget(self.scan_output)
                
                # Add credential check progress bar (initially hidden)
                self.credential_progress_bar = QProgressBar()
                self.credential_progress_bar.setRange(0, 100)
                self.credential_progress_bar.setValue(0)
                self.credential_progress_bar.setStyleSheet("QProgressBar {border: 2px solid #FF9999; border-radius: 5px; text-align: center;} QProgressBar::chunk {background-color: #FF9999;}")
                self.credential_progress_bar.setVisible(False)
                scan_layout.addWidget(self.credential_progress_bar)
                
                # Buttons layout
                buttons_layout = QHBoxLayout()
                
                self.start_scan_button = QPushButton("Start Scan")
                self.start_scan_button.setStyleSheet("padding: 10px; background-color: #A3D5FF; color: white; border-radius: 5px;")
                self.start_scan_button.clicked.connect(self.start_scan)
                buttons_layout.addWidget(self.start_scan_button)
                
                # Add select directory button
                self.select_directory_button = QPushButton("Save Location")
                self.select_directory_button.setStyleSheet("padding: 10px; background-color: #98FB98; color: black; border-radius: 5px;")
                self.select_directory_button.clicked.connect(self.select_save_directory)
                buttons_layout.addWidget(self.select_directory_button)
                
                # Add credential testing button
                self.test_creds_button = QPushButton("Test Default Credentials")
                self.test_creds_button.setStyleSheet("padding: 10px; background-color: #FFCC66; color: black; border-radius: 5px;")
                self.test_creds_button.clicked.connect(self.perform_login_attempts)
                buttons_layout.addWidget(self.test_creds_button)
                
                # Add cancel button for credential testing (initially hidden)
                self.cancel_creds_button = QPushButton("Cancel Tests")
                self.cancel_creds_button.setStyleSheet("padding: 10px; background-color: #FF9999; color: black; border-radius: 5px;")
                self.cancel_creds_button.clicked.connect(self.cancel_credential_tests)
                self.cancel_creds_button.setVisible(False)
                buttons_layout.addWidget(self.cancel_creds_button)
                
                scan_layout.addLayout(buttons_layout)

                # Save location label
                self.save_location_label = QLabel(f"Save Location: {os.getcwd()}")
                self.save_location_label.setStyleSheet("font-size: 12px; color: #666; padding: 5px;")
                scan_layout.addWidget(self.save_location_label)
                
                layout.addLayout(scan_layout)

            elif index == 2:  # Generate Report
                report_layout = QVBoxLayout()
                
                self.report_status = QLabel("Ready to generate a security report")
                self.report_status.setStyleSheet("font-size: 16px; color: #333; padding: 5px;")
                report_layout.addWidget(self.report_status)
                
                self.report_output = QTextEdit()
                self.report_output.setReadOnly(True)
                # Hide scrollbars
                self.report_output.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
                self.report_output.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
                report_layout.addWidget(self.report_output)
                
                report_buttons = QHBoxLayout()
                
                self.generate_report_button = QPushButton("Generate Report")
                self.generate_report_button.setStyleSheet("padding: 10px; background-color: #A3D5FF; color: white; border-radius: 5px;")
                self.generate_report_button.clicked.connect(self.generate_report)
                report_buttons.addWidget(self.generate_report_button)
                
                self.open_report_button = QPushButton("Open Report")
                self.open_report_button.setStyleSheet("padding: 10px; background-color: #98FB98; color: black; border-radius: 5px;")
                self.open_report_button.clicked.connect(self.open_report)
                self.open_report_button.setEnabled(False)
                report_buttons.addWidget(self.open_report_button)
                
                report_layout.addLayout(report_buttons)
                
                layout.addLayout(report_layout)
            else:
                text_label = QLabel(text)
                text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                text_label.setWordWrap(True)
                text_label.setStyleSheet("font-size: 16px; color: #333; padding: 5px;")
                layout.addWidget(text_label)

            gradient_bar = QFrame()
            gradient_bar.setFixedHeight(10)
            gradient_bar.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #A3D5FF, stop:1 #98FB98);")
            layout.addWidget(gradient_bar)

            self.main_content.addWidget(page)
            self.pages.append(title)

        # Add settings page
        settings_page = self.create_settings_page()
        self.main_content.addWidget(settings_page)
        self.pages.append("Settings")

        self.main_layout.addWidget(self.sidebar)
        self.main_layout.addWidget(self.main_content)
        self.setLayout(self.main_layout)
        
        # Add network segmentation page
        segmentation_page = self.create_segmentation_page()
        self.main_content.addWidget(segmentation_page)
        self.pages.append("Network Segmentation")
        
        # Store the save directory
        self.save_directory = os.getcwd()
        self.report_file = ""
        
        # Default settings
        self.network_range = "192.168.1.0/24"
        self.scan_timeout = 1
        
        # Store IoT devices from scan
        self.iot_devices = []
        
        # Success count for credential testing
        self.success_count = 0
        
        self.successful_logins = {}
        
        # Initialize credential check thread as None
        self.credential_check_thread = None
        
        # Initialize scan timer for progress tracking
        self.scan_timer = None
        self.scan_timer_counter = 0
        
    def toggle_sidebar(self, event):
        if self.sidebar.width() == 90:
            self.sidebar.setFixedWidth(200)
            self.collapse_button.setVisible(True)

    def collapse_sidebar(self):
        self.sidebar.setFixedWidth(90)
        self.collapse_button.setVisible(False)

    def switch_page(self, index):
        self.main_content.setCurrentIndex(index)
        
    def create_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
    
        header = QLabel()
        header.setStyleSheet("background-color: #E0F2FF; font-size: 20px; font-weight: bold; color: #2C3E50; padding: 5px;")
        header.setText("Settings")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setFixedHeight(30)
        layout.addWidget(header)
    
        settings_layout = QVBoxLayout()
    
        # Network settings
        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout()
        
        self.network_range_input = QLineEdit("192.168.1.0/24")
        self.network_range_input.setToolTip("CIDR notation for network range to scan")
        network_layout.addRow("Network Range:", self.network_range_input)
        
        self.scan_timeout_input = QSpinBox()
        self.scan_timeout_input.setRange(1, 10)
        self.scan_timeout_input.setValue(1)
        self.scan_timeout_input.setSuffix(" seconds")
        network_layout.addRow("Scan Timeout:", self.scan_timeout_input)
    
        network_group.setLayout(network_layout)
        settings_layout.addWidget(network_group)
    
        # Save settings button
        self.save_settings_button = QPushButton("Save Settings")
        self.save_settings_button.setStyleSheet("padding: 10px; background-color: #A3D5FF; color: white; border-radius: 5px;")
        self.save_settings_button.clicked.connect(self.save_settings)
        settings_layout.addWidget(self.save_settings_button)
    
        layout.addLayout(settings_layout)
    
        # Add gradient bar at the bottom
        gradient_bar = QFrame()
        gradient_bar.setFixedHeight(10)
        gradient_bar.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #A3D5FF, stop:1 #98FB98);")
        layout.addWidget(gradient_bar)
    
        return page
        
    def create_segmentation_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        header = QLabel()
        header.setStyleSheet("background-color: #E0F2FF; font-size: 20px; font-weight: bold; color: #2C3E50; padding: 5px;")
        header.setText("Network Segmentation")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setFixedHeight(30)
        layout.addWidget(header)

    # Main section
        segmentation_layout = QVBoxLayout()
    
    # Description
        description = QLabel("Network segmentation is a security best practice that separates IoT devices "
                         "from personal computers and smartphones. This helps protect your personal "
                         "data if an IoT device is compromised.")
        description.setWordWrap(True)
        description.setStyleSheet("font-size: 14px; color: #333; padding: 10px;")
        segmentation_layout.addWidget(description)
    
    # Status
        self.segmentation_status = QLabel("Ready to check network segmentation")
        self.segmentation_status.setStyleSheet("font-size: 16px; color: #333; padding: 5px;")
        segmentation_layout.addWidget(self.segmentation_status)
    
    # Output area
        self.segmentation_output = QTextEdit()
        self.segmentation_output.setReadOnly(True)
        self.segmentation_output.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.segmentation_output.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        segmentation_layout.addWidget(self.segmentation_output)
    
    # Buttons
        buttons_layout = QHBoxLayout()
    
        self.check_segmentation_button = QPushButton("Check Segmentation")
        self.check_segmentation_button.setStyleSheet("padding: 10px; background-color: #A3D5FF; color: white; border-radius: 5px;")
        self.check_segmentation_button.clicked.connect(self.check_segmentation)
        buttons_layout.addWidget(self.check_segmentation_button)
    
        self.open_segmentation_report_button = QPushButton("Open Report")
        self.open_segmentation_report_button.setStyleSheet("padding: 10px; background-color: #98FB98; color: black; border-radius: 5px;")
        self.open_segmentation_report_button.clicked.connect(self.open_segmentation_report)
        self.open_segmentation_report_button.setEnabled(False)
        buttons_layout.addWidget(self.open_segmentation_report_button)
    
        segmentation_layout.addLayout(buttons_layout)
    
        layout.addLayout(segmentation_layout)
    
    # Add gradient bar at the bottom
        gradient_bar = QFrame()
        gradient_bar.setFixedHeight(10)
        gradient_bar.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #A3D5FF, stop:1 #98FB98);")
        layout.addWidget(gradient_bar)
    
        return page
        
    def check_segmentation(self):
        """Start a segmentation check in a separate thread"""
    # Check if scan has been run
        if not hasattr(self, 'scan_thread') or not hasattr(self.scan_thread, 'result_data'):
            QMessageBox.warning(self, "Scan Required", 
                             "Please run a device scan first before checking segmentation.")
            return
    
    # Get the devices from the scan results
        result_data = self.scan_thread.result_data
        if not result_data or len(result_data) < 2 or not result_data[1]:
            QMessageBox.warning(self, "No Devices", 
                             "No devices found from previous scan. Please run a scan first.")
            return
        
    # Get all devices (not just IoT)
        all_devices = result_data[1]
    
    # Update UI
        self.segmentation_output.clear()
        self.segmentation_status.setText("Analyzing network segmentation...")
        self.check_segmentation_button.setEnabled(False)
    
    # Start the segmentation check thread
        self.segmentation_thread = SegmentationCheckThread(all_devices, self.save_directory)
        self.segmentation_thread.check_complete.connect(self.display_segmentation_results)
        self.segmentation_thread.status_update.connect(self.update_segmentation_status)
        self.segmentation_thread.error_occurred.connect(self.handle_segmentation_error)
        self.segmentation_thread.start()

    def update_segmentation_status(self, message):
        """Update the status message for segmentation checks"""
        self.segmentation_status.setText(message)
        self.segmentation_output.append(message)

    def handle_segmentation_error(self, error_message):
        """Handle errors in segmentation checking"""
        self.check_segmentation_button.setEnabled(True)
        QMessageBox.critical(self, "Segmentation Check Error", 
                          f"Error checking network segmentation:\n\n{error_message}")

    def display_segmentation_results(self, results, report):
        """Display the results of the segmentation check"""
    # Update UI
        self.segmentation_output.setText(report)
        self.check_segmentation_button.setEnabled(True)
        self.segmentation_status.setText("Segmentation check completed")
    
    # Enable the report button
        self.segmentation_report_file = os.path.join(self.save_directory, 'segmentation_report.txt')
        self.open_segmentation_report_button.setEnabled(True)
    
    # Show notification
        if results.get('properly_segmented', False):
            icon = QMessageBox.Icon.Information
            title = "Good News!"
            message = "Your network appears to be properly segmented. IoT devices are separated from personal devices."
        else:
            icon = QMessageBox.Icon.Warning
            title = "Security Issue Detected"
            message = "Your network is not properly segmented. IoT devices and personal devices are on the same network."
    
        QMessageBox.information(self, title, f"{message}\n\nA detailed report has been saved to:\n{self.segmentation_report_file}")

    def open_segmentation_report(self):
        """Open the segmentation report file"""
        if hasattr(self, 'segmentation_report_file') and os.path.exists(self.segmentation_report_file):
        # Open the file using the appropriate command for the OS
            if platform.system() == "Windows":
                os.startfile(self.segmentation_report_file)
            elif platform.system() == "Darwin":  # macOS
                subprocess.call(["open", self.segmentation_report_file])
            else:  # Linux
                subprocess.call(["xdg-open", self.segmentation_report_file])
        else:
            QMessageBox.information(self, "Report Not Available", 
                                 "No segmentation report is available. Please run a check first.")

    def save_settings(self):
        """Saves the current settings"""
        # Save network range
        network_range = self.network_range_input.text().strip()
        scan_timeout = self.scan_timeout_input.value()
        
        # Simple validation
        try:
            import ipaddress
            ipaddress.ip_network(network_range)
            
            # Store settings
            self.network_range = network_range
            self.scan_timeout = scan_timeout
            
            QMessageBox.information(self, "Settings Saved", "Your settings have been saved successfully.")
        except Exception as e:
            QMessageBox.warning(self, "Invalid Settings", f"Error in network range: {str(e)}")

    def select_save_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory to Save Scan Results")
        if dir_path:  # If a directory was selected
            self.save_directory = dir_path
            self.save_location_label.setText(f"Save Location: {dir_path}")
            self.scan_status.setText(f"Ready to scan. Results will be saved to: {dir_path}")
            
    def start_scan(self):
        """Starts a network scan in a separate thread with improved error handling"""
        # Get settings from the UI if the settings page exists
        if hasattr(self, 'network_range_input') and hasattr(self, 'scan_timeout_input'):
            try:
                network_range = self.network_range_input.text().strip()
                scan_timeout = self.scan_timeout_input.value()
            
            # Validate network range
                import ipaddress
                ipaddress.ip_network(network_range)
            except Exception as e:
                QMessageBox.warning(self, "Invalid Network Range", 
                                 f"Please check your network settings: {str(e)}")
                return
        else:
        # Default settings if settings page doesn't exist
            network_range = '192.168.1.0/24'
            scan_timeout = 1
    
    # Define the function here, inside the method
        def start_actual_scan():
            self.scan_output.setText(f"Initializing scan of {network_range}...")
            self.progress_bar.setValue(0)
            self.start_scan_button.setText("Scanning...")

        # Create the scanner thread with the selected save directory
            self.scan_thread = ScannerThread(
                save_directory=self.save_directory,
                network_range=network_range,
                timeout=scan_timeout
            )
            self.scan_thread.result_ready.connect(self.display_scan_results)
            self.scan_thread.progress_update.connect(self.update_progress)
            self.scan_thread.status_update.connect(self.update_status)
            self.scan_thread.files_created.connect(self.update_file_paths)
            self.scan_thread.error_occurred.connect(self.handle_scan_error)
            self.scan_thread.start()
        
        # Add a scan timer to show activity is happening
            self.scan_timer = QTimer(self)
            self.scan_timer.timeout.connect(self.update_scan_time)
            self.scan_timer_counter = 0
            self.scan_timer.start(1000)  # Update every second
    
    # Function to handle database download status updates
        def update_db_status(message):
            self.scan_status.setText(message)
            self.scan_output.setText(message)
    
    # Function to reset the UI state if something fails
        def reset_scan_ui():
            self.start_scan_button.setEnabled(True)
            self.select_directory_button.setEnabled(True)
            self.test_creds_button.setEnabled(True)
            self.start_scan_button.setText("Start Scan")
    
    # First ensure we have the password database
        self.scan_output.setText("Preparing to scan: Checking password database...")
        self.progress_bar.setValue(10)
        self.start_scan_button.setEnabled(False)
        self.select_directory_button.setEnabled(False)
        self.test_creds_button.setEnabled(False)
        self.start_scan_button.setText("Preparing...")
    
    # Path to the database file
        password_db_file = os.path.join(self.save_directory, 'default_passwords.csv')
    
    # Check if database is already loaded or exists
        if password_checker.df is not None:
            self.scan_output.append("Database already loaded in memory.")
            start_actual_scan()
        elif os.path.exists(password_db_file):
            # Try to load existing file
            self.scan_output.append(f"Found existing database file. Loading...")
            success = password_checker.load_default_passwords(
                local_file=password_db_file,
                status_callback=lambda msg: self.scan_output.append(msg)
            )
        
            if success:
                self.scan_output.append("Database loaded successfully.")
                start_actual_scan()
            else:
            # File exists but couldn't be loaded, try downloading
                self.scan_output.append("Existing database file couldn't be loaded. Downloading fresh copy...")
                if self.download_password_database():
                    start_actual_scan()
                else:
                    reset_scan_ui()
        else:
            # No database file, need to download
            self.scan_output.append("No database file found. Downloading...")
            if self.download_password_database():
                start_actual_scan()
            else:
                reset_scan_ui()
    
    # Create a database download thread
        class DownloadThread(QThread):
            update_progress = pyqtSignal(int)
            update_status = pyqtSignal(str)
            download_complete = pyqtSignal(bool)
    
            def __init__(self, save_file):
                super().__init__()
                self.save_file = save_file
        
            def run(self):
                try:
                    self.update_status.emit("Downloading password database...")
                    self.update_progress.emit(20)
            
            # Import requests here to ensure it's available
                    import requests
            
            # Stream download with progress updates
                    response = requests.get(CSV_URL, stream=True)
                    response.raise_for_status()
            
            # Get content length if available
                    total_length = response.headers.get('content-length')
            
                    if total_length is None:  # No content length header
                        self.update_status.emit("Downloading database (size unknown)...")
                        content = response.content
                        with open(self.save_file, 'wb') as f:
                            f.write(content)
                        self.update_progress.emit(75)
                    else:
                # We know the size, so we can show proper progress
                        total_length = int(total_length)
                        self.update_status.emit(f"Downloading database ({total_length/1024:.1f} KB)...")
                
                        with open(self.save_file, 'wb') as f:
                            dl = 0
                            for data in response.iter_content(chunk_size=4096):
                                dl += len(data)
                                f.write(data)
                                done = int(50 * dl / total_length) + 20
                                self.update_progress.emit(min(done, 75))
                                self.update_status.emit(f"Downloading: {dl/1024:.1f} KB of {total_length/1024:.1f} KB")
            
            # Now load the downloaded database
                    self.update_status.emit("Download complete. Loading database...")
                    self.update_progress.emit(80)
            
                    success = password_checker.load_default_passwords(
                        local_file=self.save_file,
                        status_callback=lambda msg: self.update_status.emit(msg)
                    )
            
                    if success:
                        self.update_status.emit(f"Database loaded successfully with {len(password_checker.df)} credentials.")
                        self.update_progress.emit(100)
                        self.download_complete.emit(True)
                    else:
                        self.update_status.emit("Error loading the downloaded database.")
                        self.download_complete.emit(False)
                
                except Exception as e:
                    import traceback
                    error_trace = traceback.format_exc()
                    self.update_status.emit(f"Error downloading database: {str(e)}\n{error_trace}")
                    self.download_complete.emit(False)
    
    # Create and start the download thread
        self.download_thread = DownloadThread(password_db_file)
        self.download_thread.update_progress.connect(self.progress_bar.setValue)
        self.download_thread.update_status.connect(update_db_status)
        self.download_thread.download_complete.connect(
            lambda success: start_actual_scan() if success else reset_scan_ui()
        )
        self.download_thread.start()

    def handle_scan_error(self, error_message):
        """Handle errors that occur during scanning"""
        self.start_scan_button.setEnabled(True)
        self.select_directory_button.setEnabled(True)
        self.test_creds_button.setEnabled(True)
        self.start_scan_button.setText("Start Scan")
        
        QMessageBox.critical(self, "Scan Error", 
                           f"An error occurred during scanning:\n\n{error_message}\n\nPlease try again.")
        
        if hasattr(self, 'scan_timer'):
            self.scan_timer.stop()

    def update_scan_time(self):
        """Updates the scan timer to show progress"""
        self.scan_timer_counter += 1
        minutes = self.scan_timer_counter // 60
        seconds = self.scan_timer_counter % 60
        self.scan_status.setText(f"Scanning in progress... ({minutes:02d}:{seconds:02d})")

    def update_progress(self, value):
        """Updates the progress bar with current scan progress"""
        self.progress_bar.setValue(value)

    def update_status(self, message):
        """Updates the status message and appends to scan output"""
        self.scan_status.setText(message)
        current_text = self.scan_output.toPlainText()
        if current_text and not current_text.startswith("Initializing"):
            self.scan_output.append(message)
        else:
            self.scan_output.setText(message)
            
    def update_file_paths(self, all_devices_file, iot_devices_file, credential_report_file=""):
        """Updates stored file paths after a scan"""
        # Store the file paths
        self.all_devices_file = all_devices_file
        self.iot_devices_file = iot_devices_file
        self.credential_report_file = credential_report_file
        
    def download_password_database(self):
        """Download the password database with detailed status updates"""
        self.scan_output.clear()
        self.progress_bar.setValue(0)
        self.scan_status.setText("Downloading password database...")
    
    # Disable buttons during download
        self.start_scan_button.setEnabled(False)
        self.select_directory_button.setEnabled(False)
        self.test_creds_button.setEnabled(False)
    
    # Display the URL we're trying to use
        self.scan_output.append(f"Database URL: {CSV_URL}")
    
    # Create the database file path
        db_file = os.path.join(self.save_directory, 'default_passwords.csv')
        self.scan_output.append(f"Will save to: {db_file}")
    
    # Create directory if needed
        if not os.path.exists(self.save_directory):
            try:
                os.makedirs(self.save_directory, exist_ok=True)
                self.scan_output.append(f"Created directory: {self.save_directory}")
            except Exception as e:
                self.scan_output.append(f"Error creating directory: {str(e)}")
                self.reset_download_ui()
                return False
    
        try:
            self.scan_output.append("Importing requests library...")
            import requests
        
            self.scan_output.append("Starting download (this may take a moment)...")
            self.progress_bar.setValue(10)
        
        # Use a direct approach without streaming to simplify
            response = requests.get(CSV_URL, timeout=30)
        
            self.scan_output.append(f"Response status code: {response.status_code}")
            self.progress_bar.setValue(50)
        
            if response.status_code != 200:
                self.scan_output.append(f"Error: Received HTTP status code {response.status_code}")
                self.reset_download_ui()
                return False
            
        # Save the content to file
            content = response.content
            self.scan_output.append(f"Downloaded {len(content)} bytes")
            self.progress_bar.setValue(70)
        
            with open(db_file, 'wb') as f:
                f.write(content)
        
            self.scan_output.append(f"Saved database to {db_file}")
            self.progress_bar.setValue(80)
        
        # Verify the file looks correct
            try:
                with open(db_file, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                    self.scan_output.append(f"First line of database: {first_line}")
            
                if ',' not in first_line:
                    self.scan_output.append("Warning: File doesn't look like a CSV. Download may have failed.")
            except Exception as read_err:
                self.scan_output.append(f"Warning: Could not read file: {str(read_err)}")
        
        # Now load the database
            self.scan_output.append("Loading database into memory...")
            success = password_checker.load_default_passwords(
                local_file=db_file,
                status_callback=lambda msg: self.scan_output.append(msg)
            )
        
            if success:
                self.scan_output.append(f"Database loaded successfully with {len(password_checker.df)} credentials")
                self.progress_bar.setValue(100)
                self.reset_download_ui()
                return True
            else:
                self.scan_output.append("Error loading database into memory")
                self.reset_download_ui()
                return False
            
        except Exception as e:
            import traceback
            self.scan_output.append(f"Error during download: {str(e)}")
            self.scan_output.append(traceback.format_exc())
            self.reset_download_ui()
            return False

    def reset_download_ui(self):
        """Reset UI after download attempt"""
        self.start_scan_button.setEnabled(True)
        self.select_directory_button.setEnabled(True)
        self.test_creds_button.setEnabled(True)
        self.start_scan_button.setText("Start Scan")

    def display_scan_results(self, text):
        """Displays the results of the scan in the UI"""
        self.scan_output.setText(text)
        self.start_scan_button.setEnabled(True)
        self.select_directory_button.setEnabled(True)
        self.test_creds_button.setEnabled(True)
        self.start_scan_button.setText("Start Scan")
        self.scan_status.setText("Scan completed")
        
        # Stop the timer
        if hasattr(self, 'scan_timer'):
            self.scan_timer.stop()
        
        # Check if IoT devices were found
        iot_devices_found = 0
        all_devices_found = 0
        
        if hasattr(self.scan_thread, 'result_data'):
            result_data = self.scan_thread.result_data
            if result_data and len(result_data) >= 2:
                iot_devices_found = len(result_data[0])
                all_devices_found = len(result_data[1])
        
        # Show popup notification with more details
        QMessageBox.information(self, "Scan Complete", 
                             f"Scan completed successfully.\n\nSummary:\n- {all_devices_found} total devices found\n- {iot_devices_found} IoT devices identified\n\nReports saved to:\n{self.save_directory}")
        
        # If no IoT devices found, show a message
        if iot_devices_found == 0:
            self.scan_output.append("\nNo IoT devices were detected in the scan. This could be because:")
            self.scan_output.append("1. There are no IoT devices on this network")
            self.scan_output.append("2. Devices are offline or not responding to scans")
            self.scan_output.append("3. Device signatures don't match IoT patterns")
            self.scan_output.append("\nTry adjusting the scan timeout in settings for more thorough results.")
            
    def attempt_login_with_warning(self):
        warning_msg = QMessageBox()
        warning_msg.setIcon(QMessageBox.Icon.Warning)
        warning_msg.setWindowTitle("Security Warning")
        warning_msg.setText("Warning: Login Attempt")
        warning_msg.setInformativeText(
            "Attempting to log in to devices without permission may be illegal in your jurisdiction. "
            "Only continue if you own these devices or have explicit permission to test them.\n\n"
            "Do you want to continue with actual login attempts?"
        )
        warning_msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        warning_msg.setDefaultButton(QMessageBox.StandardButton.No)
        
        if warning_msg.exec() == QMessageBox.StandardButton.Yes:
            # User consented, proceed with login attempts
            self.perform_login_attempts()
        else:
            self.scan_status.setText("Login attempt canceled by user")

    def cancel_credential_tests(self):
        """Cancels the ongoing credential tests"""
    # Check which thread is running and stop it
        if hasattr(self, 'batch_login_thread') and self.batch_login_thread.isRunning():
            self.batch_login_thread.stop()
            self.scan_output.append("Credential testing canceled by user")
        elif hasattr(self, 'credential_check_thread') and self.credential_check_thread.isRunning():
            self.credential_check_thread.stop()
            self.scan_output.append("Credential testing canceled by user")
    
    # Reset UI
        self.test_creds_button.setEnabled(True)
        self.start_scan_button.setEnabled(True)
        self.select_directory_button.setEnabled(True)
        self.cancel_creds_button.setVisible(False)
        self.credential_progress_bar.setVisible(False)
            
    def load_devices_from_file(self, file_path):
        """Loads device information from a file previously generated by the scanner"""
        devices = []
        
        with open(file_path, 'r') as f:
            content = f.read()
            
        # Split into device sections using separator
        sections = content.split("-" * 40)
        
        # Process each section
        for section in sections:
            if "IP:" in section:
                # This looks like a device section
                lines = section.strip().split('\n')
                device = {}
                
                for i, line in enumerate(lines):
                    line = line.strip()
                    
                    if "IP:" in line:
                        device['ip'] = line.split(":", 1)[1].strip()
                    elif "Hostname:" in line:
                        device['hostname'] = line.split(":", 1)[1].strip()
                    elif "Vendor:" in line:
                        device['vendor'] = line.split(":", 1)[1].strip()
                    elif "IoT Confidence:" in line:
                        try:
                            confidence = line.split(":", 1)[1].strip()
                            device['iot_confidence'] = int(confidence.replace('%', ''))
                        except:
                            device['iot_confidence'] = 0
                    elif "Open Ports:" in line:
                        ports = []
                        # Find port lines that follow this line
                        port_start_idx = i + 1
                        for j in range(port_start_idx, len(lines)):
                            port_line = lines[j].strip()
                            if port_line.startswith('-'):
                                port_info = port_line[1:].strip()
                                if '/' in port_info:
                                    port_num, service = port_info.split('/', 1)
                                    try:
                                        ports.append((int(port_num.strip()), service.strip()))
                                    except:
                                        pass
                            elif port_line and not port_line.startswith('-'):
                                # No longer a port line
                                break
                        device['open_ports'] = ports
                
                # Only add devices with an IP address
                if 'ip' in device:
                    # This is an IoT device (only devices in iot_devices file are IoT)
                    device['is_iot'] = True
                    devices.append(device)
        
        return devices

    def perform_login_attempts(self):
        """Starts credential checking in a separate thread with single confirmation and no additional prompts"""
    # Check if we have scan results
        if not hasattr(self, 'scan_thread') or not hasattr(self.scan_thread, 'device_ports'):
            self.scan_status.setText("No devices found to test. Run a scan first.")
            return
    
    # First try to get devices from in-memory data if available
        iot_devices = []
    
    # Try to get devices from the scan results directly if available
        if hasattr(self, 'scan_thread') and hasattr(self.scan_thread, 'result_data'):
            if isinstance(self.scan_thread.result_data, tuple) and len(self.scan_thread.result_data) >= 1:
                iot_devices = self.scan_thread.result_data[0]  # First element should be iot_devices
    
    # If not available in memory, try to load from file
        if not iot_devices and hasattr(self, 'iot_devices_file') and os.path.exists(self.iot_devices_file):
            try:
                iot_devices = self.load_devices_from_file(self.iot_devices_file)
            except Exception as e:
                self.scan_status.setText(f"Error loading device information: {str(e)}")
                return
        
    # Check if we found any devices
        if not iot_devices:
            self.scan_status.setText("No IoT devices found to test. Run a scan first.")
            return
        
        self.scan_output.clear()
        self.scan_output.append(f"Preparing to test credentials for {len(iot_devices)} IoT devices...")
    
    # Setup UI for credential testing
        self.test_creds_button.setEnabled(False)
        self.start_scan_button.setEnabled(False)
        self.select_directory_button.setEnabled(False)
        self.cancel_creds_button.setVisible(True)
        self.credential_progress_bar.setValue(0)
        self.credential_progress_bar.setVisible(True)
    
    # Reset success count and successful logins dictionary
        self.success_count = 0
        self.successful_logins = {}
        
    # Store device ports for the credential check thread
        device_ports = {}
        if hasattr(self, 'scan_thread') and hasattr(self.scan_thread, 'device_ports'):
            device_ports = self.scan_thread.device_ports
    
    # First, check for default credentials and generate a report
        self.scan_output.append("Checking for potential default credentials...")
    
    # Create file paths in the save directory
        credential_report_file = os.path.join(self.save_directory, 'credential_report.txt')
        password_db_file = os.path.join(self.save_directory, 'default_passwords.csv')
    
    # Ensure password database is loaded first
        if password_checker.df is None:
            self.scan_output.append("Loading default password database...")
            try:
                success = password_checker.load_default_passwords(
                    local_file=password_db_file,
                    status_callback=lambda msg: self.scan_output.append(msg)
                )
                if not success:
                    self.scan_status.setText("Error: Could not load password database")
                    self.restore_ui_after_credentials()
                    return
            except Exception as e:
                self.scan_output.append(f"Error loading password database: {str(e)}")
                self.restore_ui_after_credentials()
                return
    
    # Check for default credentials and generate report
        try:
            self.scan_output.append("Analyzing devices for potential default credentials...")
            credential_results = password_checker.check_device_passwords(
                iot_devices, 
                status_callback=lambda msg: self.scan_output.append(msg)
            )
    
        # Manually export credential report
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
    
            self.scan_output.append(f"Credential check results exported to: {credential_report_file}")
        
        # Count devices with potential default credentials
            devices_with_creds = 0
            all_credentials = []
        
        # Compile a list of all credentials to test
            for ip, result in credential_results.items():
                default_creds = result.get('default_credentials', [])
                if default_creds:
                    devices_with_creds += 1
                    device = result.get('device', {})
                    vendor = device.get('vendor', 'Unknown')
                
                    for cred in default_creds:
                        all_credentials.append({
                            'ip': ip,
                            'vendor': vendor,
                            'username': cred.get('username', ''),
                            'password': cred.get('password', '')
                        })
        
            if devices_with_creds == 0:
                self.scan_output.append("No devices with potential default credentials found.")
                QMessageBox.information(self, "Credential Check Complete", 
                                     "No devices with potential default credentials were found.")
                self.restore_ui_after_credentials()
                return
                
            self.scan_output.append(f"Found {devices_with_creds} devices with {len(all_credentials)} potential default credentials to test.")
        
        # Ask for confirmation ONCE before proceeding with all login attempts
            warning_msg = QMessageBox()
            warning_msg.setIcon(QMessageBox.Icon.Warning)
            warning_msg.setWindowTitle("Security Warning")
            warning_msg.setText("Warning: Login Attempt")
            warning_msg.setInformativeText(
                f"The scan has identified {len(all_credentials)} potential default credentials across {devices_with_creds} devices.\n\n"
                "Attempting to log in to devices without permission may be illegal in your jurisdiction. "
                "Only continue if you own these devices or have explicit permission to test them.\n\n"
                "Do you want to proceed with testing ALL potential default credentials?"
            )
            warning_msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            warning_msg.setDefaultButton(QMessageBox.StandardButton.No)
        
            if warning_msg.exec() != QMessageBox.StandardButton.Yes:
                self.scan_status.setText("Login attempt canceled by user")
                self.restore_ui_after_credentials()
                return
        
        # Create and start a login testing thread
            self.scan_output.append("Starting automated credential testing...")
        
        # Create a new class for batch login testing
            class BatchLoginThread(QThread):
                status_update = pyqtSignal(str)
                progress_update = pyqtSignal(int)
                login_result = pyqtSignal(bool, str, str, str, str)  # success, ip, vendor, username, password
                all_done = pyqtSignal(int)  # signal with total success count
                error_occurred = pyqtSignal(str)  # signal for error reporting
            
                def __init__(self, credentials, device_ports):
                    super().__init__()
                    self.credentials = credentials
                    self.device_ports = device_ports
                    self.stop_requested = False
                
                def run(self):
                    success_count = 0
                    total = len(self.credentials)
                
                    try:
                        for idx, cred in enumerate(self.credentials):
                            if self.stop_requested:
                                break
                            
                            ip = cred['ip']
                            vendor = cred['vendor']
                            username = cred['username']
                            password = cred['password']
                        
                        # Update progress
                            progress = int((idx + 1) / total * 100)
                            self.progress_update.emit(progress)
                        
                            self.status_update.emit(f"Testing {ip} ({vendor}) with {username}:{password}...")
                        
                        # Attempt login
                            try:
                                success, message = password_checker.attempt_login(
                                    ip, username, password, 
                                    status_callback=lambda msg: self.status_update.emit(msg)
                                )
                            
                                if success:
                                    success_count += 1
                                    self.status_update.emit(f⚠️ VULNERABLE: Successfully logged into {ip}!")
                                    self.login_result.emit(True, ip, vendor, username, password)
                                else:
                                    self.status_update.emit(f"Login failed for {ip}: {message}")
                            except Exception as e:
                                self.status_update.emit(f"Error testing {ip}: {str(e)}")
                    
                        self.all_done.emit(success_count)
                    
                    except Exception as e:
                        import traceback
                        error_msg = f"Error in batch login thread: {str(e)}\n{traceback.format_exc()}"
                        self.error_occurred.emit(error_msg)
            
                def stop(self):
                    self.stop_requested = True
        
        # Start the batch login thread
            self.batch_login_thread = BatchLoginThread(all_credentials, device_ports)
            self.batch_login_thread.status_update.connect(self.append_login_status)
            self.batch_login_thread.progress_update.connect(self.update_credential_progress)
            self.batch_login_thread.login_result.connect(self.record_successful_login)
            self.batch_login_thread.all_done.connect(self.finalize_credential_check)
            self.batch_login_thread.error_occurred.connect(self.handle_credential_error)
            self.batch_login_thread.start()
            
        except Exception as e:
            import traceback
            error_msg = f"Error during credential check: {str(e)}\n{traceback.format_exc()}"
            self.scan_output.append(f"Error: {error_msg}")
            self.restore_ui_after_credentials()

    def restore_ui_after_credentials(self):
        """Restores the UI after credential testing is complete or fails"""
        self.test_creds_button.setEnabled(True)
        self.start_scan_button.setEnabled(True)
        self.select_directory_button.setEnabled(True)
        self.cancel_creds_button.setVisible(False)
        self.credential_progress_bar.setVisible(False)

    def handle_credential_error(self, error_message):
        """Handle errors that occur during credential checking"""
        self.scan_output.append(f"Error during credential testing: {error_message}")
        QMessageBox.warning(self, "Credential Test Error", 
                          f"An error occurred during credential testing:\n\n{error_message}")
        self.restore_ui_after_credentials()
        
    def update_credential_progress(self, percent):
        """Updates the credential checking progress bar"""
        self.credential_progress_bar.setValue(percent)

    def append_login_status(self, message):
        """Helper method to append login status messages to scan output"""
        self.scan_output.append(message)

    def handle_credential_found(self, success, ip, vendor, username, password):
        """Handles a credential found event from the thread"""
        # Store the current credentials being tested
        self.current_username = username
        self.current_password = password
        
        # Show confirmation dialog
        confirm_msg = QMessageBox()
        confirm_msg.setIcon(QMessageBox.Icon.Question)
        confirm_msg.setWindowTitle("Confirm Login Attempt")
        confirm_msg.setText(f"Attempt login to {ip} ({vendor})?")
        confirm_msg.setInformativeText(
            f"Username: {username}\nPassword: {password}\n\n"
            "Do you want to try these credentials?"
        )
        confirm_msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if confirm_msg.exec() == QMessageBox.StandardButton.Yes:
            self.scan_output.append(f"Attempting login to {ip} with {username}:{password}...")
            
            # Get device ports from the scanner thread
            device_ports = []
            if hasattr(self, 'scan_thread') and hasattr(self.scan_thread, 'device_ports'):
                device_ports_dict = self.scan_thread.device_ports
                if isinstance(device_ports_dict, dict) and ip in device_ports_dict:
                    device_ports = device_ports_dict[ip]
            
            # Create a thread for the login attempt
            self.login_thread = LoginAttemptThread(ip, username, password, device_ports)
            self.login_thread.status_update.connect(self.append_login_status)
            self.login_thread.login_result.connect(self.handle_login_result)
            self.login_thread.start()
            
            # Wait for the thread to finish
            self.login_thread.wait()

    def handle_login_result(self, success, ip, message):
        """Handler for login attempt results"""
        if success:
            self.success_count += 1
        # Save the successful credentials for the report
            if ip not in self.successful_logins:
                self.successful_logins[ip] = []
            self.successful_logins[ip].append({
                'username': self.current_username,
                'password': self.current_password
            })
            self.scan_output.append(f"⚠️ VULNERABLE: Successfully logged into {ip}!")
            QMessageBox.warning(self, "Security Vulnerability", 
                         f"Successfully logged into device {ip} using default credentials!\n\nThis is a serious security risk. Change the device password immediately.")
        else:
            self.scan_output.append(f"Login failed for {ip}: {message}")
            
    def record_successful_login(self, success, ip, vendor, username, password):
        """Records a successful login without prompting"""
        if success:
            self.success_count += 1
        # Save the successful credentials for the report
            if ip not in self.successful_logins:
                self.successful_logins[ip] = []
            self.successful_logins[ip].append({
                'username': username,
                'password': password
            })

    def finalize_credential_check(self, success_count):
        """Called when credential checking is complete"""
    # Restore UI
        self.test_creds_button.setEnabled(True)
        self.start_scan_button.setEnabled(True)
        self.select_directory_button.setEnabled(True)
        self.cancel_creds_button.setVisible(False)
        self.credential_progress_bar.setVisible(False)
    
        if self.success_count > 0:
            self.scan_output.append(f"⚠️ Found {self.success_count} devices vulnerable to default credentials!")
        
        # Create a detailed report of successful logins
            report = f"Credential Testing Results\n{'='*30}\n\n"
            report += f"Tested {len(self.successful_logins)} devices with successful logins\n\n"
        
            for ip, credentials in self.successful_logins.items():
                report += f"Device IP: {ip}\n"
                report += f"Working credentials:\n"
                for cred in credentials:
                    report += f"  - Username: {cred['username']}, Password: {cred['password']}\n"
                report += "\n"
        
            self.scan_output.append(report)
        
            QMessageBox.warning(self, "Security Vulnerability", 
                             f"Found {self.success_count} successful logins with default credentials!\n\n"
                             f"This affects {len(self.successful_logins)} devices on your network.\n\n"
                             "Review the scan output for details and change these passwords immediately.")
        else:
            self.scan_output.append("No devices were compromised with default credentials.")
            QMessageBox.information(self, "Credential Test Complete", 
                                 "Good news! None of the devices could be accessed using default credentials.")
            
    def generate_report(self):
        """Generates a security report based on scan results"""
    # Check if scan has been run
        if not self.iot_devices_file or not os.path.exists(self.iot_devices_file):
            QMessageBox.warning(self, "Scan Required", 
                             "Please run a device scan first before generating a report.")
            return
        
        self.report_output.setText("Generating security report...")
        self.generate_report_button.setEnabled(False)
        self.report_status.setText("Generating report...")
    
    # Start the report generator thread with self reference for accessing successful_logins
        self.report_thread = ReportGeneratorThread(self.save_directory, self)
        self.report_thread.report_ready.connect(self.display_report)
        self.report_thread.status_update.connect(self.update_report_status)
        self.report_thread.error_occurred.connect(self.handle_report_error)
        self.report_thread.start()
    
    def update_report_status(self, message):
        """Updates the report status message"""
        self.report_status.setText(message)
    
    def handle_report_error(self, error_message):
        """Handle errors in report generation"""
        self.generate_report_button.setEnabled(True)
        QMessageBox.critical(self, "Report Generation Error", 
                          f"Error generating report:\n\n{error_message}")
    
    def display_report(self, text):
        """Displays the generated report summary"""
        self.report_output.setText(text)
        self.generate_report_button.setEnabled(True)
        self.report_status.setText("Report generation completed")
        
        # Update report file path
        self.report_file = os.path.join(self.save_directory, 'security_report.txt')
        self.open_report_button.setEnabled(True)
        
        # Show popup notification
        QMessageBox.information(self, "Report Generated", 
                             f"Security report generated successfully and saved to:\n{self.report_file}")
    
    def open_report(self):
        """Opens the generated report file with the system's default application"""
        # Open the generated report file
        if self.report_file and os.path.exists(self.report_file):
            # Open the file using the appropriate command for the OS
            if platform.system() == "Windows":
                os.startfile(self.report_file)
            elif platform.system() == "Darwin":  # macOS
                subprocess.call(["open", self.report_file])
            else:  # Linux
                subprocess.call(["xdg-open", self.report_file])
        else:
            QMessageBox.information(self, "Report Not Available", 
                                 "No report file is available. Please generate a report first.")
        
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet("""
        * { color: black; }
        QTextEdit { color: black; background-color: #f0f0f0; }
        QMessageBox QLabel { color: black; }
    """)
    window = MenuGUI()
    window.show()
    sys.exit(app.exec())
