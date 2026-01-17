# CyberSentinel-IDS
A robust console-based security engine designed to detect and analyze system threats through log analysis. Features include brute-force detection using threshold logic, IP blacklisting, and user behavior profiling. Implements Role-Based Access Control (RBAC) for Admins, Analysts, and Auditors, alongside XOR-encrypted reporting.
# CyberSentinel IDS Console

![Version](https://img.shields.io/badge/version-1.0-blue.svg)
![C++](https://img.shields.io/badge/C++-17-00599C.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**CyberSentinel** is a comprehensive console-based Intrusion Detection System (IDS) and Log Analysis tool implemented in C++ using Object-Oriented Programming principles. It provides security professionals with powerful capabilities for monitoring, analyzing, and responding to security incidents.

---

## 📋 Table of Contents

Table of Contents

Features
System Requirements
Installation
Quick Start
User Roles
Core Functionality
File Structure
Configuration
Usage Examples
Security Features
OOP Concepts Demonstrated
Troubleshooting
Resources

---

## ✨ Features

### **Log Management**
- CSV-based security log parsing
- Interactive log creation and editing
- Advanced log search capabilities (by user, IP, action)
- Automatic log sorting and analysis

### **Security Analysis**
- **Behavior Analysis**: User profiling based on login patterns and time windows
- **Threat Detection**: Automated identification of suspicious activities
- **Risk Scoring**: 0-100 risk assessment with actionable recommendations
- **Visual Analytics**: ASCII bar charts for failed login frequency

### **Rule-Based Detection**
- **Threshold Rules**: Detect repeated actions within time windows
- **IP Blacklist Rules**: Flag access from known malicious IPs
- **Custom Rule Builder**: Interactive rule creation interface

### **Incident Reporting**
- Automated incident report generation
- Password-protected reports
- Report encryption/decryption (XOR-based)
- Template-based quick notes
- Export functionality

### **Role-Based Access Control**
- **Security Admin**: Full system access
- **Security Analyst**: Analysis and log management
- **Security Auditor**: View-only access to reports

### **Advanced Features**
- Real-time timestamp display
- Behavioral anomaly detection
- Multi-account management with password protection
- Colored terminal output for enhanced readability
- Performance metrics (analysis time tracking)

---

## 💻 System Requirements

- **Compiler**: C++11 or later (C++17 recommended)
- **Operating System**: Linux, macOS, or Windows (with ANSI color support)
- **Terminal**: ANSI escape code compatible terminal
- **RAM**: Minimum 512 MB
- **Storage**: 10 MB free space

---

## 🚀 Installation

### **Compile from Source**

```bash
# Clone or download the source code
# Navigate to the project directory

# Compile with g++
g++ -std=c++17 -o cybersentinel main.cpp

# Or with clang++
clang++ -std=c++17 -o cybersentinel main.cpp

# Run the application
./cybersentinel
```

### **Windows Compilation**

```cmd
g++ -std=c++17 -o cybersentinel.exe main.cpp
cybersentinel.exe
```

---

## 🎯 Quick Start

### **First Run**

1. Launch the application:
   ```bash
   ./cybersentinel
   ```

2. The system automatically creates default files:
   - `accounts.txt` - User accounts
   - `system_logs.txt` - Sample security logs
   - `rules.txt` - Detection rules
   - `encrypted.key` - Encryption key

3. Select a role (Admin recommended for first use)

4. Login with default credentials:
   - **Admin**: `admin` / `admin123`
   - **Analyst**: `analyst` / `analyst123`
   - **Auditor**: `auditor` / `auditor123`

5. Navigate the menu to explore features

### **Basic Workflow**

1. **Create/Load Logs** → Log Management → Create system logs
2. **Configure Rules** → Rules & Configuration → Rule builder
3. **Analyze Logs** → Log Management → Analyze logs
4. **View Report** → Reporting & Encryption → View last report
5. **Check Threats** → Security Analysis → Threat summary

---

## 👥 User Roles

### **Security Admin** 🔴
**Access Level**: Full Control

**Capabilities**:
- All log management operations
- Security analysis and visualization
- Report creation, encryption, decryption
- Rule configuration and editing
- System utilities and settings
- Password management

**Use Case**: System administrators and security leads

---

### **Security Analyst** 🟡
**Access Level**: Analysis & Monitoring

**Capabilities**:
- Log management and creation
- Security analysis and behavior profiling
- Threat detection and visualization
- Limited report access

**Restrictions**:
- Cannot modify rules
- Cannot encrypt/decrypt reports
- Cannot access advanced utilities

**Use Case**: SOC analysts and security researchers

---

### **Security Auditor** 🟢
**Access Level**: View Only

**Capabilities**:
- View password-protected reports
- Export reports
- Read-only access to incident data

**Restrictions**:
- Cannot create or modify logs
- Cannot run analysis
- Cannot configure rules
- Cannot encrypt reports

**Use Case**: Compliance officers and external auditors

---

## 🔧 Core Functionality

### **1. Log Management**

#### **Analyze Logs & Generate Report**
Processes security logs through configured rules and generates comprehensive incident reports with:
- Alert details (user, IP, severity, timestamps)
- Custom analyst notes
- Password protection
- Performance metrics

#### **User Log Input**
Interactive log creation supporting:
- Username, action, and status entries
- Automated LOGIN analysis
- Failed login detection
- Statistical summaries

#### **Log Search**
Advanced filtering by:
- Username
- IP address
- Action type

---

### **2. Security Analysis & Visuals**

#### **Behavior Analysis**
Profiles user behavior including:
- Normal login time windows (Morning/Afternoon/Night)
- Typical IP addresses
- Success/failure rates
- Risk indicators

#### **Failed Login Bar Chart**
ASCII visualization showing login failure frequency per user

#### **Threat Summary**
Comprehensive risk assessment featuring:
- Brute-force detection
- High-severity operation counting
- 0-100 risk scoring
- Actionable recommendations
- Event timeline

#### **System Statistics**
- Total logs processed
- Unique users and IPs
- Login success/failure rates
- Most targeted users

---

### **3. Reporting & Encryption**

#### **Password-Protected Reports**
Reports require authentication before viewing

#### **Quick Incident Notes**
Template-based notes:
- Brute force attack template
- Blacklisted IP template
- Suspicious behavior template

#### **Report Export**
Copy reports to custom filenames

#### **Encryption/Decryption**
XOR-based symmetric encryption for sensitive reports

---

### **4. Rules & Configuration**

#### **Rule Builder**
Interactive interface for creating:

**Threshold Rules**:
```
THRESHOLD,ACTION,STATUS,WINDOW_SECONDS,THRESHOLD_COUNT
Example: THRESHOLD,LOGIN,FAILED,120,5
```
Detects 5+ failed logins within 120 seconds

**Blacklist Rules**:
```
BLACKLIST,IP1;IP2;IP3
Example: BLACKLIST,203.0.113.7;198.51.100.25
```
Flags access from listed IPs

#### **Rule Editor**
- View current rules
- Append new rules
- Clear all rules
- Hot-reload into analyzer

#### **Password Management**
Change report access password with verification

#### **File Cleanup**
Remove old report files and passwords

---

### **5. Utilities & Help**

- Sample log preview
- Security resource links (OWASP, MITRE ATT&CK, Snort, Suricata)
- Project documentation
- System information

---

## 📁 File Structure

```
cybersentinel/
│
├── cybersentinel         
├── main.cpp               
│
├── accounts.txt           
├── encrypted.key          
│
├── system_logs.txt        
├── user_logs.txt         
├── rules.txt             
│
├── incident_report.txt   
├── incident_report.enc    
├── report_pass.txt        
├── alerts.txt             

```

---

## ⚙️ Configuration

### **Log File Format** (`system_logs.txt`)

```csv
# timestamp, user, action, status, ip, severity
2025-11-07 09:41:21, root, LOGIN, FAILED, 192.168.1.10, 3
2025-11-07 10:15:10, alice, DOWNLOAD, SUCCESS, 10.0.0.5, 1
```

**Fields**:
- `timestamp`: YYYY-MM-DD HH:MM:SS
- `user`: Username
- `action`: LOGIN, DOWNLOAD, UPLOAD, DELETE, etc.
- `status`: SUCCESS or FAILED
- `ip`: IPv4 address
- `severity`: 1 (Low) to 4 (Critical)

### **Rules File Format** (`rules.txt`)

```
# Threshold rule: action, status, time window (seconds), count threshold
THRESHOLD,LOGIN,FAILED,120,5

# Blacklist rule: semicolon-separated IPs
BLACKLIST,203.0.113.7;198.51.100.25
```

### **Accounts File Format** (`accounts.txt`)

```
ROLE username password
ADMIN admin admin123
ANALYST analyst analyst123
AUDITOR auditor auditor123
```

---

## 📖 Usage Examples

### **Example 1: Detect Brute-Force Attack**

1. Login as **Admin**
2. Go to **Log Management** → **Create system_logs.txt**
3. Add 6+ failed LOGIN attempts from same user/IP within 2 minutes
4. Go to **Rules & Configuration** → **Create rules.txt**
5. Add threshold rule: `LOGIN,FAILED,120,5`
6. Return to **Log Management** → **Analyze logs**
7. View generated report showing brute-force alert

### **Example 2: Behavioral Analysis**

1. Login as **Analyst**
2. Ensure logs contain varied timestamps and user activities
3. Go to **Security Analysis** → **Behavior analysis**
4. Review normal login patterns and anomaly warnings

### **Example 3: Secure Report Sharing**

1. Login as **Admin**
2. Generate incident report
3. Set report password when prompted
4. Go to **Reporting** → **Encrypt report**
5. Share `incident_report.enc` file
6. Recipient uses **Decrypt report** with password

---

## 🔒 Security Features

### **Password Protection**
- Role-based authentication
- Report access control
- Password change capability
- Encrypted password storage (basic)

### **Encryption**
- XOR-based symmetric encryption
- Configurable encryption key
- File-level encryption for reports

### **Audit Trail**
- Timestamped operations
- User action logging
- Role-based access restrictions

### **Best Practices Implemented**
- Principle of least privilege (role separation)
- Defense in depth (multiple security layers)
- Secure configuration defaults
- Input validation

---

## 🎓 OOP Concepts Demonstrated

### **Classes & Objects**
- `LogEntry`, `SecurityLog`, `PrivilegedLog`
- `Alert`, `Rule`, `ThresholdRule`, `IPBlacklistRule`
- `LogAnalyzer`, `IncidentReport`, `Admin`

### **Inheritance**
- `SecurityLog` extends `LogEntry`
- `PrivilegedLog` extends `SecurityLog`
- `ThresholdRule` and `IPBlacklistRule` implement `Rule`
- Multiple inheritance: `SecurityLog` inherits from both `LogEntry` and `Printable`

### **Polymorphism**
- Virtual functions: `Rule::evaluate()`, `LogEntry::display()`
- Operator overloading: `<<` for Alert, `<` for SecurityLog, explicit cast operators
- Runtime polymorphism with `unique_ptr<Rule>`

### **Encapsulation**
- Private member variables with public accessors
- Protected inheritance in `AdminBase`
- Controlled data access through methods

### **Abstraction**
- Abstract base class `Rule` with pure virtual functions
- Abstract `Printable` interface
- Template class `Repository<T>`

### **Templates**
- Class template: `Repository<T>`
- Function templates: `utils::filter()`, `utils::groupBy()`

### **RAII & Smart Pointers**
- `unique_ptr` for rule management
- Automatic resource cleanup in destructors

---

## 🐛 Troubleshooting

### **Common Issues**

#### **Compilation Errors**
```bash
# Ensure C++11 or later
g++ -std=c++17 -o cybersentinel main.cpp

# Check for missing headers
# Verify all standard library includes are available
```

#### **Colors Not Displaying**
- Ensure terminal supports ANSI escape codes
- Windows: Use Windows Terminal or enable VT100 mode
- Alternative: Comment out color codes in `ui` namespace

#### **File Access Errors**
```bash
# Check file permissions
chmod 644 system_logs.txt rules.txt accounts.txt
chmod 755 cybersentinel

# Verify files exist in current directory
ls -la
```

#### **Login Failures**
- Default passwords are in `accounts.txt`
- Verify file format: `ROLE username password`
- Check for extra spaces or newlines

#### **Empty Analysis Reports**
- Ensure `system_logs.txt` has valid entries
- Check log format matches specification
- Verify `rules.txt` contains active rules

---

## 📚 Resources

### **Security Standards**
- [OWASP](https://owasp.org/) - Web Application Security
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat Intelligence
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### **IDS Tools**
- [Snort](https://www.snort.org/) - Network IDS
- [Suricata](https://suricata.io/) - Open-source IDS/IPS
- [OSSEC](https://www.ossec.net/) - Host-based IDS

### **Learning Resources**
- SANS Institute - Security Training
- Cybrary - Free Cybersecurity Courses
- TryHackMe - Hands-on Security Labs

---

## 🎖️ Acknowledgments

- OWASP Foundation for security guidelines
- MITRE Corporation for ATT&CK framework
- Open-source IDS community
- C++ standard library contributors

---

**CyberSentinel** - Empowering Security Professionals with Intelligent Log Analysis

*Built with C++ | Secured by Design | Powered by OOP*
