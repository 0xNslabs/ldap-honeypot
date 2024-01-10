# Simple LDAP Honeypot Server

## Introduction
The Simple LDAP Honeypot Server is a specialized tool created for cybersecurity experts and hobbyists to observe and analyze LDAP-based network interactions. Written in Python and utilizing the Twisted framework, this script simulates an LDAP server to log unauthorized access attempts and credentials, offering valuable insights into potential network vulnerabilities and intrusion attempts.

## Features
- **Low-Interaction Honeypot**: Effectively imitates an LDAP server, focusing on logging authentication attempts.
- **Flexible Configuration**: Easily modify host and port settings through command-line arguments.
- **Comprehensive Logging**: Captures detailed information about LDAP queries, including usernames and passwords.
- **Real-Time Monitoring**: Instantly logs and reports LDAP interaction, aiding in prompt detection of suspicious activities.
- **Educational Purpose**: Serves as an excellent resource for understanding LDAP security threats and reconnaissance tactics.

## Requirements
- Python 3.x
- Twisted Python library

## Installation
To set up the LDAP honeypot server, follow these instructions:

```bash
git clone https://github.com/0xNslabs/ldap-honeypot.git
cd ldap-honeypot
pip install twisted
```

## Usage
Launch the server with optional parameters for the host and port. The default settings bind the server to all interfaces (0.0.0.0) on port 389.

```bash
python3 ldap.py --host 0.0.0.0 --port 389
```

## Logging
The LDAP honeypot logs all captured interactions in ldap_honeypot.log, providing a record of authentication attempts and LDAP queries for further analysis.

## Simple LDAP Honeypot In Action
![Simple LDAP Honeypot in Action](https://raw.githubusercontent.com/0xNslabs/ldap-honeypot/main/PoC.png)
*The above image showcases the Simple LDAP Honeypot Server in action, capturing real-time LDAP queries and credentials.*

## Security and Compliance
- **Caution**:  Use this honeypot in secure, controlled environments for research and educational purposes.
- **Compliance**: Ensure deployment is in line with local and international legal requirements.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.