# Simple LDAP Honeypot Server

## Introduction
The Simple LDAP Honeypot Server is a low-interaction honeypot designed to observe and analyze LDAP-based network interactions. Written in Python with the Twisted framework, it emulates key LDAP behaviors (Bind, Search, RootDSE, and common Extended Requests) and logs authentication attempts and raw request bytes for incident analysis and threat research.

## Features
- **Low-Interaction Honeypot**: Emulates core LDAP operations without exposing a real directory service.
- **Improved Protocol Handling**: BER/LDAPMessage-aware parsing for Bind, Search, Unbind, and ExtendedRequest (including StartTLS OID).
- **Configurable RootDSE Metadata**: Customize `vendorName`, `vendorVersion`, `namingContexts`, and `defaultNamingContext` via CLI arguments.
- **Comprehensive Logging**:
  - Logs connection metadata and extracted credentials (when present).
  - Logs raw request bytes in hexadecimal for anomaly/zero-day detection.
- **Safety Controls**: Idle timeout and maximum buffer size to reduce resource abuse.

## Requirements
- Python 3.x
- Twisted

## Installation
```bash
git clone https://github.com/0xNslabs/ldap-honeypot.git
cd ldap-honeypot
pip install twisted
```

## Usage
Start the server with optional parameters for host and port. By default, it binds to all interfaces (`0.0.0.0`) on port `389`.

```bash
python3 ldap.py --host 0.0.0.0 --port 389
```

### RootDSE customization
Many scanners and LDAP clients query **RootDSE** via a base-scope search with an empty base DN (`base=""`, `scope=0`). This honeypot can emulate common directory metadata, and you can override key fields using CLI arguments.

#### Set vendor name/version
```bash
python3 ldap.py --host 0.0.0.0 --port 389 \
  --vendor-name "Microsoft Corporation" \
  --vendor-version "Windows Server"
```

#### Set naming contexts (repeatable)
```bash
python3 ldap.py --host 0.0.0.0 --port 389 \
  --naming-context "DC=corp,DC=local" \
  --naming-context "CN=Configuration,DC=corp,DC=local" \
  --naming-context "CN=Schema,CN=Configuration,DC=corp,DC=local"
```

#### Set default naming context
If omitted, `defaultNamingContext` defaults to the first `--naming-context`.

```bash
python3 ldap.py --host 0.0.0.0 --port 389 \
  --naming-context "DC=corp,DC=local" \
  --default-naming-context "DC=corp,DC=local"
```

## Logging
All LDAP interactions are logged to `ldap_honeypot.log`.

In addition to normal event lines, the server logs:
- `RAW BYTES HEX:` for each received TCP chunk
- `RAW LDAPMessage HEX:` for each fully parsed LDAPMessage

These raw-hex logs are useful for detecting malformed BER, fuzzing activity, and potential zero-day probing.

## Simple LDAP Honeypot In Action
![Simple LDAP Honeypot in Action](https://raw.githubusercontent.com/0xNslabs/ldap-honeypot/main/PoC.png)
*The above image showcases the Simple LDAP Honeypot Server in action, capturing real-time LDAP queries and credentials.*

## Other Simple Honeypot Services
- [DNS Honeypot](https://github.com/0xNslabs/dns-honeypot) - Monitors DNS interactions.
- [FTP Honeypot](https://github.com/0xNslabs/ftp-honeypot) - Simulates an FTP server.
- [HTTP Honeypot](https://github.com/0xNslabs/http-honeypot) - Monitors HTTP interactions.
- [HTTPS Honeypot](https://github.com/0xNslabs/https-honeypot) - Monitors HTTPS interactions.
- [MongoDB Honeypot](https://github.com/0xNslabs/mongodb-honeypot) - Simulates a MongoDB database server.
- [NTP Honeypot](https://github.com/0xNslabs/ntp-honeypot) - Monitors Network Time Protocol interactions.
- [PostgreSQL Honeypot](https://github.com/0xNslabs/postgresql-honeypot) - Simulates a PostgreSQL database server.
- [SIP Honeypot](https://github.com/0xNslabs/sip-honeypot) - Monitors SIP (Session Initiation Protocol) interactions.
- [SSH Honeypot](https://github.com/0xNslabs/ssh-honeypot) - Emulates an SSH server.
- [TELNET Honeypot](https://github.com/0xNslabs/telnet-honeypot) - Simulates a TELNET server.

## Security and Compliance
- **Caution**: Use this honeypot in secure, controlled environments for research and educational purposes.
- **Compliance**: Ensure deployment is in line with local and international legal requirements.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.
