import os
import argparse
from binascii import unhexlify
from contextlib import suppress
from struct import unpack
from twisted.internet import reactor, protocol, endpoints
from twisted.python import log

script_dir = os.path.dirname(os.path.abspath(__file__))


class SimpleLDAPProtocol(protocol.Protocol):
    def connectionMade(self):
        client_ip = self.transport.getPeer().host
        client_port = self.transport.getPeer().port
        log.msg(f"LDAP NEW Connection - Client IP: {client_ip}, Port: {client_port}")

    def dataReceived(self, data):
        log.msg(f"Received data: {data}")
        username, password = self.parse_ldap_packet(data)
        if username or password:
            if isinstance(username, bytes):
                username = username.decode()
            if isinstance(password, bytes):
                password = password.decode()

            log.msg(f"Credentials - Username: {username}, Password: {password}")
        self.transport.write(unhexlify(b"300c02010165070a013204000400"))
        self.transport.loseConnection()

    def connectionLost(self, reason):
        log.msg("Connection lost")

    def parse_ldap_packet(self, data):
        username, password = "", ""
        with suppress(Exception):
            version = data.find(b"\x02\x01\x03")
            if version > 0:
                username_start = version + 5
                username_end = (
                    unpack("b", data[version + 4 : username_start])[0] + username_start
                )
                username = data[username_start:username_end]
                auth_type = data[username_end]
                if auth_type == 0x80:
                    if data[username_end + 1] == 0x82:
                        password_start = username_end + 4
                        password_end = (
                            unpack(">H", data[username_end + 2 : username_end + 4])[0]
                            + username_end
                            + 4
                        )
                    else:
                        password_start = username_end + 2
                        password_end = (
                            unpack("b", data[username_end + 2 : username_end + 3])[0]
                            + username_start
                            + 2
                        )
                    password = data[password_start:password_end]
        return username, password


class SimpleLDAPFactory(protocol.ServerFactory):
    protocol = SimpleLDAPProtocol


def main():
    parser = argparse.ArgumentParser(description="Run a simple LDAP honeypot server.")
    parser.add_argument(
        "--host", type=str, default="0.0.0.0", help="Host to bind the LDAP server to."
    )
    parser.add_argument(
        "--port", type=int, default=389, help="Port to bind the LDAP server to."
    )
    args = parser.parse_args()

    LOG_FILE_PATH = os.path.join(script_dir, "ldap_honeypot.log")
    print(f"LDAP HONEYPOT ACTIVE ON HOST: {args.host}, PORT: {args.port}")
    print(f"ALL attempts will be logged in: {LOG_FILE_PATH}")
    log_observer = log.FileLogObserver(open(LOG_FILE_PATH, "a"))
    log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    ldap_factory = SimpleLDAPFactory()

    reactor.listenTCP(args.port, ldap_factory, interface=args.host)
    reactor.run()


if __name__ == "__main__":
    main()
