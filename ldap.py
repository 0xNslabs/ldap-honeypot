import os
import argparse
from binascii import unhexlify, hexlify
from contextlib import suppress
from twisted.internet import reactor, protocol
from twisted.python import log

script_dir = os.path.dirname(os.path.abspath(__file__))

OID_STARTTLS = "1.3.6.1.4.1.1466.20037"
LDAP_RESULT_SUCCESS = 0
LDAP_RESULT_OPERATIONS_ERROR = 1
LDAP_RESULT_PROTOCOL_ERROR = 2
LDAP_RESULT_INVALID_CREDENTIALS = 49
LDAP_RESULT_INSUFFICIENT_ACCESS = 50
LDAP_RESULT_UNWILLING_TO_PERFORM = 53


class _IncompleteBER(Exception):
    pass

def _hex_preview(b: bytes, limit: int = 8192) -> str:
    if b is None:
        return ""
    if len(b) <= limit:
        return hexlify(b).decode("ascii", "ignore")
    return hexlify(b[:limit]).decode("ascii", "ignore") + f"...(truncated,{len(b)}B)"


def _ber_read_tlv(buf: bytes, off: int):
    if off + 2 > len(buf):
        raise _IncompleteBER()

    tag = buf[off]
    lb = buf[off + 1]
    p = off + 2

    if (lb & 0x80) == 0:
        ln = lb
    else:
        n = lb & 0x7F
        if n == 0:
            raise ValueError("indefinite_length_not_supported")
        if p + n > len(buf):
            raise _IncompleteBER()
        ln = int.from_bytes(buf[p : p + n], "big", signed=False)
        p += n

    end = p + ln
    if end > len(buf):
        raise _IncompleteBER()

    return tag, p - off, ln, p, end


def _decode_integer(buf: bytes, off: int):
    tag, _, _, v0, v1 = _ber_read_tlv(buf, off)
    if tag != 0x02:
        raise ValueError("expected_integer")
    raw = buf[v0:v1]
    n = int.from_bytes(raw, "big", signed=(raw[:1] >= b"\x80"))
    return n, v1


def _decode_enumerated(buf: bytes, off: int):
    tag, _, _, v0, v1 = _ber_read_tlv(buf, off)
    if tag != 0x0A:
        raise ValueError("expected_enumerated")
    raw = buf[v0:v1]
    n = int.from_bytes(raw, "big", signed=(raw[:1] >= b"\x80"))
    return n, v1


def _decode_boolean(buf: bytes, off: int):
    tag, _, ln, v0, v1 = _ber_read_tlv(buf, off)
    if tag != 0x01 or ln != 1:
        raise ValueError("expected_boolean")
    return buf[v0] != 0, v1


def _decode_octet_string(buf: bytes, off: int):
    tag, _, _, v0, v1 = _ber_read_tlv(buf, off)
    if tag != 0x04:
        raise ValueError("expected_octet_string")
    return buf[v0:v1], v1


def _decode_context_octet_string(buf: bytes, off: int, expected_tag: int):
    tag, _, _, v0, v1 = _ber_read_tlv(buf, off)
    if tag != expected_tag:
        raise ValueError("expected_context_octet_string")
    return buf[v0:v1], v1


def _ber_encode_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _ber_encode(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_encode_len(len(payload)) + payload


def _ber_int(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    if n > 0:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big", signed=False)
        if b[0] & 0x80:
            b = b"\x00" + b
        return b
    return n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)


def _ber_encode_integer(n: int) -> bytes:
    return _ber_encode(0x02, _ber_int(int(n)))


def _ber_encode_enumerated(n: int) -> bytes:
    return _ber_encode(0x0A, _ber_int(int(n)))


def _ber_encode_octet_string(s: bytes) -> bytes:
    return _ber_encode(0x04, s)


def _ber_encode_sequence(items: list) -> bytes:
    return _ber_encode(0x30, b"".join(items))


def _ber_encode_set(items: list) -> bytes:
    return _ber_encode(0x31, b"".join(items))


def _ber_encode_application(app_tag: int, encoded_components: list) -> bytes:
    payload = b"".join(encoded_components)
    return bytes([app_tag]) + _ber_encode_len(len(payload)) + payload


def _ldap_message(msgid: int, protocol_op_tlv: bytes) -> bytes:
    return _ber_encode_sequence([_ber_encode_integer(msgid), protocol_op_tlv])


def _encode_bind_response(msgid: int, code: int, matched_dn: str = "", diag: str = "") -> bytes:
    op = _ber_encode_application(
        0x61,
        [
            _ber_encode_enumerated(code),
            _ber_encode_octet_string((matched_dn or "").encode("utf-8", "ignore")),
            _ber_encode_octet_string((diag or "").encode("utf-8", "ignore")),
        ],
    )
    return _ldap_message(msgid, op)


def _encode_search_result_done(msgid: int, code: int, matched_dn: str = "", diag: str = "") -> bytes:
    op = _ber_encode_application(
        0x65,
        [
            _ber_encode_enumerated(code),
            _ber_encode_octet_string((matched_dn or "").encode("utf-8", "ignore")),
            _ber_encode_octet_string((diag or "").encode("utf-8", "ignore")),
        ],
    )
    return _ldap_message(msgid, op)


def _encode_partial_attribute(attr: str, values: list) -> bytes:
    vals = [_ber_encode_octet_string(str(v).encode("utf-8", "ignore")) for v in (values or [])]
    return _ber_encode_sequence(
        [
            _ber_encode_octet_string((attr or "").encode("utf-8", "ignore")),
            _ber_encode_set(vals),
        ]
    )


def _encode_search_result_entry(msgid: int, dn: str, attrs: dict) -> bytes:
    pal = []
    for k, v in (attrs or {}).items():
        if v is None:
            continue
        if isinstance(v, list):
            pal.append(_encode_partial_attribute(str(k), [str(x) for x in v]))
        else:
            pal.append(_encode_partial_attribute(str(k), [str(v)]))
    attributes_tlv = _ber_encode_sequence(pal)
    op = _ber_encode_application(
        0x64,
        [
            _ber_encode_octet_string((dn or "").encode("utf-8", "ignore")),
            attributes_tlv,
        ],
    )
    return _ldap_message(msgid, op)


def _encode_extended_response(msgid: int, code: int, matched_dn: str = "", diag: str = "", resp_name: str | None = None) -> bytes:
    parts = [
        _ber_encode_enumerated(code),
        _ber_encode_octet_string((matched_dn or "").encode("utf-8", "ignore")),
        _ber_encode_octet_string((diag or "").encode("utf-8", "ignore")),
    ]
    if resp_name:
        parts.append(_ber_encode(0x8A, resp_name.encode("ascii", "ignore")))
    op = _ber_encode_application(0x78, parts)
    return _ldap_message(msgid, op)


class SimpleLDAPProtocol(protocol.Protocol):
    MAX_BUFFER = 1024 * 1024
    IDLE_TIMEOUT_S = 12

    def connectionMade(self):
        self._buf = b""
        self._idle_call = None
        self._last_msgid = 1
        self._last_op_tag = None
        self._last_req_name = ""
        self._last_search_is_rootdse = False
        self._reset_idle_timer()

        client_ip = self.transport.getPeer().host
        client_port = self.transport.getPeer().port
        log.msg(f"LDAP NEW Connection - Client IP: {client_ip}, Port: {client_port}")

    def _reset_idle_timer(self):
        with suppress(Exception):
            if self._idle_call and self._idle_call.active():
                self._idle_call.cancel()
        with suppress(Exception):
            self._idle_call = reactor.callLater(self.IDLE_TIMEOUT_S, self._idle_timeout)

    def _idle_timeout(self):
        with suppress(Exception):
            self.transport.loseConnection()

    def dataReceived(self, data):
        log.msg(f"Received data: {data}")
        log.msg(f"RAW BYTES HEX: {_hex_preview(data)}")

        if not data:
            return

        self._reset_idle_timer()

        if len(self._buf) + len(data) > self.MAX_BUFFER:
            log.msg(f"RAW BYTES HEX: buffer_overflow len={len(self._buf) + len(data)}")
            with suppress(Exception):
                self.transport.loseConnection()
            return

        self._buf += data

        while True:
            try:
                msg, consumed = self._try_parse_ldap_message(self._buf)
            except _IncompleteBER:
                return
            except Exception:
                self._send_fallback_and_close()
                return

            if msg is None:
                return

            self._buf = self._buf[consumed:]
            log.msg(f"RAW LDAPMessage HEX: {_hex_preview(msg)}")

            username, password = self.parse_ldap_packet(msg)
            if username or password:
                if isinstance(username, bytes):
                    username = username.decode("utf-8", "ignore")
                if isinstance(password, bytes):
                    password = password.decode("utf-8", "ignore")
                log.msg(f"Credentials - Username: {username}, Password: {password}")

            frames = self._build_response_frames()
            for fr in frames:
                with suppress(Exception):
                    self.transport.write(fr)

            if self._last_op_tag == 0x42:
                with suppress(Exception):
                    self.transport.loseConnection()
                return

            if not self._buf:
                return

    def connectionLost(self, reason):
        with suppress(Exception):
            if self._idle_call and self._idle_call.active():
                self._idle_call.cancel()
        self._buf = b""
        log.msg("Connection lost")

    def _try_parse_ldap_message(self, buf: bytes):
        if not buf:
            return None, 0
        tag, hdr, ln, _, _ = _ber_read_tlv(buf, 0)
        if tag != 0x30:
            raise ValueError("expected_sequence")
        total = hdr + ln
        if total > len(buf):
            raise _IncompleteBER()
        return buf[:total], total

    def _decode_ldap_message(self, msg: bytes):
        tag, _, _, v0, v1 = _ber_read_tlv(msg, 0)
        if tag != 0x30:
            raise ValueError("bad_message")
        inner = msg[v0:v1]
        off = 0
        msgid, off = _decode_integer(inner, off)
        op_tag, _, _, op_v0, op_v1 = _ber_read_tlv(inner, off)
        op_val = inner[op_v0:op_v1]
        return msgid, op_tag, op_val

    def _send_fallback_and_close(self):
        with suppress(Exception):
            self.transport.write(unhexlify(b"300c02010165070a013204000400"))
        with suppress(Exception):
            self.transport.loseConnection()

    def _build_rootdse_attrs(self) -> dict:
        naming_contexts = list(getattr(self.factory, "ldap_naming_contexts", []) or [])
        default_nc = str(getattr(self.factory, "ldap_default_naming_context", "") or "")
        vendor_name = str(getattr(self.factory, "ldap_vendor_name", "Microsoft Corporation") or "Microsoft Corporation")
        vendor_version = str(getattr(self.factory, "ldap_vendor_version", "Windows Server") or "Windows Server")

        naming_contexts = [str(x).strip() for x in naming_contexts if str(x).strip()]
        if not naming_contexts:
            naming_contexts = ["DC=corp,DC=local", "CN=Configuration,DC=corp,DC=local", "CN=Schema,CN=Configuration,DC=corp,DC=local"]

        if not default_nc.strip():
            default_nc = naming_contexts[0]

        return {
            "namingContexts": naming_contexts,
            "defaultNamingContext": [default_nc],
            "supportedLDAPVersion": ["3", "2"],
            "supportedExtension": [OID_STARTTLS],
            "vendorName": [vendor_name],
            "vendorVersion": [vendor_version],
        }

    def _build_response_frames(self) -> list:
        msgid = int(getattr(self, "_last_msgid", 1) or 1)
        op = getattr(self, "_last_op_tag", None)

        if op == 0x60:
            return [_encode_bind_response(msgid, LDAP_RESULT_SUCCESS, "", "")]
        if op == 0x63:
            if bool(getattr(self, "_last_search_is_rootdse", False)):
                entry = _encode_search_result_entry(msgid, "", self._build_rootdse_attrs())
                done = _encode_search_result_done(msgid, LDAP_RESULT_SUCCESS, "", "")
                return [entry, done]
            return [_encode_search_result_done(msgid, LDAP_RESULT_SUCCESS, "", "")]
        if op == 0x77:
            oid = str(getattr(self, "_last_req_name", "") or "")
            if oid == OID_STARTTLS:
                return [_encode_extended_response(msgid, LDAP_RESULT_UNWILLING_TO_PERFORM, "", "unwillingToPerform", resp_name=OID_STARTTLS)]
            return [_encode_extended_response(msgid, LDAP_RESULT_PROTOCOL_ERROR, "", "protocolError")]
        if op == 0x42:
            return []
        return [_encode_search_result_done(msgid, LDAP_RESULT_PROTOCOL_ERROR, "", "protocolError")]

    def parse_ldap_packet(self, data):
        username, password = "", ""
        self._last_msgid = 1
        self._last_op_tag = None
        self._last_req_name = ""
        self._last_search_is_rootdse = False

        with suppress(Exception):
            msgid, op_tag, op_val = self._decode_ldap_message(data)
            self._last_msgid = int(msgid)
            self._last_op_tag = int(op_tag)

            if op_tag == 0x60:
                off = 0
                _, off = _decode_integer(op_val, off)
                dn_b, off = _decode_octet_string(op_val, off)
                username = dn_b
                tag, _, _, v0, v1 = _ber_read_tlv(op_val, off)
                if tag == 0x80:
                    password = op_val[v0:v1]
                return username, password

            if op_tag == 0x63:
                off = 0
                base_b, off = _decode_octet_string(op_val, off)
                scope, off = _decode_enumerated(op_val, off)
                self._last_search_is_rootdse = (base_b == b"") and (int(scope) == 0)
                return "", ""

            if op_tag == 0x77:
                with suppress(Exception):
                    name_b, _ = _decode_context_octet_string(op_val, 0, 0x80)
                    self._last_req_name = name_b.decode("utf-8", "ignore")
                return "", ""

        return username, password


class SimpleLDAPFactory(protocol.ServerFactory):
    protocol = SimpleLDAPProtocol


def main():
    parser = argparse.ArgumentParser(description="Run a simple LDAP honeypot server.")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind the LDAP server to.")
    parser.add_argument("--port", type=int, default=389, help="Port to bind the LDAP server to.")
    parser.add_argument("--vendor-name", type=str, default="Microsoft Corporation", help="RootDSE vendorName value.")
    parser.add_argument("--vendor-version", type=str, default="Windows Server", help="RootDSE vendorVersion value.")
    parser.add_argument(
        "--naming-context",
        dest="naming_contexts",
        action="append",
        default=["DC=corp,DC=local", "CN=Configuration,DC=corp,DC=local", "CN=Schema,CN=Configuration,DC=corp,DC=local"],
        help="Repeatable. RootDSE namingContexts value(s).",
    )
    parser.add_argument(
        "--default-naming-context",
        dest="default_naming_context",
        type=str,
        default="",
        help="RootDSE defaultNamingContext value. Defaults to first --naming-context.",
    )
    args = parser.parse_args()

    naming_contexts = [str(x).strip() for x in (args.naming_contexts or []) if str(x).strip()]
    if not naming_contexts:
        naming_contexts = ["DC=corp,DC=local", "CN=Configuration,DC=corp,DC=local", "CN=Schema,CN=Configuration,DC=corp,DC=local"]

    default_nc = str(args.default_naming_context or "").strip()
    if not default_nc:
        default_nc = naming_contexts[0]

    LOG_FILE_PATH = os.path.join(script_dir, "ldap_honeypot.log")
    print(f"LDAP HONEYPOT ACTIVE ON HOST: {args.host}, PORT: {args.port}")
    print(f"ALL attempts will be logged in: {LOG_FILE_PATH}")
    log_observer = log.FileLogObserver(open(LOG_FILE_PATH, "a"))
    log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    ldap_factory = SimpleLDAPFactory()
    ldap_factory.ldap_vendor_name = str(args.vendor_name)
    ldap_factory.ldap_vendor_version = str(args.vendor_version)
    ldap_factory.ldap_naming_contexts = naming_contexts
    ldap_factory.ldap_default_naming_context = default_nc

    reactor.listenTCP(args.port, ldap_factory, interface=args.host)
    reactor.run()


if __name__ == "__main__":
    main()
