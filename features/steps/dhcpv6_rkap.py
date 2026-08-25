"""Wire-level RFC 9915 Reconfiguration Key Authentication Protocol helpers."""

from dataclasses import dataclass
import hashlib
import hmac


DHCPV6_REPLY = 7
DHCPV6_RECONFIGURE = 10

OPTION_CLIENT_ID = 1
OPTION_SERVER_ID = 2
OPTION_AUTH = 11
OPTION_INTERFACE_ID = 18
OPTION_RECONFIGURE_MESSAGE = 19

RKAP_PROTOCOL = 3
RKAP_ALGORITHM_HMAC_MD5 = 1
RKAP_RDM_MONOTONIC = 0
RKAP_KEY_TYPE = 1
RKAP_HMAC_TYPE = 2


class RkapValidationError(ValueError):
    """Raised when a DHCPv6 message violates the RKAP wire contract."""


@dataclass(frozen=True)
class Dhcpv6Option:
    code: int
    value: bytes
    offset: int


@dataclass(frozen=True)
class RkapKey:
    value: bytes
    replay: int


@dataclass(frozen=True)
class ValidatedReconfigure:
    replay: int
    requested_message: int
    option_codes: tuple[int, ...]


def parse_dhcpv6_message(message):
    data = bytes(message)
    if len(data) < 4:
        raise RkapValidationError("DHCPv6 message is shorter than its four-byte header")

    options = []
    offset = 4
    while offset < len(data):
        if len(data) - offset < 4:
            raise RkapValidationError("DHCPv6 option header is truncated")
        code = int.from_bytes(data[offset : offset + 2], "big")
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        end = offset + 4 + length
        if end > len(data):
            raise RkapValidationError(
                f"DHCPv6 option {code} declares {length} bytes past message end"
            )
        options.append(Dhcpv6Option(code, data[offset + 4 : end], offset))
        offset = end

    return data[0], int.from_bytes(data[1:4], "big"), tuple(options)


def _single_option(options, code, name):
    matches = [option for option in options if option.code == code]
    if len(matches) != 1:
        raise RkapValidationError(
            f"{name} must appear exactly once; received {len(matches)}"
        )
    return matches[0]


def _parse_rkap_auth(option, expected_type):
    if len(option.value) != 28:
        raise RkapValidationError(
            f"RKAP Authentication payload must be 28 bytes; received {len(option.value)}"
        )
    protocol, algorithm, rdm = option.value[:3]
    if protocol != RKAP_PROTOCOL:
        raise RkapValidationError(f"Authentication protocol {protocol} is not RKAP")
    if algorithm != RKAP_ALGORITHM_HMAC_MD5:
        raise RkapValidationError(
            f"RKAP algorithm {algorithm} is not the required HMAC-MD5 algorithm"
        )
    if rdm != RKAP_RDM_MONOTONIC:
        raise RkapValidationError(
            f"RKAP replay detection method {rdm} is not monotonic-counter mode"
        )
    auth_type = option.value[11]
    if auth_type != expected_type:
        raise RkapValidationError(
            f"RKAP authentication information type {auth_type} is not {expected_type}"
        )
    return int.from_bytes(option.value[3:11], "big"), option.value[12:28]


def extract_rkap_key(reply_message):
    message_type, _, options = parse_dhcpv6_message(reply_message)
    if message_type != DHCPV6_REPLY:
        raise RkapValidationError(
            f"RKAP key must be learned from DHCPv6 REPLY, not type {message_type}"
        )
    auth = _single_option(options, OPTION_AUTH, "Authentication option")
    replay, key = _parse_rkap_auth(auth, RKAP_KEY_TYPE)
    return RkapKey(key, replay)


def validate_rkap_reconfigure(
    reconfigure_message,
    key,
    expected_client_duid,
    expected_server_duid,
    previous_replay=None,
):
    data = bytes(reconfigure_message)
    message_type, transaction_id, options = parse_dhcpv6_message(data)
    if message_type != DHCPV6_RECONFIGURE:
        raise RkapValidationError(
            f"Expected DHCPv6 RECONFIGURE type 10; received {message_type}"
        )
    if transaction_id != 0:
        raise RkapValidationError(
            f"DHCPv6 RECONFIGURE transaction ID must be zero; received {transaction_id}"
        )

    allowed = {
        OPTION_CLIENT_ID,
        OPTION_SERVER_ID,
        OPTION_AUTH,
        OPTION_RECONFIGURE_MESSAGE,
    }
    unexpected = [option.code for option in options if option.code not in allowed]
    if unexpected:
        raise RkapValidationError(
            "DHCPv6 RECONFIGURE contains forbidden option codes: "
            + ", ".join(str(code) for code in unexpected)
        )

    client_id = _single_option(options, OPTION_CLIENT_ID, "Client Identifier")
    server_id = _single_option(options, OPTION_SERVER_ID, "Server Identifier")
    message_option = _single_option(
        options, OPTION_RECONFIGURE_MESSAGE, "Reconfigure Message option"
    )
    auth = _single_option(options, OPTION_AUTH, "Authentication option")

    if client_id.value != bytes(expected_client_duid):
        raise RkapValidationError("RECONFIGURE targets an unexpected client DUID")
    if server_id.value != bytes(expected_server_duid):
        raise RkapValidationError("RECONFIGURE uses an unexpected server DUID")
    if len(message_option.value) != 1 or message_option.value[0] not in (5, 6, 11):
        raise RkapValidationError("Reconfigure Message option has an invalid message type")

    replay, received_digest = _parse_rkap_auth(auth, RKAP_HMAC_TYPE)
    if previous_replay is not None and replay <= previous_replay:
        raise RkapValidationError(
            f"RKAP replay value {replay} is not greater than {previous_replay}"
        )

    zeroed = bytearray(data)
    digest_start = auth.offset + 4 + 12
    zeroed[digest_start : digest_start + 16] = b"\x00" * 16
    expected_digest = hmac.new(bytes(key), zeroed, hashlib.md5).digest()
    if not hmac.compare_digest(received_digest, expected_digest):
        raise RkapValidationError("RKAP HMAC-MD5 validation failed")

    return ValidatedReconfigure(
        replay=replay,
        requested_message=message_option.value[0],
        option_codes=tuple(option.code for option in options),
    )
