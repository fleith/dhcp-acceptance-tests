import hashlib
import hmac
import unittest

from features.steps.dhcpv6_rkap import (
    OPTION_AUTH,
    OPTION_CLIENT_ID,
    OPTION_INTERFACE_ID,
    OPTION_RECONFIGURE_MESSAGE,
    OPTION_SERVER_ID,
    RkapValidationError,
    extract_rkap_key,
    parse_dhcpv6_message,
    validate_rkap_reconfigure,
)


CLIENT_DUID = bytes.fromhex("0004" + "11" * 16)
SERVER_DUID = bytes.fromhex("0004" + "22" * 16)
RKAP_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def _option(code, value):
    return code.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _auth_payload(replay, auth_type, value):
    return bytes([3, 1, 0]) + replay.to_bytes(8, "big") + bytes([auth_type]) + value


def _reply_with_key(replay=4):
    return (
        bytes([7, 0, 0, 1])
        + _option(OPTION_SERVER_ID, SERVER_DUID)
        + _option(OPTION_CLIENT_ID, CLIENT_DUID)
        + _option(OPTION_AUTH, _auth_payload(replay, 1, RKAP_KEY))
    )


def _signed_reconfigure(replay=5, extra_options=b""):
    message = (
        bytes([10, 0, 0, 0])
        + _option(OPTION_SERVER_ID, SERVER_DUID)
        + _option(OPTION_CLIENT_ID, CLIENT_DUID)
        + _option(OPTION_RECONFIGURE_MESSAGE, b"\x05")
        + extra_options
        + _option(OPTION_AUTH, _auth_payload(replay, 2, b"\x00" * 16))
    )
    digest = hmac.new(RKAP_KEY, message, hashlib.md5).digest()
    return message[:-16] + digest


class Dhcpv6RkapTests(unittest.TestCase):
    def test_extracts_key_from_initial_reply_and_validates_reconfigure(self):
        learned = extract_rkap_key(_reply_with_key())
        validated = validate_rkap_reconfigure(
            _signed_reconfigure(),
            learned.value,
            CLIENT_DUID,
            SERVER_DUID,
            previous_replay=learned.replay,
        )

        self.assertEqual(learned.value, RKAP_KEY)
        self.assertEqual(validated.replay, 5)
        self.assertEqual(validated.requested_message, 5)

    def test_tampered_authenticated_message_is_rejected(self):
        message = bytearray(_signed_reconfigure())
        _, _, options = parse_dhcpv6_message(message)
        reconf = next(
            option for option in options if option.code == OPTION_RECONFIGURE_MESSAGE
        )
        message[reconf.offset + 4] = 6

        with self.assertRaisesRegex(RkapValidationError, "HMAC-MD5"):
            validate_rkap_reconfigure(
                message, RKAP_KEY, CLIENT_DUID, SERVER_DUID, previous_replay=4
            )

    def test_equal_or_older_replay_value_is_rejected(self):
        for replay in (5, 4):
            with self.subTest(replay=replay):
                with self.assertRaisesRegex(RkapValidationError, "not greater"):
                    validate_rkap_reconfigure(
                        _signed_reconfigure(replay),
                        RKAP_KEY,
                        CLIENT_DUID,
                        SERVER_DUID,
                        previous_replay=5,
                    )

    def test_interface_id_is_forbidden_in_direct_reconfigure(self):
        with self.assertRaisesRegex(RkapValidationError, "forbidden option codes: 18"):
            validate_rkap_reconfigure(
                _signed_reconfigure(
                    extra_options=_option(OPTION_INTERFACE_ID, b"relay-only")
                ),
                RKAP_KEY,
                CLIENT_DUID,
                SERVER_DUID,
                previous_replay=4,
            )

    def test_duplicate_authentication_option_is_rejected(self):
        duplicate = _option(OPTION_AUTH, _auth_payload(5, 2, b"\x00" * 16))
        with self.assertRaisesRegex(RkapValidationError, "forbidden|exactly once"):
            validate_rkap_reconfigure(
                _signed_reconfigure(extra_options=duplicate),
                RKAP_KEY,
                CLIENT_DUID,
                SERVER_DUID,
                previous_replay=4,
            )

    def test_truncated_option_is_rejected(self):
        with self.assertRaisesRegex(RkapValidationError, "past message end"):
            parse_dhcpv6_message(bytes([10, 0, 0, 0, 0, 1, 0, 9, 1]))


if __name__ == "__main__":
    unittest.main()
