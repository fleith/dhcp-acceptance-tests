"""DHCPv6 lease lifetime validation steps."""

from behave import then

from dhcpv6_support import cls, context_storage_v6


def _request_reply():
    sniffer = context_storage_v6.get("request_sniffer")
    trid = context_storage_v6.get("request_trid")
    assert sniffer is not None, "No DHCPv6 REQUEST capture is available"
    assert trid is not None, "No DHCPv6 REQUEST transaction ID is available"

    reply_class = cls("DHCP6_Reply")
    replies = [
        packet
        for packet in (sniffer.results or [])
        if packet.haslayer(reply_class)
        and getattr(packet[reply_class], "trid", None) == trid
    ]
    assert replies, "No captured DHCPv6 REPLY for the REQUEST"
    return replies[0]


def _assert_approximately(actual, expected, label):
    tolerance = max(2, expected * 0.05)
    assert abs(actual - expected) <= tolerance, (
        f"{label}={actual}s is not approximately {expected}s "
        f"(tolerance +/-{tolerance}s)"
    )


@then("the DHCPv6 REPLY has the expected IA_NA timers")
def step_then_reply_has_expected_ia_na_timers(context):
    ia_na = _request_reply().getlayer(cls("DHCP6OptIA_NA"))
    assert ia_na is not None, "DHCPv6 REPLY missing IA_NA option"

    _assert_approximately(ia_na.T1, 60, "IA_NA T1")
    _assert_approximately(ia_na.T2, 105, "IA_NA T2")
    assert ia_na.T1 < ia_na.T2, (
        f"IA_NA T1={ia_na.T1}s must be less than T2={ia_na.T2}s"
    )


@then("the DHCPv6 REPLY has the expected IA Address lifetimes")
def step_then_reply_has_expected_ia_address_lifetimes(context):
    ia_address = _request_reply().getlayer(cls("DHCP6OptIAAddress"))
    assert ia_address is not None, "DHCPv6 REPLY missing IA Address option"

    preferred = ia_address.preflft
    valid = ia_address.validlft
    assert preferred > 0, "IA Address preferred lifetime must be nonzero"
    assert valid > 0, "IA Address valid lifetime must be nonzero"
    _assert_approximately(preferred, 120, "IA Address preferred lifetime")
    _assert_approximately(valid, 120, "IA Address valid lifetime")
    assert preferred <= valid, (
        f"IA Address preferred lifetime={preferred}s must not exceed "
        f"valid lifetime={valid}s"
    )
