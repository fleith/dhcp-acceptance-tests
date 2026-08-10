import os
import time

from behave import then, when

from dhcpv6_support import (
    INTERFACE,
    Ether,
    IPv6,
    UDP,
    cls as _cls,
    client_duid as _client_duid,
    context_storage_v6,
    dhcpv6_packets as _dhcpv6_packets,
    duids_equal as _duids_equal,
    get_server_duid as _get_server_duid,
    ia_na as _ia_na,
    new_trid as _new_trid,
    require_scapy_v6 as _require_scapy_v6,
    sc_dhcp6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


_FQDN_OPTION_CODE = 39
_SERVER_SUFFIX = os.getenv(
    "TEST_RFC4704_SERVER_SUFFIX",
    "dhcp-acceptance.test",
).strip(".")
_CLIENT_FQDN = os.getenv(
    "TEST_RFC4704_FQDN",
    f"rfc4704-client.{_SERVER_SUFFIX}.",
)
_EXPECTED_FQDN = os.getenv("TEST_RFC4704_EXPECTED_FQDN", _CLIENT_FQDN)
_CLIENT_FLAGS = os.getenv("TEST_RFC4704_CLIENT_FLAGS", "S")
_EXPECTED_FLAGS = os.getenv("TEST_RFC4704_EXPECTED_FLAGS", "S")
_NEGOTIATION_CLIENT_FLAGS = os.getenv(
    "TEST_RFC4704_NEGOTIATION_CLIENT_FLAGS",
    "S",
)
_PARTIAL_FQDN = os.getenv("TEST_RFC4704_PARTIAL_FQDN", "rfc4704-partial")
_EXPECTED_PARTIAL_FQDN = os.getenv(
    "TEST_RFC4704_EXPECTED_PARTIAL_FQDN",
    f"{_PARTIAL_FQDN}.{_SERVER_SUFFIX}.",
)


def _flags_value(value):
    if isinstance(value, int):
        return value
    text = str(value).strip().upper()
    if text in ("", "0", "NONE"):
        return 0
    try:
        return int(text, 0)
    except ValueError:
        pass
    unknown = set(text) - {"S", "O", "N", "+", ",", "|", " ", "-"}
    if unknown:
        raise ValueError(f"Unknown RFC 4704 flag characters: {sorted(unknown)}")
    return sum(bit for name, bit in (("S", 1), ("O", 2), ("N", 4)) if name in text)


def _normalized_flags(value):
    bits = _flags_value(value)
    return tuple(name for name, bit in (("S", 1), ("O", 2), ("N", 4)) if bits & bit)


def _dns_wire_name(name, terminated=True):
    text = name.decode("ascii") if isinstance(name, bytes) else str(name)
    labels = text.rstrip(".").split(".") if text.rstrip(".") else []
    encoded = bytearray()
    for label in labels:
        raw_label = label.encode("ascii")
        if not 1 <= len(raw_label) <= 63:
            raise ValueError(f"Invalid DNS label {label!r}")
        encoded.append(len(raw_label))
        encoded.extend(raw_label)
    if terminated:
        encoded.append(0)
    return bytes(encoded)


def _decode_dns_wire_name(wire):
    labels = []
    offset = 0
    terminated = False
    while offset < len(wire):
        length = wire[offset]
        offset += 1
        if length == 0:
            terminated = True
            break
        assert length <= 63, "RFC 4704 FQDN used a reserved DNS label encoding"
        end = offset + length
        assert end <= len(wire), "RFC 4704 FQDN contains a truncated DNS label"
        labels.append(wire[offset:end].decode("ascii"))
        offset = end
    assert offset == len(wire), "RFC 4704 FQDN contains trailing DNS wire data"
    name = ".".join(labels)
    return (name + "." if terminated else name), terminated


def _canonical_name(name, terminated=None):
    text = name.decode("ascii") if isinstance(name, bytes) else str(name)
    text = text.strip().lower()
    if terminated is None:
        terminated = text.endswith(".")
    return text.rstrip(".") + ("." if terminated else "")


def _raw_fqdn_option(name, flags, terminated=True):
    data = bytes([_flags_value(flags)]) + _dns_wire_name(name, terminated=terminated)
    return _cls("DHCP6OptUnknown")(optcode=_FQDN_OPTION_CODE, data=data)


def _fqdn_option(name, flags):
    packet_class = getattr(sc_dhcp6, "DHCP6OptClientFQDN", None)
    if packet_class is None:
        return _raw_fqdn_option(name, flags)
    return packet_class(flags=_flags_value(flags), fqdn=name)


def _client_message(message_name, trid):
    return (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls(message_name)(trid=trid)
    )


def _send_solicit(case, fqdn_option=None, requested_options=None):
    _require_scapy_v6()
    trid = _new_trid()
    packet = (
        _client_message("DHCP6_Solicit", trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na()
    )
    if fqdn_option is not None:
        packet /= fqdn_option
    if requested_options is not None:
        packet /= _cls("DHCP6OptOptReq")(reqopts=requested_options)

    response_class = _cls("DHCP6_Advertise")

    def matching_advertise(response):
        if not response.haslayer(response_class):
            return False
        if getattr(response[response_class], "trid", None) != trid:
            return False
        client_id = response.getlayer(_cls("DHCP6OptClientId"))
        return _duids_equal(getattr(client_id, "duid", None), _client_duid())

    sniffer = _start_v6_sniffer(timeout=12, stop_filter=matching_advertise)
    sendp(packet, iface=INTERFACE, verbose=False)
    context_storage_v6[f"rfc4704_{case}_trid"] = trid
    context_storage_v6[f"rfc4704_{case}_sniffer"] = sniffer


def _matching_response(case, message_name, expected_server_duid=None):
    trid = context_storage_v6[f"rfc4704_{case}_trid"]
    sniffer = context_storage_v6[f"rfc4704_{case}_sniffer"]
    candidates = _dhcpv6_packets(sniffer, message_name, trid)
    responses = []
    for packet in candidates:
        client_id = packet.getlayer(_cls("DHCP6OptClientId"))
        if not _duids_equal(getattr(client_id, "duid", None), _client_duid()):
            continue
        server_duid = _get_server_duid(packet)
        if server_duid is None:
            continue
        if expected_server_duid is not None and not _duids_equal(
            server_duid,
            expected_server_duid,
        ):
            continue
        responses.append(packet)
    assert responses, f"No matching DHCPv6 {message_name} received for RFC 4704 {case}"
    response = responses[0]
    message = response.getlayer(_cls(message_name))
    assert getattr(message, "trid", None) == trid, (
        f"RFC 4704 {message_name} transaction ID does not match {trid:#x}"
    )
    return response


def _assert_response_identity(packet, expected_server_duid=None):
    client_id = packet.getlayer(_cls("DHCP6OptClientId"))
    actual_client_duid = getattr(client_id, "duid", None)
    assert _duids_equal(actual_client_duid, _client_duid()), (
        "RFC 4704 response has an unexpected Client Identifier"
    )

    server_duid = _get_server_duid(packet)
    assert server_duid, "RFC 4704 response is missing a Server Identifier"
    if expected_server_duid is not None:
        assert _duids_equal(server_duid, expected_server_duid), (
            "RFC 4704 response came from a different DHCPv6 server"
        )
    return server_duid


def _find_fqdn_option(packet):
    packet_class = getattr(sc_dhcp6, "DHCP6OptClientFQDN", None)
    if packet_class is not None:
        option = packet.getlayer(packet_class)
        if option is not None:
            return option

    layer = packet
    while layer is not None:
        if getattr(layer, "optcode", None) == _FQDN_OPTION_CODE:
            return layer
        next_layer = getattr(layer, "payload", None)
        if next_layer is None or next_layer is layer:
            break
        layer = next_layer
    return None


def _fqdn_wire_fields(option):
    raw = bytes(option)
    assert len(raw) >= 5, "RFC 4704 Client FQDN option is truncated"
    option_code = int.from_bytes(raw[0:2], "big")
    option_length = int.from_bytes(raw[2:4], "big")
    assert option_code == _FQDN_OPTION_CODE, (
        f"Expected DHCPv6 option 39, got option {option_code}"
    )
    assert option_length >= 1, "RFC 4704 Client FQDN option has no Flags field"
    assert len(raw) >= 4 + option_length, "RFC 4704 option length exceeds its payload"
    body = raw[4 : 4 + option_length]
    return body[0], body[1:]


def _assert_fqdn(option, expected_name, expected_flags, allow_partial=False):
    assert option is not None, "Response is missing DHCPv6 Client FQDN option 39"
    wire_flags, wire_name = _fqdn_wire_fields(option)
    assert wire_flags & 0xF8 == 0, "RFC 4704 response did not clear reserved flag bits"

    actual_flags = _normalized_flags(wire_flags)
    wanted_flags = _normalized_flags(expected_flags)
    assert actual_flags == wanted_flags, (
        f"RFC 4704 flags differ: expected {wanted_flags}, got {actual_flags}"
    )

    decoded_name, terminated = _decode_dns_wire_name(wire_name)
    expected = _canonical_name(expected_name, terminated=True)
    if allow_partial:
        accepted_names = {
            _canonical_name(_PARTIAL_FQDN, terminated=False),
            expected,
        }
        assert _canonical_name(decoded_name, terminated=terminated) in accepted_names, (
            f"Unexpected RFC 4704 partial-name result {decoded_name!r}; "
            f"expected one of {sorted(accepted_names)}"
        )
    else:
        assert terminated, "Server returned a partial name instead of a complete FQDN"
        assert _canonical_name(decoded_name, terminated=True) == expected, (
            f"RFC 4704 FQDN differs: expected {expected!r}, got {decoded_name!r}"
        )


def _assert_negotiated_flags(option, client_flags):
    assert option is not None, "Response is missing DHCPv6 Client FQDN option 39"
    server_flags, _ = _fqdn_wire_fields(option)
    client_flags = _flags_value(client_flags)

    assert client_flags & 0x02 == 0, "RFC 4704 clients must clear the O flag"
    assert not (client_flags & 0x01 and client_flags & 0x04), (
        "RFC 4704 clients cannot request both S and N"
    )
    assert server_flags & 0xF8 == 0, (
        "RFC 4704 response did not clear reserved flag bits"
    )
    assert not (server_flags & 0x01 and server_flags & 0x04), (
        "RFC 4704 server set mutually exclusive S and N flags"
    )

    server_overrode_s = bool(server_flags & 0x01) != bool(client_flags & 0x01)
    assert bool(server_flags & 0x02) == server_overrode_s, (
        "RFC 4704 server must set O exactly when it overrides the client's S preference"
    )


def _capture_advertise(case):
    advertise = _matching_response(case, "DHCP6_Advertise")
    server_duid = _assert_response_identity(advertise)
    iaaddr = advertise.getlayer(_cls("DHCP6OptIAAddress"))
    assert iaaddr is not None and getattr(iaaddr, "addr", None), (
        "RFC 4704 ADVERTISE is missing an IA Address"
    )
    context_storage_v6["rfc4704_server_duid"] = server_duid
    context_storage_v6["rfc4704_offered_ipv6"] = iaaddr.addr
    context_storage_v6["rfc4704_offered_preferred_lifetime"] = iaaddr.preflft
    context_storage_v6["rfc4704_offered_valid_lifetime"] = iaaddr.validlft
    return advertise


@when("an RFC 4704 client sends a SOLICIT with its configured FQDN and requests option 39")
def step_when_solicit_with_fqdn(context):
    _send_solicit(
        "positive_solicit",
        fqdn_option=_fqdn_option(_CLIENT_FQDN, _CLIENT_FLAGS),
        requested_options=[_FQDN_OPTION_CODE],
    )


@then("the matching ADVERTISE contains the negotiated RFC 4704 FQDN")
def step_then_advertise_contains_fqdn(context):
    advertise = _capture_advertise("positive_solicit")
    _assert_fqdn(_find_fqdn_option(advertise), _EXPECTED_FQDN, _EXPECTED_FLAGS)


@when("the RFC 4704 client sends a REQUEST with its configured FQDN and requests option 39")
def step_when_request_with_fqdn(context):
    _require_scapy_v6()
    trid = _new_trid()
    request = (
        _client_message("DHCP6_Request", trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptServerId")(duid=context_storage_v6["rfc4704_server_duid"])
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na(
            context_storage_v6["rfc4704_offered_ipv6"],
            context_storage_v6["rfc4704_offered_preferred_lifetime"],
            context_storage_v6["rfc4704_offered_valid_lifetime"],
        )
        / _fqdn_option(_CLIENT_FQDN, _CLIENT_FLAGS)
        / _cls("DHCP6OptOptReq")(reqopts=[_FQDN_OPTION_CODE])
    )
    response_class = _cls("DHCP6_Reply")

    def matching_reply(response):
        if not response.haslayer(response_class):
            return False
        if getattr(response[response_class], "trid", None) != trid:
            return False
        client_id = response.getlayer(_cls("DHCP6OptClientId"))
        return _duids_equal(getattr(client_id, "duid", None), _client_duid())

    sniffer = _start_v6_sniffer(timeout=12, stop_filter=matching_reply)
    sendp(request, iface=INTERFACE, verbose=False)
    context_storage_v6["rfc4704_positive_request_trid"] = trid
    context_storage_v6["rfc4704_positive_request_sniffer"] = sniffer


@then("the matching REPLY contains the negotiated RFC 4704 FQDN")
def step_then_reply_contains_fqdn(context):
    reply = _matching_response(
        "positive_request",
        "DHCP6_Reply",
        context_storage_v6["rfc4704_server_duid"],
    )
    _assert_response_identity(reply, context_storage_v6["rfc4704_server_duid"])
    _assert_fqdn(_find_fqdn_option(reply), _EXPECTED_FQDN, _EXPECTED_FLAGS)


@when("an RFC 4704 client sends a SOLICIT with a partial FQDN and requests option 39")
def step_when_solicit_with_partial_fqdn(context):
    _send_solicit(
        "partial",
        fqdn_option=_raw_fqdn_option(_PARTIAL_FQDN, _CLIENT_FLAGS, terminated=False),
        requested_options=[_FQDN_OPTION_CODE],
    )


@then("the matching ADVERTISE contains a valid RFC 4704 name for the partial FQDN")
def step_then_advertise_handles_partial_fqdn(context):
    advertise = _capture_advertise("partial")
    _assert_fqdn(
        _find_fqdn_option(advertise),
        _EXPECTED_PARTIAL_FQDN,
        _EXPECTED_FLAGS,
        allow_partial=True,
    )


@when("an RFC 4704 client sends a SOLICIT with its FQDN but omits option 39 from the ORO")
def step_when_solicit_fqdn_not_in_oro(context):
    _send_solicit(
        "not_requested",
        fqdn_option=_fqdn_option(_CLIENT_FQDN, _CLIENT_FLAGS),
        requested_options=[23, 24],
    )


@when("an RFC 4704 client requests option 39 without sending a Client FQDN option")
def step_when_solicit_without_fqdn(context):
    _send_solicit("not_supplied", requested_options=[_FQDN_OPTION_CODE])


@then("the matching ADVERTISE does not contain an RFC 4704 Client FQDN option")
def step_then_advertise_omits_fqdn(context):
    case = "not_requested" if "rfc4704_not_requested_trid" in context_storage_v6 else "not_supplied"
    advertise = _matching_response(case, "DHCP6_Advertise")
    _assert_response_identity(advertise)
    assert _find_fqdn_option(advertise) is None, (
        "ADVERTISE included Client FQDN without both option 39 and an ORO request"
    )


@then("the matching ADVERTISE exposes the known Kea 2.2 unrequested FQDN behavior")
def step_then_advertise_documents_kea_unrequested_fqdn(context):
    advertise = _matching_response("not_requested", "DHCP6_Advertise")
    _assert_response_identity(advertise)
    assert _find_fqdn_option(advertise) is not None, (
        "Kea no longer returns an unrequested Client FQDN; remove this "
        "non-compliance scenario and run the RFC omission scenario instead"
    )


@when("an RFC 4704 client sends a SOLICIT with a legal S preference")
def step_when_solicit_with_legal_s_preference(context):
    _send_solicit(
        "flag_negotiation",
        fqdn_option=_fqdn_option(_CLIENT_FQDN, _NEGOTIATION_CLIENT_FLAGS),
        requested_options=[_FQDN_OPTION_CODE],
    )


@then("the matching ADVERTISE negotiates RFC 4704 flags according to server policy")
def step_then_advertise_negotiates_flags(context):
    advertise = _matching_response("flag_negotiation", "DHCP6_Advertise")
    _assert_response_identity(advertise)
    _assert_negotiated_flags(
        _find_fqdn_option(advertise),
        _NEGOTIATION_CLIENT_FLAGS,
    )


@when("an RFC 4704 client sends a SOLICIT with a truncated FQDN DNS label")
def step_when_solicit_with_truncated_fqdn(context):
    _require_scapy_v6()
    trid = _new_trid()
    malformed_fqdn = _cls("DHCP6OptUnknown")(
        optcode=_FQDN_OPTION_CODE,
        data=b"\x01\x0arfc47",
    )
    packet = (
        _client_message("DHCP6_Solicit", trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na()
        / _cls("DHCP6OptOptReq")(reqopts=[_FQDN_OPTION_CODE])
        / malformed_fqdn
    )
    sendp(packet, iface=INTERFACE, verbose=False)
    time.sleep(0.25)


@when("the client sends a valid RFC 4704 SOLICIT after the malformed FQDN")
def step_when_valid_solicit_after_malformed(context):
    _send_solicit(
        "recovery",
        fqdn_option=_fqdn_option(_CLIENT_FQDN, _CLIENT_FLAGS),
        requested_options=[_FQDN_OPTION_CODE],
    )


@then("the matching ADVERTISE proves RFC 4704 negotiation remains responsive")
def step_then_server_remains_responsive(context):
    advertise = _matching_response("recovery", "DHCP6_Advertise")
    _assert_response_identity(advertise)
    _assert_fqdn(
        _find_fqdn_option(advertise),
        _EXPECTED_FQDN,
        _EXPECTED_FLAGS,
    )
