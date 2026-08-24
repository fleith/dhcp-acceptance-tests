#!/usr/bin/env python3
"""Small authoritative RFC 2136 observer used by the isolated DDNS profile."""

import os
import socketserver
import struct
import threading

import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset


ZONE = os.getenv("DDNS_ZONE", "dhcp-acceptance.test.").rstrip(".") + "."
_records = {}
_lock = threading.Lock()


def _canonical(name):
    return str(name).rstrip(".").lower() + "."


def _operation_class(rrset):
    deleting = getattr(rrset, "deleting", None)
    return deleting if deleting is not None else rrset.rdclass


def _apply_update(request):
    changes = []
    with _lock:
        for rrset in request.authority:
            name = _canonical(rrset.name)
            operation = _operation_class(rrset)
            if rrset.rdtype == dns.rdatatype.ANY:
                if operation == dns.rdataclass.ANY:
                    for key in [key for key in _records if key[0] == name]:
                        _records.pop(key, None)
                    changes.append(f"delete-name {name}")
                continue
            if rrset.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
                continue
            key = (name, rrset.rdtype)
            record_type = dns.rdatatype.to_text(rrset.rdtype).lower()
            if operation == dns.rdataclass.ANY:
                _records.pop(key, None)
                changes.append(f"delete-{record_type} {name}")
            elif operation == dns.rdataclass.NONE:
                values = {rdata.address for rdata in rrset}
                remaining = _records.get(key, set()) - values
                if remaining:
                    _records[key] = remaining
                else:
                    _records.pop(key, None)
                changes.append(
                    f"delete-{record_type}-values {name} {sorted(values)}"
                )
            else:
                values = {rdata.address for rdata in rrset}
                _records.setdefault(key, set()).update(values)
                changes.append(f"add-{record_type} {name} {sorted(values)}")
    for change in changes:
        print(f"[ddns-observer] {change}", flush=True)


def _soa_for(name):
    zone = _canonical(name)
    return dns.rrset.from_text(
        zone,
        60,
        dns.rdataclass.IN,
        dns.rdatatype.SOA,
        f"ns1.{zone} hostmaster.{zone} 1 60 60 60 60",
    )


def _response_for(wire):
    request = dns.message.from_wire(wire, one_rr_per_rrset=True)
    response = dns.message.make_response(request)
    response.flags |= dns.flags.AA
    if request.opcode() == dns.opcode.UPDATE:
        _apply_update(request)
        response.set_rcode(dns.rcode.NOERROR)
        return response.to_wire()

    if not request.question:
        response.set_rcode(dns.rcode.FORMERR)
        return response.to_wire()

    question = request.question[0]
    name = _canonical(question.name)
    if question.rdtype == dns.rdatatype.SOA:
        response.answer.append(_soa_for(question.name))
    elif question.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        with _lock:
            addresses = sorted(_records.get((name, question.rdtype), set()))
        if addresses:
            response.answer.append(
                dns.rrset.from_text(
                    name,
                    30,
                    dns.rdataclass.IN,
                    question.rdtype,
                    *addresses,
                )
            )
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)
            response.authority.append(_soa_for(ZONE))
    elif question.rdtype == dns.rdatatype.ANY:
        with _lock:
            record_sets = [
                (record_type, sorted(values))
                for (record_name, record_type), values in _records.items()
                if record_name == name and values
            ]
        for record_type, values in record_sets:
            response.answer.append(
                dns.rrset.from_text(
                    name,
                    30,
                    dns.rdataclass.IN,
                    record_type,
                    *values,
                )
            )
        if not record_sets:
            response.set_rcode(dns.rcode.NXDOMAIN)
            response.authority.append(_soa_for(ZONE))
    else:
        response.set_rcode(dns.rcode.NOERROR)
        response.authority.append(_soa_for(ZONE))
    return response.to_wire()


class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        payload, socket = self.request
        try:
            socket.sendto(_response_for(payload), self.client_address)
        except Exception as exc:
            print(f"[ddns-observer] UDP error: {exc}", flush=True)


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        header = self.request.recv(2)
        if len(header) != 2:
            return
        expected = struct.unpack("!H", header)[0]
        payload = b""
        while len(payload) < expected:
            chunk = self.request.recv(expected - len(payload))
            if not chunk:
                return
            payload += chunk
        try:
            response = _response_for(payload)
            self.request.sendall(struct.pack("!H", len(response)) + response)
        except Exception as exc:
            print(f"[ddns-observer] TCP error: {exc}", flush=True)


class _UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class _TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main():
    udp = _UdpServer(("0.0.0.0", 53), _UdpHandler)
    tcp = _TcpServer(("0.0.0.0", 53), _TcpHandler)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    print(f"[ddns-observer] authoritative observer ready for {ZONE}", flush=True)
    udp.serve_forever()


if __name__ == "__main__":
    main()
