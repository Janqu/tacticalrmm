#!/usr/bin/env python3
"""SNMP poller that runs on a TRMM agent acting as a probe for its site.

Upload this into the Script Manager (shell: python) and run it from an automated
task on one agent per site, with arguments:

    --url https://api.example.com --agent-id {{agent.agent_id}} --api-key {{global.snmp_api_key}}

It asks the server which devices belong to its own site, polls them, and posts the
readings back. Standard library only on purpose: the agent ships a bare Python with
no third party packages, and shipping a net-snmp binary to every probe is not worth
it for what amounts to a few UDP round trips.

Run with --selftest to check the BER codec without touching the network.
"""

import argparse
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------- BER / ASN.1

SEQUENCE = 0x30
INTEGER = 0x02
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
GET_REQUEST = 0xA0
GET_RESPONSE = 0xA2

# SNMPv2c "this OID does not exist here" markers, returned in place of a value
NO_SUCH_OBJECT = 0x80
NO_SUCH_INSTANCE = 0x81
END_OF_MIB_VIEW = 0x82
MISSING = (NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW)

# value tags that carry an unsigned integer
COUNTER32 = 0x41
GAUGE32 = 0x42
TIMETICKS = 0x43
COUNTER64 = 0x46
UNSIGNED_TAGS = (COUNTER32, GAUGE32, TIMETICKS, COUNTER64)


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(body)) + body


def _enc_int(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return _tlv(INTEGER, value.to_bytes(length, "big", signed=True))


def _enc_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip(".").split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part < 0x80:
            body.append(part)
            continue
        chunk = bytearray()
        while part:
            chunk.insert(0, (part & 0x7F) | 0x80)
            part >>= 7
        chunk[-1] &= 0x7F
        body += chunk
    return _tlv(OID, bytes(body))


def _read_len(data: bytes, pos: int):
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    return int.from_bytes(data[pos : pos + count], "big"), pos + count


def _read_tlv(data: bytes, pos: int):
    tag = data[pos]
    length, pos = _read_len(data, pos + 1)
    return tag, data[pos : pos + length], pos + length


def _decode_value(tag: int, body: bytes):
    if tag in MISSING:
        return None
    if tag == INTEGER:
        return int.from_bytes(body, "big", signed=True)
    if tag in UNSIGNED_TAGS:
        return int.from_bytes(body, "big")
    if tag == OCTET_STRING:
        return body.decode("utf-8", "replace").strip("\x00").strip()
    if tag == OID:
        return body.hex()
    if tag == NULL:
        return None
    return body.hex()


def build_get(community: str, oids, request_id: int) -> bytes:
    varbinds = b"".join(_tlv(SEQUENCE, _enc_oid(o) + _tlv(NULL, b"")) for o in oids)
    pdu = _tlv(
        GET_REQUEST,
        _enc_int(request_id)
        + _enc_int(0)  # error-status
        + _enc_int(0)  # error-index
        + _tlv(SEQUENCE, varbinds),
    )
    return _tlv(
        SEQUENCE,
        _enc_int(1)  # version 1 == SNMPv2c
        + _tlv(OCTET_STRING, community.encode())
        + pdu,
    )


def parse_response(data: bytes) -> dict:
    """Returns {oid: value}. Missing OIDs are simply absent."""
    _, msg, _ = _read_tlv(data, 0)
    pos = 0
    _, _, pos = _read_tlv(msg, pos)  # version
    _, _, pos = _read_tlv(msg, pos)  # community
    tag, pdu, _ = _read_tlv(msg, pos)
    if tag != GET_RESPONSE:
        raise ValueError(f"unexpected PDU tag 0x{tag:02x}")

    pos = 0
    _, _, pos = _read_tlv(pdu, pos)  # request-id
    _, err, pos = _read_tlv(pdu, pos)  # error-status
    _, _, pos = _read_tlv(pdu, pos)  # error-index
    if int.from_bytes(err, "big"):
        return {}

    _, varbinds, _ = _read_tlv(pdu, pos)

    out = {}
    pos = 0
    while pos < len(varbinds):
        _, vb, pos = _read_tlv(varbinds, pos)
        _, oid_body, inner = _read_tlv(vb, 0)
        tag, body, _ = _read_tlv(vb, inner)
        value = _decode_value(tag, body)
        if value is not None:
            out[_oid_to_str(oid_body)] = value
    return out


def _oid_to_str(body: bytes) -> str:
    parts = [body[0] // 40, body[0] % 40]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def snmp_get(host: str, port: int, community: str, oids, timeout=2.0, retries=1) -> dict:
    request = build_get(community, oids, request_id=1)
    last_error = None
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(request, (host, port))
            data, _ = sock.recvfrom(65535)
            return parse_response(data)
        except Exception as err:  # timeouts, refused, malformed
            last_error = err
        finally:
            sock.close()
    raise TimeoutError(str(last_error) if last_error else "no response")


# ------------------------------------------------------------------ OID sets

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"

PRT_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"
PRT_PAGES = "1.3.6.1.2.1.43.10.2.1.4.1.1"
# supplies table, probed by index rather than walked to keep the codec GET-only
PRT_SUPPLY_DESC = "1.3.6.1.2.1.43.11.1.1.6.1."
PRT_SUPPLY_MAX = "1.3.6.1.2.1.43.11.1.1.8.1."
PRT_SUPPLY_LEVEL = "1.3.6.1.2.1.43.11.1.1.9.1."
MAX_SUPPLIES = 8

UPS_CHARGE = "1.3.6.1.2.1.33.1.2.4.0"
UPS_MINUTES = "1.3.6.1.2.1.33.1.2.3.0"
UPS_BATT_STATUS = "1.3.6.1.2.1.33.1.2.1.0"
UPS_LOAD = "1.3.6.1.2.1.33.1.4.4.1.5.1"

IF_NUMBER = "1.3.6.1.2.1.2.1.0"


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")
    return slug or "supply"


def poll_printer(host, port, community, timeout, retries) -> tuple:
    base = snmp_get(
        host, port, community,
        [SYS_DESCR, SYS_NAME, PRT_SERIAL, PRT_PAGES],
        timeout, retries,
    )
    metrics = {}
    if PRT_PAGES in base:
        metrics["pages.total"] = float(base[PRT_PAGES])

    supply_oids = []
    for i in range(1, MAX_SUPPLIES + 1):
        supply_oids += [f"{PRT_SUPPLY_DESC}{i}", f"{PRT_SUPPLY_MAX}{i}", f"{PRT_SUPPLY_LEVEL}{i}"]
    supplies = snmp_get(host, port, community, supply_oids, timeout, retries)

    for i in range(1, MAX_SUPPLIES + 1):
        level = supplies.get(f"{PRT_SUPPLY_LEVEL}{i}")
        maximum = supplies.get(f"{PRT_SUPPLY_MAX}{i}")
        if level is None or maximum is None:
            continue
        # negative levels are the MIB's "unknown" / "no restriction" sentinels
        if level < 0 or maximum <= 0:
            continue
        name = _slug(supplies.get(f"{PRT_SUPPLY_DESC}{i}", ""))
        metrics[f"supply.{name}"] = round(level / maximum * 100, 1)

    return base.get(SYS_DESCR), base.get(PRT_SERIAL), metrics


def poll_ups(host, port, community, timeout, retries) -> tuple:
    data = snmp_get(
        host, port, community,
        [SYS_DESCR, UPS_CHARGE, UPS_MINUTES, UPS_BATT_STATUS, UPS_LOAD],
        timeout, retries,
    )
    metrics = {
        key: float(data[oid])
        for key, oid in (
            ("battery.charge_percent", UPS_CHARGE),
            ("battery.minutes_remaining", UPS_MINUTES),
            ("battery.status", UPS_BATT_STATUS),
            ("output.load_percent", UPS_LOAD),
        )
        if oid in data
    }
    return data.get(SYS_DESCR), None, metrics


def poll_generic(host, port, community, timeout, retries) -> tuple:
    data = snmp_get(
        host, port, community, [SYS_DESCR, SYS_NAME, SYS_UPTIME, IF_NUMBER], timeout, retries
    )
    metrics = {}
    if SYS_UPTIME in data:
        # TimeTicks are hundredths of a second
        metrics["uptime.seconds"] = float(data[SYS_UPTIME]) / 100.0
    if IF_NUMBER in data:
        metrics["interfaces.count"] = float(data[IF_NUMBER])
    return data.get(SYS_DESCR), None, metrics


POLLERS = {"printer": poll_printer, "ups": poll_ups}


# ---------------------------------------------------------------------- main


def _http(url: str, api_key: str, payload=None, insecure=False):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={"X-API-KEY": api_key, "Content-Type": "application/json"},
        method="POST" if data else "GET",
    )
    ctx = ssl._create_unverified_context() if insecure else None
    with urllib.request.urlopen(request, timeout=30, context=ctx) as response:
        return json.loads(response.read().decode() or "null")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="https://api.example.com")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--insecure", action="store_true", help="self signed cert")
    args = parser.parse_args()

    endpoint = f"{args.url.rstrip('/')}/qdt_snmp/probe/{args.agent_id}/devices/"

    try:
        devices = _http(endpoint, args.api_key, insecure=args.insecure)
    except urllib.error.HTTPError as err:
        print(f"could not fetch device list: HTTP {err.code} {err.read()[:200]!r}")
        return 1
    except Exception as err:
        print(f"could not fetch device list: {err}")
        return 1

    if not devices:
        print("no snmp devices configured for this site")
        return 0

    results, unreachable = [], 0
    for device in devices:
        poller = POLLERS.get(device["device_type"], poll_generic)
        try:
            descr, serial, metrics = poller(
                device["ip"], device["port"], device["community"],
                args.timeout, args.retries,
            )
            results.append({
                "id": device["id"],
                "reachable": True,
                "model_name": descr,
                "serial": serial,
                "metrics": metrics,
            })
            print(f"ok   {device['name']} ({device['ip']}): {metrics}")
        except Exception as err:
            unreachable += 1
            results.append({"id": device["id"], "reachable": False, "error": str(err)[:2000]})
            print(f"FAIL {device['name']} ({device['ip']}): {err}")

    try:
        summary = _http(endpoint, args.api_key, payload=results, insecure=args.insecure)
        print(f"posted: {summary}")
    except Exception as err:
        print(f"could not post readings: {err}")
        return 1

    # non-zero when anything was unreachable, so this doubles as a script check
    return 1 if unreachable else 0


def selftest() -> int:
    assert _enc_oid("1.3.6.1.2.1.1.1.0").hex() == "06082b06010201010100"
    assert _oid_to_str(bytes.fromhex("2b06010201010100")) == "1.3.6.1.2.1.1.1.0"
    # a long OID arc has to survive the 7-bit continuation encoding
    for oid in ("1.3.6.1.2.1.43.11.1.1.9.1.1", "1.3.6.1.4.1.9999.128.300.1"):
        body = _enc_oid(oid)
        _, decoded, _ = _read_tlv(body, 0)
        assert _oid_to_str(decoded) == oid, oid
    assert _enc_len(200).hex() == "81c8"
    assert _enc_len(4) == b"\x04"

    request = build_get("public", [SYS_DESCR, SYS_NAME], request_id=1)
    assert request[0] == SEQUENCE

    # a hand-built response must round trip through the parser
    varbinds = _tlv(SEQUENCE, _enc_oid(SYS_DESCR) + _tlv(OCTET_STRING, b"HP LaserJet"))
    varbinds += _tlv(SEQUENCE, _enc_oid(PRT_PAGES) + _tlv(COUNTER32, (15234).to_bytes(4, "big")))
    varbinds += _tlv(SEQUENCE, _enc_oid(PRT_SERIAL) + _tlv(NO_SUCH_INSTANCE, b""))
    pdu = _tlv(GET_RESPONSE, _enc_int(1) + _enc_int(0) + _enc_int(0) + _tlv(SEQUENCE, varbinds))
    message = _tlv(SEQUENCE, _enc_int(1) + _tlv(OCTET_STRING, b"public") + pdu)

    parsed = parse_response(message)
    assert parsed[SYS_DESCR] == "HP LaserJet", parsed
    assert parsed[PRT_PAGES] == 15234, parsed
    assert PRT_SERIAL not in parsed, "missing OIDs must be dropped, not returned as junk"

    assert _slug("Black Toner Cartridge") == "black_toner_cartridge"
    assert _slug("") == "supply"
    print("selftest ok")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main())
