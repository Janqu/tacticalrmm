#!/usr/bin/env python3
"""SNMP poller that runs on a TRMM agent acting as a probe for its site.

Upload this into the Script Manager (shell: python) and run it from an automated
task on one agent per site, with arguments:

    --url https://api.example.com --agent-id {{agent.agent_id}} --api-key {{global.snmp_api_key}}

It asks the server which devices belong to its own site, polls them, and posts the
readings back. Standard library only on purpose: the agent ships a bare Python with
no third party packages, and shipping a net-snmp binary to every probe is not worth
it for what amounts to a few UDP round trips.

A device row may carry a metric_map saying which OID to report under which name; if
it does, that is used verbatim. Otherwise the built-in profile for the device type
applies. Printers vary enough between vendors that guessing in code does not work.

To work out the map for a new model, run it against one device without a server:

    --dump 192.168.10.50 [--community public] [--port 161]

That walks the relevant subtrees and prints json: the decoded supplies with their
colorant and fill level, a suggested metric_map, and the raw OIDs behind it.

Run with --selftest to check the codec and the decoding without a network.
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
GET_NEXT_REQUEST = 0xA1
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


def build_get(community: str, oids, request_id: int, pdu_tag: int = GET_REQUEST) -> bytes:
    varbinds = b"".join(_tlv(SEQUENCE, _enc_oid(o) + _tlv(NULL, b"")) for o in oids)
    pdu = _tlv(
        pdu_tag,
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


def _exchange(host, port, community, oids, timeout, retries, pdu_tag) -> dict:
    request = build_get(community, oids, request_id=1, pdu_tag=pdu_tag)
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


def snmp_get(host: str, port: int, community: str, oids, timeout=2.0, retries=1) -> dict:
    return _exchange(host, port, community, oids, timeout, retries, GET_REQUEST)


def snmp_walk(host, port, community, root: str, timeout=2.0, retries=1, limit=200) -> dict:
    """GETNEXT down a subtree. Used by --dump; the scheduled poll stays GET only."""
    prefix = root.rstrip(".") + "."
    current = root
    out = {}

    for _ in range(limit):
        reply = _exchange(host, port, community, [current], timeout, retries, GET_NEXT_REQUEST)
        if not reply:
            break
        # exactly one varbind comes back for a single-OID GETNEXT
        next_oid, value = next(iter(reply.items()))
        if not next_oid.startswith(prefix) or next_oid in out:
            break
        out[next_oid] = value
        current = next_oid

    return out


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

# prtInput: paper trays, probed by index just like the supplies table
INPUT_MAX_COL = "1.3.6.1.2.1.43.8.2.1.9.1."
INPUT_LEVEL_COL = "1.3.6.1.2.1.43.8.2.1.10.1."
INPUT_NAME_COL = "1.3.6.1.2.1.43.8.2.1.13.1."
INPUT_MEDIA_COL = "1.3.6.1.2.1.43.8.2.1.12.1."
INPUT_DESC_COL = "1.3.6.1.2.1.43.8.2.1.18.1."
MAX_TRAYS = 8


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

    tray_oids = []
    for i in range(1, MAX_TRAYS + 1):
        tray_oids += [
            f"{INPUT_NAME_COL}{i}",
            f"{INPUT_DESC_COL}{i}",
            f"{INPUT_MAX_COL}{i}",
            f"{INPUT_LEVEL_COL}{i}",
        ]
    trays = snmp_get(host, port, community, tray_oids, timeout, retries)

    for i in range(1, MAX_TRAYS + 1):
        level = trays.get(f"{INPUT_LEVEL_COL}{i}")
        maximum = trays.get(f"{INPUT_MAX_COL}{i}")
        # same sentinel rules as supplies: negative means unknown, not empty
        if not isinstance(level, int) or not isinstance(maximum, int):
            continue
        if level < 0 or maximum <= 0:
            continue
        name = trays.get(f"{INPUT_NAME_COL}{i}") or trays.get(f"{INPUT_DESC_COL}{i}")
        metrics[f"tray.{_slug(name) if name else i}"] = round(level / maximum * 100, 1)

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


def poll_from_map(host, port, community, metric_map, timeout, retries) -> tuple:
    """Poll exactly what the device row says to poll.

    Preferred over the built-in profiles: vendors disagree about how the printer MIB
    should be filled in, so the mapping belongs on the device where --dump and a human
    (or an assistant) can get it right per model instead of being guessed in code.
    """
    wanted = [SYS_DESCR]
    for spec in metric_map.values():
        wanted.append(spec["oid"])
        if spec.get("max_oid"):
            wanted.append(spec["max_oid"])

    data = snmp_get(host, port, community, sorted(set(wanted)), timeout, retries)

    metrics = {}
    for metric, spec in metric_map.items():
        raw = data.get(spec["oid"])
        if raw is None or isinstance(raw, str):
            continue
        if spec.get("max_oid"):
            maximum = data.get(spec["max_oid"])
            if not isinstance(maximum, (int, float)) or maximum <= 0 or raw < 0:
                continue
            metrics[metric] = round(raw / maximum * 100, 1)
        else:
            metrics[metric] = round(float(raw) * float(spec.get("scale", 1)), 2)

    return data.get(SYS_DESCR), None, metrics


# ------------------------------------------------------------------ discovery

# subtrees worth showing when working out what a device actually exposes
DUMP_TREES = {
    "system": "1.3.6.1.2.1.1",
    "printer.general": "1.3.6.1.2.1.43.5.1.1",
    "printer.marker": "1.3.6.1.2.1.43.10.2.1",
    "printer.supplies": "1.3.6.1.2.1.43.11.1.1",
    "printer.colorant": "1.3.6.1.2.1.43.12.1.1",
    "printer.input": "1.3.6.1.2.1.43.8.2.1",
    "host.device": "1.3.6.1.2.1.25.3.2.1",
    "ups": "1.3.6.1.2.1.33",
}

SUPPLY_TYPES = {
    1: "other", 2: "unknown", 3: "toner", 4: "wasteToner", 5: "ink",
    6: "inkCartridge", 7: "inkRibbon", 8: "wasteInk", 9: "opc", 10: "developer",
    11: "fuserOil", 12: "solidWax", 13: "ribbonWax", 14: "wasteWax", 15: "fuser",
}

SUPPLY_DESC_COL = "1.3.6.1.2.1.43.11.1.1.6.1."
SUPPLY_TYPE_COL = "1.3.6.1.2.1.43.11.1.1.5.1."
SUPPLY_MAX_COL = "1.3.6.1.2.1.43.11.1.1.8.1."
SUPPLY_LEVEL_COL = "1.3.6.1.2.1.43.11.1.1.9.1."
SUPPLY_COLORANT_COL = "1.3.6.1.2.1.43.11.1.1.3.1."
COLORANT_VALUE_COL = "1.3.6.1.2.1.43.12.1.1.4.1."


def decode_trays(trees: dict) -> list:
    """Paper trays from prtInput. Same sentinel rules as supplies: a negative level
    means unknown or "capacity not reported", not an empty tray."""
    tree = trees.get("printer.input", {})
    indices = sorted(
        {int(oid[len(INPUT_LEVEL_COL) :]) for oid in tree if oid.startswith(INPUT_LEVEL_COL)}
    )

    out = []
    for i in indices:
        level = tree.get(f"{INPUT_LEVEL_COL}{i}")
        maximum = tree.get(f"{INPUT_MAX_COL}{i}")
        name = tree.get(f"{INPUT_NAME_COL}{i}") or tree.get(f"{INPUT_DESC_COL}{i}")
        out.append({
            "index": i,
            "name": name or f"Schacht {i}",
            "media": tree.get(f"{INPUT_MEDIA_COL}{i}"),
            "level": level,
            "max": maximum,
            "percent": (
                round(level / maximum * 100, 1)
                if isinstance(level, int) and isinstance(maximum, int) and maximum > 0 and level >= 0
                else None
            ),
            "suggested_metric": f"tray.{_slug(name) if name else i}",
            "level_oid": f"{INPUT_LEVEL_COL}{i}",
            "max_oid": f"{INPUT_MAX_COL}{i}",
        })
    return out


def decode_supplies(trees: dict) -> list:
    """Turn the raw supplies and colorant tables into something readable.

    Done here rather than left to the reader: the standard part of the MIB is
    unambiguous, so decoding it locally shrinks what anyone downstream has to guess.
    """
    supplies_tree = trees.get("printer.supplies", {})
    colorant_tree = trees.get("printer.colorant", {})

    indices = sorted(
        {int(oid[len(SUPPLY_LEVEL_COL) :]) for oid in supplies_tree if oid.startswith(SUPPLY_LEVEL_COL)}
    )

    out = []
    for i in indices:
        colorant_idx = supplies_tree.get(f"{SUPPLY_COLORANT_COL}{i}")
        colour = colorant_tree.get(f"{COLORANT_VALUE_COL}{colorant_idx}") if colorant_idx else None
        type_code = supplies_tree.get(f"{SUPPLY_TYPE_COL}{i}")
        level = supplies_tree.get(f"{SUPPLY_LEVEL_COL}{i}")
        maximum = supplies_tree.get(f"{SUPPLY_MAX_COL}{i}")

        name = _slug(colour) if colour else _slug(supplies_tree.get(f"{SUPPLY_DESC_COL}{i}", ""))
        out.append({
            "index": i,
            "description": supplies_tree.get(f"{SUPPLY_DESC_COL}{i}"),
            "colorant": colour,
            "type": SUPPLY_TYPES.get(type_code, type_code),
            "level": level,
            "max": maximum,
            "percent": (
                round(level / maximum * 100, 1)
                if isinstance(level, int) and isinstance(maximum, int) and maximum > 0 and level >= 0
                else None
            ),
            "suggested_metric": f"supply.{name}",
            "level_oid": f"{SUPPLY_LEVEL_COL}{i}",
            "max_oid": f"{SUPPLY_MAX_COL}{i}",
        })
    return out


def suggest_metric_map(trees: dict, supplies: list, trays: list = ()) -> dict:
    """A starting point, not a verdict. Only percentages that actually computed."""
    suggestion = {}
    for entry in list(supplies) + list(trays):
        if entry["percent"] is not None:
            suggestion[entry["suggested_metric"]] = {
                "oid": entry["level_oid"],
                "max_oid": entry["max_oid"],
            }
    if PRT_PAGES in trees.get("printer.marker", {}):
        suggestion["pages.total"] = {"oid": PRT_PAGES}
    if SYS_UPTIME in trees.get("system", {}):
        suggestion["uptime.seconds"] = {"oid": SYS_UPTIME, "scale": 0.01}
    return suggestion


def dump(host, port, community, timeout, retries) -> dict:
    trees = {}
    for label, root in DUMP_TREES.items():
        try:
            found = snmp_walk(host, port, community, root, timeout, retries)
        except Exception as err:
            trees[label] = {"error": str(err)}
            continue
        if found:
            trees[label] = found

    supplies = decode_supplies(trees)
    trays = decode_trays(trees)
    return {
        "host": host,
        "port": port,
        "sys_descr": trees.get("system", {}).get(SYS_DESCR),
        "supplies": supplies,
        "trays": trays,
        "suggested_metric_map": suggest_metric_map(trees, supplies, trays),
        "raw": trees,
    }


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
    parser.add_argument("--url", help="https://api.example.com")
    parser.add_argument("--agent-id")
    parser.add_argument("--api-key")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--insecure", action="store_true", help="self signed cert")
    parser.add_argument(
        "--dump",
        metavar="IP",
        help="walk one device and print what it exposes as json, then exit. "
        "Needs no server, use it to work out a metric_map for a new model.",
    )
    parser.add_argument("--community", default="public", help="only with --dump")
    parser.add_argument("--port", type=int, default=161, help="only with --dump")
    args = parser.parse_args()

    if args.dump:
        print(json.dumps(
            dump(args.dump, args.port, args.community, args.timeout, args.retries),
            indent=2, ensure_ascii=False,
        ))
        return 0

    missing = [n for n in ("url", "agent_id", "api_key") if not getattr(args, n)]
    if missing:
        parser.error(f"missing required arguments: {', '.join('--' + m.replace('_', '-') for m in missing)}")

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
        metric_map = device.get("metric_map") or {}
        try:
            if metric_map:
                descr, serial, metrics = poll_from_map(
                    device["ip"], device["port"], device["community"],
                    metric_map, args.timeout, args.retries,
                )
            else:
                poller = POLLERS.get(device["device_type"], poll_generic)
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

    # getnext uses a different pdu tag but the same envelope
    walk_req = build_get("public", [SYS_DESCR], request_id=1, pdu_tag=GET_NEXT_REQUEST)
    _, msg, _ = _read_tlv(walk_req, 0)
    pos = 0
    _, _, pos = _read_tlv(msg, pos)
    _, _, pos = _read_tlv(msg, pos)
    assert msg[pos] == GET_NEXT_REQUEST, "walk must send GETNEXT, not GET"

    # supplies and colorant tables must decode into named, percentaged entries
    trees = {
        "printer.supplies": {
            f"{SUPPLY_DESC_COL}1": "HP 59A Black Cartridge",
            f"{SUPPLY_TYPE_COL}1": 3,
            f"{SUPPLY_MAX_COL}1": 3000,
            f"{SUPPLY_LEVEL_COL}1": 750,
            f"{SUPPLY_COLORANT_COL}1": 1,
            # a level of -2 means "no restriction", it must not become a reading
            f"{SUPPLY_DESC_COL}2": "Wartungskit",
            f"{SUPPLY_TYPE_COL}2": 15,
            f"{SUPPLY_MAX_COL}2": -2,
            f"{SUPPLY_LEVEL_COL}2": -2,
        },
        "printer.colorant": {f"{COLORANT_VALUE_COL}1": "black"},
        "printer.marker": {PRT_PAGES: 15234},
        "system": {SYS_UPTIME: 900},
    }
    supplies = decode_supplies(trees)
    assert [s["index"] for s in supplies] == [1, 2], supplies
    assert supplies[0]["colorant"] == "black"
    assert supplies[0]["type"] == "toner"
    assert supplies[0]["percent"] == 25.0, supplies[0]
    # the colorant table wins over the vendor's description string
    assert supplies[0]["suggested_metric"] == "supply.black", supplies[0]
    assert supplies[1]["percent"] is None, "sentinel levels must not produce a percentage"

    # paper trays decode from prtInput with the same sentinel rules
    trees["printer.input"] = {
        f"{INPUT_NAME_COL}1": "Tray 1",
        f"{INPUT_MAX_COL}1": 500,
        f"{INPUT_LEVEL_COL}1": 125,
        f"{INPUT_MEDIA_COL}1": "A4",
        f"{INPUT_NAME_COL}2": "Manual Feed",
        f"{INPUT_MAX_COL}2": -2,
        f"{INPUT_LEVEL_COL}2": -3,
    }
    trays = decode_trays(trees)
    assert [t["name"] for t in trays] == ["Tray 1", "Manual Feed"], trays
    assert trays[0]["percent"] == 25.0, trays[0]
    assert trays[0]["media"] == "A4"
    assert trays[0]["suggested_metric"] == "tray.tray_1", trays[0]
    assert trays[1]["percent"] is None, "a manual feed reports no usable capacity"

    suggestion = suggest_metric_map(trees, supplies, trays)
    assert set(suggestion) == {
        "supply.black", "tray.tray_1", "pages.total", "uptime.seconds"
    }, suggestion
    assert "supply.wartungskit" not in suggestion
    assert "tray.manual_feed" not in suggestion

    # the map poller must apply max_oid as a percentage and scale as a factor
    sample = {
        SYS_DESCR: "HP LaserJet",
        "1.3.6.1.2.1.43.11.1.1.9.1.1": 750,
        "1.3.6.1.2.1.43.11.1.1.8.1.1": 3000,
        SYS_UPTIME: 900,
    }
    original_get = globals()["snmp_get"]
    globals()["snmp_get"] = lambda *a, **k: sample
    try:
        _, _, metrics = poll_from_map("x", 161, "public", suggestion, 1, 0)
    finally:
        globals()["snmp_get"] = original_get
    assert metrics["supply.black"] == 25.0, metrics
    assert metrics["uptime.seconds"] == 9.0, metrics
    assert "pages.total" not in metrics, "an OID the device did not answer must be skipped"

    # the printer profile polls supplies and trays by index, sentinels included
    def fake_printer_get(host, port, community, oids, timeout, retries):
        if PRT_PAGES in oids:
            return {SYS_DESCR: "HP LaserJet", PRT_SERIAL: "SN1", PRT_PAGES: 100}
        if any(o.startswith(PRT_SUPPLY_LEVEL) for o in oids):
            return {
                f"{PRT_SUPPLY_DESC}1": "Black Cartridge",
                f"{PRT_SUPPLY_MAX}1": 3000,
                f"{PRT_SUPPLY_LEVEL}1": 1500,
            }
        return {
            f"{INPUT_NAME_COL}1": "Tray 1",
            f"{INPUT_MAX_COL}1": 500,
            f"{INPUT_LEVEL_COL}1": 250,
            # a manual feed reports no usable capacity and must be skipped
            f"{INPUT_NAME_COL}2": "Manual Feed",
            f"{INPUT_MAX_COL}2": -2,
            f"{INPUT_LEVEL_COL}2": -3,
        }

    globals()["snmp_get"] = fake_printer_get
    try:
        descr, serial, metrics = poll_printer("x", 161, "public", 1, 0)
    finally:
        globals()["snmp_get"] = original_get
    assert descr == "HP LaserJet" and serial == "SN1"
    assert metrics == {
        "pages.total": 100.0,
        "supply.black_cartridge": 50.0,
        "tray.tray_1": 50.0,
    }, metrics

    print("selftest ok")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main())
