import hashlib
import io
import ipaddress
import string
import struct
from collections.abc import Iterator
from typing import Any

import dpkt

from .timeutils import iso_timestamp

DNS_CHARACTERS = (string.ascii_letters + string.digits + "-_").encode("ascii")


def _dns_question(data: bytes) -> str | None:
    if len(data) < 13 or not struct.unpack("!H", data[4:6])[0]:
        return None
    position = 12
    labels: list[str] = []
    for _ in range(128):
        if position >= len(data):
            return None
        length = data[position]
        position += 1
        if length == 0:
            name = ".".join(labels)
            return name if name and len(name) <= 253 else None
        if length > 63 or position + length > len(data):
            return None
        label = data[position : position + length]
        if not all(char in DNS_CHARACTERS for char in label):
            return None
        labels.append(label.decode("ascii"))
        position += length
    return None


def _tls_name(data: bytes) -> str | None:
    if len(data) < 44 or data[0] != 22 or data[5] != 1:
        return None
    end = min(len(data), 5 + int.from_bytes(data[3:5], "big"), 16389)
    position = 43
    if position >= end:
        return None
    position += 1 + data[position]
    if position + 2 > end:
        return None
    position += 2 + int.from_bytes(data[position : position + 2], "big")
    if position >= end:
        return None
    position += 1 + data[position]
    if position + 2 > end:
        return None
    extension_end = min(end, position + 2 + int.from_bytes(data[position : position + 2], "big"))
    position += 2
    for _ in range(64):
        if position + 4 > extension_end:
            return None
        kind = int.from_bytes(data[position : position + 2], "big")
        size = int.from_bytes(data[position + 2 : position + 4], "big")
        start = position + 4
        if start + size > extension_end:
            return None
        if kind == 0 and size >= 5 and data[start + 2] == 0:
            name_size = int.from_bytes(data[start + 3 : start + 5], "big")
            value = data[start + 5 : start + 5 + name_size]
            if not 1 <= name_size <= 253 or len(value) != name_size or start + 5 + name_size > start + size:
                return None
            try:
                return value.decode("ascii").encode("idna").decode("ascii")
            except UnicodeError:
                return None
        position = start + size
    return None


def packet_records(content: bytes, source: str, maximum: int) -> Iterator[dict[str, Any]]:
    source_hash = hashlib.sha256(content).hexdigest()
    stream = io.BytesIO(content)
    try:
        reader = dpkt.pcapng.Reader(stream) if content[:4] == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(stream)
        link = reader.datalink()
        if link not in {dpkt.pcap.DLT_EN10MB, dpkt.pcap.DLT_RAW, 101}:
            raise ValueError("packet link type is not supported; original capture remains preserved")
        for ordinal, (timestamp, frame) in enumerate(reader, 1):
            if ordinal > maximum:
                raise ValueError("packet count exceeds the configured row limit")
            if len(frame) > 1048576:
                raise ValueError("captured frame exceeds 1 MiB")
            try:
                network = (
                    dpkt.ethernet.Ethernet(frame).data
                    if link == dpkt.pcap.DLT_EN10MB
                    else dpkt.ip6.IP6(frame)
                    if frame and frame[0] >> 4 == 6
                    else dpkt.ip.IP(frame)
                )
                if not isinstance(network, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                source_ip, destination_ip = str(ipaddress.ip_address(network.src)), str(ipaddress.ip_address(network.dst))
                transport = network.data
                protocol = (
                    "tcp"
                    if isinstance(transport, dpkt.tcp.TCP)
                    else "udp"
                    if isinstance(transport, dpkt.udp.UDP)
                    else "icmp"
                    if isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6))
                    else "other"
                )
                source_port = getattr(transport, "sport", None)
                destination_port = getattr(transport, "dport", None)
                payload = transport.data if isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)) and isinstance(transport.data, bytes) else b""
                observed = iso_timestamp(float(timestamp))
                metadata: dict[str, Any] = {
                    "frame_number": ordinal,
                    "frame_bytes": len(frame),
                    "protocol": protocol,
                    "source_port": source_port,
                    "destination_port": destination_port,
                    "analysis_scope": "metadata_only_no_reassembly_no_decryption",
                }
                if isinstance(transport, dpkt.udp.UDP) and 53 in {source_port, destination_port}:
                    metadata["dns_question"] = _dns_question(payload[:8192])
                    metadata["dns_scope"] = "first_uncompressed_question_only"
                if isinstance(transport, dpkt.tcp.TCP):
                    metadata["tls_sni"] = _tls_name(payload[:16389])
                    metadata["tls_scope"] = "visible_single_frame_client_hello_only"
                    first = payload[:4096].split(b"\r\n", 1)[0].split(b" ")
                    if len(first) == 3 and first[0] in {b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH"} and first[2].startswith(b"HTTP/"):
                        metadata["http_method"] = first[0].decode("ascii")
                        metadata["http_path"] = first[1].split(b"?", 1)[0].decode("utf-8", errors="replace")[:1024]
                yield {
                    "source": source,
                    "source_type": "packet_capture",
                    "title": f"{protocol.upper()} {source_ip} → {destination_ip}",
                    "event_type": "network_flow",
                    "category": "network",
                    "severity": "low",
                    "event_time": observed,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "raw_payload": metadata,
                    "normalized_fields": metadata,
                    "parser_version": "socify-packet-metadata-1",
                    "idempotency_key": f"import:{source_hash}:{ordinal}",
                    "provenance": {
                        "sha256": source_hash,
                        "frame_number": ordinal,
                        "parser": "dpkt-1.9.8",
                        "limitations": "single-frame metadata; no traffic acquisition, TCP reassembly or TLS decryption",
                    },
                }
            except (dpkt.UnpackError, ValueError, OverflowError, IndexError) as exc:
                yield {"__parse_error": f"frame {ordinal}: {type(exc).__name__}", "provenance": {"sha256": source_hash, "frame_number": ordinal}}
    except (dpkt.UnpackError, ValueError, struct.error, EOFError) as exc:
        raise ValueError(f"invalid or unsupported packet capture: {type(exc).__name__}") from exc
