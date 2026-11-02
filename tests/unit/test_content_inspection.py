import base64
import json
from urllib.parse import quote

import pytest

from socify.content_inspection import (
    DEPTH_LIMIT,
    FINDING_LIMIT,
    TEXT_LIMIT,
    card_checksum,
    decode_layer,
    iban_checksum,
    inspect_content,
    inspect_event_fields,
    mask_text,
    normalized_inspection,
)


def encode(value):
    return base64.b64encode(value.encode()).decode()


@pytest.mark.parametrize("value", ["4111111111111111", "4539 1488 0343 6467", "378282246310005"])
def test_valid_payment_card_checksum(value):
    assert card_checksum(value)
    assert normalized_inspection({"message": "card=" + value})["sensitive_data_count"] == 1


@pytest.mark.parametrize("value", ["0000000000000000", "4111111111111112", "12345", "４１１１１１１１１１１１１１１１", "4a11111111111111"])
def test_invalid_payment_card_checksum(value):
    assert not card_checksum(value)


@pytest.mark.parametrize("value", ["GB82 WEST 1234 5698 7654 32", "SA0380000000608010167519", "DE89370400440532013000"])
def test_iban_checksum(value):
    assert iban_checksum(value)
    assert normalized_inspection({"message": value})["sensitive_data_count"] >= 1
    assert not iban_checksum(value[:-1] + str((int(value[-1]) + 1) % 10))


@pytest.mark.parametrize("value", ["XX0000", "GB00WEST12345698765432", "GB82WEST1234569876543!", ""])
def test_invalid_iban(value):
    assert not iban_checksum(value)


@pytest.mark.parametrize(
    "encoder,kind", [(lambda x: x.hex(), "hex"), (base64.b32encode, "base32"), (base64.b64encode, "base64"), (base64.urlsafe_b64encode, "base64")]
)
def test_decoders_preserve_text(encoder, kind):
    value = encoder(b"Investigate /etc/passwd")
    if isinstance(value, bytes):
        value = value.decode()
    assert decode_layer(value) == (kind, "Investigate /etc/passwd")
    assert inspect_content({"message": value})["decoded_threat_count"] == 1


def test_recursive_and_powershell_decoding():
    text = "Invoke-Expression ('review only')"
    result = inspect_content({"message": quote(encode(encode(text)), safe="")})
    assert result["decoded"][0]["layers"][-1]["text"] == text
    command = "Write-Output 'مراجعة'; Invoke-Expression ('text')"
    payload = base64.b64encode(command.encode("utf-16-le")).decode()
    result = inspect_content({"command_line": "powershell.exe -EncodedCommand " + payload})
    assert result["decoded"][0]["layers"][0]["encoding"] == "base64_utf16le"
    assert result["decoded"][0]["layers"][0]["text"] == command
    assert result["decoded_threat_count"] == 1


def test_secret_redaction_covers_nested_encoding_and_private_key_body():
    credential = "Ab3!Cd4@Ef5#Gh6"
    text = "api_key=" + credential
    result = inspect_content({"message": encode(encode(text))})
    assert result["findings"][0]["kind"] == "credential_assignment"
    rendered = json.dumps(result)
    assert credential not in rendered and encode(text) not in rendered
    assert result["decoded"][0]["layers"][0]["text"] == "[REDACTED]"
    material = "-----BEGIN PRIVATE KEY-----\n" + encode("private material for inspection") + "\n-----END PRIVATE KEY-----"  # pragma: allowlist secret
    result = inspect_content({"message": encode(material)})
    assert result["decoded"][0]["layers"][0]["text"] == "[REDACTED]"
    assert mask_text("abcdefgh", [(1, 5, "a"), (3, 7, "b")]) == "a[REDACTED]h"


def test_credentials_types_and_nonsecret_values():
    value = "AZ5bc98!kl34@df90"
    result = normalized_inspection({"api_key": value, "message": "Bearer " + encode(value * 2)})
    assert result["exposed_secret_count"] == 2
    assert not normalized_inspection({"api_key": "${ENV_VALUE}", "password": "********", "text": "routine application event"})
    assert not inspect_content({"message": "/etc/passwd"})["decoded_threat_count"]


def test_limits_and_invalid_bytes_do_not_crash_or_leak_unchecked_output():
    result = inspect_content({"message": "x" * (TEXT_LIMIT + 100)})
    assert result["truncated"]
    text = " ".join("api_key=" + "Ab3!Cd4@Ef5#Gh6" for _ in range(100))
    result = inspect_content({"message": encode(text)})
    assert len(result["findings"]) == FINDING_LIMIT and result["truncated"]
    assert result["decoded"][0]["layers"][0]["text"] == "[REDACTED]"
    text = "review investigation content"
    for _ in range(10):
        text = encode(text)
    result = inspect_content({"message": text})
    assert len(result["decoded"][0]["layers"]) == DEPTH_LIMIT
    assert result["decoded"][0]["depth_limit_reached"]
    for value in ("%FF", "_" * 30, "a" * 25, "0000000000000000", "", "AA=="):
        assert isinstance(inspect_content({"value": value}), dict)


def test_engine_owned_fields_cannot_be_supplied_by_logs_and_raw_is_preserved():
    raw = json.dumps({"hostname": "server-1", "exposed_secret_count": 99, "content_inspection": {"engine": "forged"}})
    fields = {"sensitive_data_count": 99, "command_line": "powershell -enc " + base64.b64encode("/etc/passwd".encode("utf-16-le")).decode()}
    inspected = inspect_event_fields(raw, fields)
    assert inspected["exposed_secret_count"] == 0
    assert inspected["sensitive_data_count"] == 0
    assert inspected["decoded_threat_count"] == 1
    assert inspected["command_line"] == fields["command_line"]
    assert json.loads(raw)["content_inspection"]["engine"] == "forged"
