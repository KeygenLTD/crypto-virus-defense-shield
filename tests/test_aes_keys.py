from src.cvds.aes_keys import expand_aes_key, scan_aes_key_schedules


def test_aes_128_known_expansion_edges():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    expanded = expand_aes_key(key)
    assert len(expanded) == 176
    assert expanded[16:32].hex() == "d6aa74fdd2af72fadaa678f1d6ab76fe"
    assert expanded[-16:].hex() == "13111d7fe3944a17f307a78b4d2b30c5"


def test_scanner_accepts_schedule_and_rejects_raw_key():
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d7781")
    expanded = expand_aes_key(key)
    blob = b"A" * 64 + expanded + b"B" * 64
    candidates = scan_aes_key_schedules(blob, base_offset=0x1000, alignment=4)
    assert [(item.key_hex, item.memory_offset) for item in candidates] == [
        (key.hex(), 0x1040)
    ]
    assert scan_aes_key_schedules(b"A" * 64 + key + b"B" * 128, alignment=4) == []
