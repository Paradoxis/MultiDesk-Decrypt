import base64
from pathlib import Path

import pytest

from multidesk_decrypt import decrypt, decrypt_xml, MultiDeskError


@pytest.fixture
def legacy_ciphertext() -> str:
    return "hOwcVeWa/3A="


@pytest.fixture
def legacy_key() -> bytes:
    return bytes.fromhex("08D771FBCCE52924A3A4444673F1425F")


@pytest.fixture
def legacy_file() -> str:
    return Path(__file__).parent / "fixtures" / "MultiDesk.xml"


@pytest.fixture
def modern_ciphertext() -> str:
    return "$1$5279777a4b21565414dc890e0a02ce81$e772486bdcdf018d70a8b7ae8a14f7d4a62c243e22663db46cd0a4abbc3bde40"


@pytest.fixture
def modern_key() -> bytes:
    return bytes.fromhex("9180009A8E770A0BF0168785EF26812E")


@pytest.fixture
def modern_file() -> str:
    return Path(__file__).parent / "fixtures" / "MultiDesk.multidesk"


def test_decrypt_legacy_string(legacy_key: bytes, legacy_ciphertext: str):
    """Ensure legacy passwords can be decrypted"""
    plaintext = decrypt(password=legacy_ciphertext, key=legacy_key)
    assert plaintext == "passward"


def test_decrypt_modern_string(modern_key: bytes, modern_ciphertext: str):
    """Ensure modern passwords can be decrypted"""
    plaintext = decrypt(password=modern_ciphertext, key=modern_key)
    assert plaintext == "root-password"

def test_decrypt_legacy_file(legacy_file: str, legacy_key: bytes):
    """Ensure legacy password files can be decrypted"""
    credentials = decrypt_xml(
        xml=Path(legacy_file).read_text(),
        key=legacy_key,
        strict=True,
    )

    assert credentials[0].username == "username"
    assert credentials[0].password == "passward"

    assert credentials[1].username == "test"
    assert credentials[1].password == "etst"
    

def test_decrypt_modern_file(modern_file: str, modern_key: bytes):
    """Ensure modern password files can be decrypted"""
    credentials = decrypt_xml(
        xml=Path(modern_file).read_text(),
        key=modern_key,
        strict=True,
    )

    root_creds = credentials[0]
    group_creds = credentials[1]
    sub_group_creds = credentials[3]
    sub_sub_group_creds = credentials[4]

    dont_inherit_sub_group_creds = credentials[2]
    dont_inherit_sub_sub_group_creds = credentials[5]
    deeply_nested_creds = credentials[6]

    root_creds.password == "root-password"
    group_creds.password == "group-password"
    sub_group_creds.password == "sub-group-password"
    sub_sub_group_creds.password == "subsub-group-password"
    deeply_nested_creds.password == "subsub-group-password"

    dont_inherit_sub_group_creds.password == "non-inherited-sub-password"
    dont_inherit_sub_sub_group_creds.password == "non-inherited-sub-sub-password"
