import base64
import hashlib
from pathlib import Path
from collections import namedtuple
from dataclasses import dataclass
from typing import Iterator

from defusedxml.ElementTree import fromstring 

from multidesk_decrypt import logger, MultiDeskError


def rc4(data: bytes, key: bytes) -> bytearray:
    """RC4 decryption"""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    res = bytearray()
    for char in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        res.append(char ^ s[(s[i] + s[j]) % 256])

    return res


def decrypt(password: str, key: bytes) -> str:
    """Decrypt a MultiDesk password"""

    if password.startswith("$1$"):
        logger.debug(
            "Password '%s' appears to be using MultiDesk 5+ (modern) format",
            password,
        )

        parts = password.split("$")
        if len(parts) < 4:
            raise MultiDeskError(
                "Malformed MultiDesk string (did the algorithm change?)"
            )

        salt = bytes.fromhex(parts[2])
        ciphertext = bytes.fromhex(parts[3])

        derived_key = bytearray(k ^ s for k, s in zip(key, salt))
        decrypted = rc4(ciphertext, derived_key)

        try:
            decoded = decrypted.decode("utf-16le").split("\0")[0]
        except UnicodeDecodeError:
            raise MultiDeskError(
                "Failed to decrypt ciphertext: %s",
                password,
            )

        return decoded

    try:
        ciphertext = base64.b64decode(password)
        logger.debug(
            "Password '%s' appears to be using MultiDesk 3.16 (legacy) format",
            password,
        )
    except (TypeError, ValueError):
        raise MultiDeskError(
            "Unknown ciphertext format for string: %s",
            password,
        )

    try:
        decrypted = rc4(ciphertext, key)
        return decrypted.decode("utf-8")
    except UnicodeDecodeError:
        raise MultiDeskError(
            "Failed to decode password: %s (did you pass a valid key?)",
            password,
        )


@dataclass(slots=True)
class Credential:
    label: str
    server: str
    domain: str
    username: str
    password: str | None = None

    def dict(self) -> dict:
        return {
            "label": self.label,
            "server": self.server,
            "domain": self.domain,
            "username": self.username,
            "password": self.password,
        }


def decrypt_xml(
    xml: str,
    key: bytes,
    strict: bool = True,
) -> Iterator[Credential]:
    """Decrypt a MultiDesk XML file"""
    tree = fromstring(xml)
    creds = _flatten(tree, key=key, strict=strict)
    return list(creds)


def _flatten(
    element,
    key: bytes,
    parent_creds: Credential | None = None,
    current_depth: int = 0,
    strict: bool = True,
) -> Iterator[Credential]:
    current_creds: Credential | None = parent_creds
    current_properties = element.find("Properties")
    if current_properties is not None:
        if current_properties.findtext("InheritGeneral", "0") == "1":
            if parent_creds is None:
                raise MultiDeskError(
                    f"Properties tag at depth {current_depth} specifies "
                    f"InheritGeneral, but no parent credentials are present."
                )
        else:
            current_password = None

            try:
                current_password = decrypt(
                    password=current_properties.findtext("Password", ""),
                    key=key,
                )
            except MultiDeskError as e:
                if strict and element.tag != "Servers":
                    raise
                else:
                    logger.warning(str(e))

            current_creds = Credential(
                server="",
                label=current_properties.findtext("Name", ""),
                username=current_properties.findtext("UserName", ""),
                domain=current_properties.findtext("Domain", ""),
                password=current_password,
            )

    for child in element:
        if child.tag in ("Group", "Servers"):
            yield from _flatten(
                element=child,
                key=key,
                parent_creds=current_creds,
                current_depth=current_depth + 1,
                strict=strict,
            )
            continue

        if child.tag != "Server":
            continue

        if child.findtext("InheritGeneral", "0") == "1":
            yield Credential(
                label=child.findtext("Name"),
                server=child.findtext("Server"),
                username=current_creds.username,
                domain=current_creds.domain,
                password=current_creds.password,
            )
            continue

        child_password = None

        try:
            child_password = decrypt(
                password=child.findtext("Password", ""),
                key=key,
            )
        except MultiDeskError as e:
            if strict:
                raise
            else:
                logger.warning(str(e))

        yield Credential(
            label=child.findtext("Name"),
            server=child.findtext("Server"),
            username=child.findtext("UserName", ""),
            domain=child.findtext("Domain", ""),
            password=child_password,
        )
