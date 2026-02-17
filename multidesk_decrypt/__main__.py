import json
import os.path
import logging
import argparse
from pathlib import Path

from multidesk_decrypt import logger, decrypt, decrypt_xml
from multidesk_decrypt.utils import CustomHelpFormatter


def main():
    parser = argparse.ArgumentParser(
        formatter_class=CustomHelpFormatter,
        description="MultiDesk password decryption tool.",
    )
    parser.add_argument("data", help="Path to an XML file, or password ciphertext.")
    parser.add_argument(
        "-k",
        "--key",
        help="Hex key obtained from `HKEY_CURRENT_USER\\Software\\MultiDesk\\key`",
        required=True,
    )
    parser.add_argument(
        "-j",
        "--json",
        help="Display output as JSON",
        action="store_true",
    )
    parser.add_argument(
        "-v", 
        "--verbose",
        help="Verbose logging",
        action="store_true",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        "--stfu",
        help="Disable all logging (mutually exclusive with -v/--verbose)",
        action="store_true",
    )
    args = parser.parse_args()

    if args.quiet and args.verbose:
        logger.error("The --quiet and --verbose flags are mutually exclusive. Use one, not both.")
        exit(1)

    if args.quiet:
        logger.setLevel(logging.ERROR)
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        key = bytes.fromhex(args.key)
    except ValueError as e:
        logger.error("Failed to decode key: %s", e)
        exit(1)

    if os.path.isfile(args.data):
        logger.info("Attempting to decrypt file: %s", args.data)
        result = decrypt_xml(xml=Path(args.data).read_text(), key=key)
    else:
        logger.info("Attempting to decrypt blob..")
        result = decrypt(args.data, key)

    if args.json:
        if isinstance(result, list):
            print(json.dumps([c.dict() for c in result], indent=2))
        else:
            print(json.dumps(result))
    else:
        
        if isinstance(result, list):
            for cred in result:
                print(
                    f"label: {cred.label}\n"
                    f"server: {cred.server}\n"
                    f"domain: {cred.domain}\n"
                    f"username: {cred.username}\n"
                    f"password: {cred.password}\n"
                    f"\n"
                )
        else:
            print(result)


if __name__ == "__main__":
    main()
