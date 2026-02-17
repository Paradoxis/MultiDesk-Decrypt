# MultiDesk Decryption Tool

Small tool to decrypt MultiDesk passwords. For more information, please refer to the [blog post](https://blog.paradoxis.nl/decrypting-multidesk-passwords-58af8ad274b3).

## Installation

To install the tool, simply use `pip` on a system with Python 3.10+:

```text
pip install multidesk
```

## Usage

The decryption tool offers the following options:

```
$ multidesk -h
usage: multidesk [-h] -k KEY [-j] [-v] [-q] data

MultiDesk password decryption tool.

positional arguments:
  data
       Path to an XML file, or password ciphertext.

options:
  -h, --help
       Show this help message and exit

  -k, --key KEY
       Hex key obtained from `HKEY_CURRENT_USER\Software\MultiDesk\key`

  -j, --json
       Display output as JSON

  -v, --verbose
       Verbose logging

  -q, --quiet, --stfu
       Disable all logging (mutually exclusive with -v/--verbose)
```

To decrypt XML files or passwords, you'll need to obtain the decryption key from the registry:

```text
reg query HKEY_CURRENT_USER\Software\MultiDesk /f key

// or

reg query HKEY_USERS\<sid>\Software\MultiDesk /f key
```

Once obtained, pass the XML file, or password you'd like to decrypt:

```text
// decrypting files directly
multidesk ./MultiDesk.xml --key 9180009A8E770A0BF0168785EF26812E

// decrypting modern (v5+) passwords
multidesk '$1$e76ceda56552e9d401ab108c1c13784d$b0db49838212040fecc999ba445b08d1602c1c4e655c13f9b3f4160d0f3349c8' --key 9180009A8E770A0BF0168785EF26812E

// decrypting legacy (3.16) passwords
multidesk 'hOwcVeWa/3A=' --key 08D771FBCCE52924A3A4444673F1425F
```
