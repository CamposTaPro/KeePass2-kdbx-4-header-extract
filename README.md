# KeePass2 kdbx 4 header extract

## Introduction
This script enables the extraction of the outer headers of a KDBX 4 file. 

The outer headers contain metadata about the database, such as the Key Derivation Function (KDF) and other parameters. However, it does **not** decrypt any inner headers or the encrypted content of the database. 

I developed this script as part of my thesis work investigating the security of KeePassXC, which uses this database format by default. 

For additional context and resources, I referenced the following:
- [KeePass Documentation on KDBX 4 Format](https://keepass.info/help/kb/kdbx_4.html)
- [KeepassDecrypt GitHub Repository](https://github.com/scubajorgen/KeepassDecrypt)

## Features
- Extracts outer headers from KDBX 4 files.
- Displays metadata such as the KDF used and other parameters.
- **Note:** This script only extracts unencrypted outer headers; it does not decrypt any part of the encrypted database.

## Motivation
The script is primarily intended for research purposes, aiding in the analysis of the KDBX format. While it currently focuses on outer header extraction, I may explore further capabilities, such as decrypting inner headers, depending on the scope of my thesis.

## Compatibility
This script has been tested with a few databases.

If you encounter any bugs or issues, please [create an issue](#) in this repository, and I will address it as soon as possible.

## Usage
To use the script, follow these steps:
1. Clone the repository.
2. Run the script on your target KDBX 4 file.
3. If you want to write the output in a file you can always redirect the stdout to the desired file

To use this script, any version of Python 3 should suffice. Simply run the script with the file path as an argument. Here is an example:


```shell
python extract_header.py example.kdbx
```

You can also use the help option to see more details:


```shell
python extract_header.py -h                                                                                                                                          
usage: extract_header.py [-h] filename

Read and parse a KDBX file.

positional arguments:
  filename    Path to the KDBX file to be read.

options:
  -h, --help  show this help message and exit
```

Here is an example of the output from this script when analyzing a KDBX database using Argon2d:


```shell
Value of the first signature (uint32, little-endian): 0x9aa2d903
Value of the second signature (uint32, little-endian): 0xb54bfb67
Format version: 4.0
ID 2 Encryption algorithm - AES-256 (size 16 bytes): 31c1f2e6bf714350be5805216afc5aff (hexdecimal)
ID 3 Compression algorithm (size 4 bytes): 1 (using GZIP)
ID 4 Master salt/seed (size 32 bytes): 470541af0812fa595728152e0fae91e785ab8887bc954b5cd64f276587ba8fad (hexadecimal)
ID 7 Encryption IV/nonce (size 16 bytes): 9077dbc963b4656f139ed29065c99f5f (hexadecimal)
ID 11 KDF parameters (size 139 bytes) - Variant dictionary:
Format version: 0x100
KDF algorithm:
 entry name -> $UUID
 size -> 16
 value -> ef636ddf8c29444b91f7a9a403e30a0c
This means the used KDF ALgorithm used was Argon2
Argon2 Iterations:
 entry name -> I
 size -> 8
 value -> 58
Argon2 Memory:
 entry name -> M
 size -> 8
 value -> 16.0 MiB
Argon2 Parallelism:
 entry name -> P
 size -> 4
 value -> 2 threads
Argon2 Salt:
 entry name -> S
 size -> 32
 value -> 48148e2966c90461318ccb5907ae10602ffabbfd6b5744963ae8ab3bd9c68c2d (hexadecimal)
Argon2 Version:
 entry name -> V
 size -> 4
 value -> 0x13 (hexadecimal)
Reached the end of the Varient dictionary, continuing to read the headers of the file...
ID 0 End of headers reached! (size 4 bytes): 0xa0d0a0d
```


## Contributions
Contributions are welcome! If you have suggestions or improvements, feel free to submit a pull request or open an issue.

