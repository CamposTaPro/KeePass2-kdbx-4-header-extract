# KeePass2-kdbx-4-header-extract

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
2. Install any required dependencies (if applicable).
3. Run the script on your target KDBX 4 file.

## Contributions
Contributions are welcome! If you have suggestions or improvements, feel free to submit a pull request or open an issue.

