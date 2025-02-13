# KeePass KDBX HMAC Brute Force PoC

## Overview
This script attempts to brute-force a **KeePass KDBX HMAC signature** by iterating over a wordlist of possible passwords.

I've placed in this folder the database i used to create this proof of concept(`testePoc.kdbx`), but it can be used with any kdbx 4 file as long as the KDF parameters are changed and the size of the header is adjusted. It performs the following steps:

1. **Reads the first 253 bytes** of the KeePass database file (`testePoc.kdbx`).
2. **Applies double SHA-256 hashing** to each password candidate.
3. **Uses Argon2 key derivation** to derive the decryption key.
4. **Computes HMAC** using the derived key and predefined parameters.
5. **Compares the computed HMAC** against the expected value to check if the password is correct.
6. **Stops if a valid password is found**; otherwise, continues testing the next password.

## How It Works
### **Key Components**
- `double_sha256(password)`: Computes SHA-256 twice on the input password.
- `readFile(filename)`: Reads the first 253 bytes of the given KDBX file.
- `brute_force_argon2(wordlist)`: Iterates through a wordlist, derives keys, computes HMACs, and checks for matches.

### **HMAC Key Generation Steps**
1. Compute **Double SHA-256** of the password.
2. Derive the **Argon2 Key** using predefined parameters (low iterations for PoC).
3. Compute the **HMAC Base Key** by hashing (`masterSeed + derivedKey + 0x01`).
4. Compute the **HMAC Key** using a block index (`0xFFFFFFFFFFFFFFFF`).
5. Compute the **HMAC Signature** of the KDBX header.
6. Compare the computed HMAC with the expected signature.

## Installation & Usage
### **Requirements**
Ensure you have Python 3 installed along with the required dependencies:

```sh
pip install argon2_cffi
```

### **Running the Script**
1. Place your KeePass database (`testePoc.kdbx`) in the script directory.
2. Modify the wordlist in `wordlist = [...]` with potential passwords.
3. Run the script:

```sh
python pocArgon2d.py
```

### **Example Output**
```sh
Trying password: 111
HMAC signature verification failed continuing to next entry
Trying password: 122
HMAC signature verification failed continuing to next entry
Trying password: 123
Password found in the wordlist: 123
```

## Notes & Limitations
- This script is a **Proof of Concept (PoC)** with minimal security parameters for fast testing.
- In a real-world attack scenario, **increase Argon2 iterations and memory usage** for security.
- The script assumes **static KDBX parameters** (e.g., salt, master seed). These must be extracted dynamically for real usage.

