import argon2.low_level
from argon2 import Type
import hmac
import hashlib

def double_sha256(password: bytes) -> bytes:
    """Compute SHA256(SHA256(password)) as per KDBX spec."""
    return hashlib.sha256(hashlib.sha256(password).digest()).digest()

def read_header(filename: str) -> bytes:
    """Read KDBX4 header until End-of-Header marker."""
    with open(filename, "rb") as f:
        data = b""
        while True:
            chunk = f.read(1024)
            if not chunk:
                break
            data += chunk
            if b"\x0d\x0a\x0d\x0a" in data:  # End-of-Header marker
                eoh = data.index(b"\x0d\x0a\x0d\x0a") + 4
                return data[:eoh]
        raise ValueError("Invalid KDBX header")

def brute_force_argon2(
    wordlist: list[bytes],
    iterations: int,
    memory: int,
    parallelism: int,
    salt: bytes,
    master_seed: bytes,
    stored_hmac: bytes,
    header: bytes
) -> None:
    """Brute-force a KDBX4 database using extracted parameters."""
    block_index = b"\xff" * 8  # 0xFFFFFFFFFFFFFFFF

    for password in wordlist:
        try:
            print(f"Trying password: {password.decode('utf-8', errors='replace')}")

            # 1. Composite key
            composite_key = double_sha256(password)

            # 2. Argon2d derived key
            derived_key = argon2.low_level.hash_secret_raw(
                secret=composite_key,
                salt=salt,
                time_cost=iterations,
                memory_cost=memory,
                parallelism=parallelism,
                hash_len=32,
                type=Type.D
            )

            # 3. HMAC key derivation
            x = hashlib.sha512(master_seed + derived_key + b"\x01").digest()
            hmac_key = hashlib.sha512(block_index + x).digest()
            computed_hmac = hmac.new(hmac_key, header, hashlib.sha256).digest()

            # 4. Validate
            if hmac.compare_digest(computed_hmac, stored_hmac):
                print(f"\nSUCCESS! Password: {password.decode()}")
                return

        except Exception as e:
            print(f"Error processing '{password.decode('utf-8', errors='replace')}': {e}")

    print("\nPassword not found.")

# ------------------------------------------
# Example usage (replace with extracted values)
if __name__ == "__main__":
    # Parameters (extract these from your KDBX4 file)
    ITERATIONS = 2          # WARNING: Use 100,000+ in real-world
    MEMORY = 16384          # WARNING: Use 1,048,576 (1 GiB) in real-world
    PARALLELISM = 1
    SALT = bytes.fromhex("5c7121609bd58f0333b33b3fddb29d22bc57343cf868fde9ca0034d16c308156")
    MASTER_SEED = bytes.fromhex("32da47790ac65e8a321aca4d8268319f946d8dd763a2b807f2408e2ba6e72049")
    STORED_HMAC = bytes.fromhex("5503588b694086b194c2ef08f285c59849989e0b85e6f36bfb63fd200aec84b5")
    HEADER = read_header("testePoc.kdbx")

    # Wordlist
    WORDLIST = [
    b"111", b"112", b"113",b"121", b"122",b"131", b"132", b"133",b"211", b"212", b"213",b"221", b"222", b"223",b"231", b"232", b"233",b"311", b"312", b"313",b"321", b"123", b"322", b"323",b"331", b"332", b"333"]

    brute_force_argon2(WORDLIST, ITERATIONS, MEMORY, PARALLELISM, SALT, MASTER_SEED, STORED_HMAC, HEADER)