
from Crypto.Hash import keccak
import hashlib

#bits: int refers to output length
def keccak_hash(data: str, bits: int = 256) -> str:
        """Compute the Keccak hash for the given data."""
        keccak_hash = keccak.new(digest_bits=bits, data=data.encode('utf-8'))
        return keccak_hash.hexdigest()

    # @staticmethod
def sha256_hash(data: str) -> str:
        """Compute the SHA-256 hash for the given data."""
        sha256_hash = hashlib.sha256(data.encode('utf-8'))
        return sha256_hash.hexdigest()

    # @staticmethod
def md5_hash(data: str) -> str:
        """Compute the MD5 hash for the given data."""
        md5_hash = hashlib.md5(data.encode('utf-8'))
        return md5_hash.hexdigest()

#for testing of attacks
def truncate_hash(hash_value: str, bits: int) -> str:
    """Truncate the hash to the specified bit size."""
    hex_length = bits // 4  # Convert bits to hex digits
    return hash_value[:hex_length]

# Example Usage
# Example Usage
# if __name__ == "__main__":
#     data = "Bob"
#     print("Original Data:", data)

#     # Generate full hash values
#     keccak_full_hash = keccak_hash(data)
#     sha256_full_hash = sha256_hash(data)
#     md5_full_hash = md5_hash(data)

#     print("Keccak-256 Hash:", keccak_full_hash)
#     print("SHA-256 Hash:", sha256_full_hash)
#     print("MD5 Hash:", md5_full_hash)

#     # Example of truncating hashes
#     bit_size = 16  # Example: Truncate to 16 bits
#     print(f"Truncated Keccak Hash ({bit_size} bits):", truncate_hash(keccak_full_hash, bit_size))
#     print(f"Truncated SHA-256 Hash ({bit_size} bits):", truncate_hash(sha256_full_hash, bit_size))
#     print(f"Truncated MD5 Hash ({bit_size} bits):", truncate_hash(md5_full_hash, bit_size))