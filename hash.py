
from Crypto.Hash import keccak
import hashlib



#     #bits: int refers to output length
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

# Example Usage
if __name__ == "__main__":
    data = "Bob"
    print("Original Data:", data)
    
    print("Keccak-256 Hash:", keccak_hash(data))
    print("SHA-256 Hash:", sha256_hash(data))
    print("MD5 Hash:", md5_hash(data))
