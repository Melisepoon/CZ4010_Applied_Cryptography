import random
import string
from hash import keccak_hash, sha256_hash, md5_hash
from rsa import RSA


class Bidder:
    def __init__(self, public_key):
        self.rsa = RSA()
        self.rsa.e, self.rsa.n = public_key

    def generate_random_bid(self):
        """Generate a random bid with hashed name and price."""
        name = ''.join(random.choices(string.ascii_lowercase, k=5))  # Random 5-letter name
        price = random.randint(10, 1000)  # Random price between 10 and 1000
        hashed_name = keccak_hash(name)  # Hash the name
        bid_data = f"{hashed_name}:{price}"
        return bid_data

    def encrypt_bid(self, bid_data):
        """Encrypt the bid using the auctioneer's public key."""
        encrypted_bid = self.rsa.encrypt(bid_data)
        return encrypted_bid
    
    
