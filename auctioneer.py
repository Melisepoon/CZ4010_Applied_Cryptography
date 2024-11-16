# these 3 functions for testing only
import random
import string

from rsa import RSA
from hash import keccak_hash, sha256_hash, md5_hash
import socket
import threading
from bidder import Bidder
# Define global min and max prime values for RSA key generation
# can change key size accordingly
# anything above 16 bits will take super long...
MIN_PRIME = 2**15
MAX_PRIME = 2**16 - 1
BITS = 256
#replace host n port
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 53140  # Port to listen on (non-privileged ports are > 1023)

class Auctioneer:
    def __init__(self):
        self.rsa = RSA()
        # self.hash = Hashing() #for hashing
        self.public_key = None
        self.private_key = None
        self.host = HOST
        self.port = PORT
        self.bids = []  # List to store received bids
        self.auction_active = True
        
    def generate_keys(self):
        """Generate the auctioneer's public and private RSA keys using the global min and max prime values."""
        self.public_key, self.private_key = self.rsa.generate_keys(min_value=MIN_PRIME, max_value=MAX_PRIME)
        # self.public_key, self.private_key = self.rsa.generate_keysv2(BITS)
        # can remove printing of private key
        print("Auctioneer's Public Key {e,n}:", self.public_key)
        # print("Auctioneer's Private Key {d,n}:", self.private_key)

        # Write the public key to a file
        self.write_public_key_to_file()
    
    def write_public_key_to_file(self):
        """Write the public key to a file, overwriting if it already exists."""
        with open("public_key.txt", "w") as file:
            file.write(str(self.public_key))
        print("Public key written to public_key.txt")
    
    # forport
    def start_server(self):
        """Start the auctioneer's server to listen for incoming bids."""
        print("Starting auctioneer server...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen()

        print(f"Auctioneer is listening on {self.host}:{self.port}...")
        while self.auction_active:
            client_socket, client_address = server_socket.accept()
            print(f"Received connection from {client_address}")
            thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            thread.start()

    #for port   
    def handle_client(self, client_socket):
        """Handle incoming bids from clients."""
        try:
            encrypted_bid = client_socket.recv(1024)
            if encrypted_bid:
                decrypted_bid = self.decrypt_bid(eval(encrypted_bid.decode()))
                print(f"Decrypted bid received: {decrypted_bid}")
                hashed_name, price = decrypted_bid.split(":")
                price = int(price)

                # Store the bid (hashed_name and price) for later comparison
                self.bids.append((hashed_name, price))
                print(f"Received Bid: Hashed Name: {hashed_name}, Price: {price}")
            client_socket.close()
        except Exception as e:
            print(f"Error handling client: {e}")

    def end_auction(self):
        """End the auction and determine the winner."""
        self.auction_active = False
        print("Auction ended. Determining winner...")
        if not self.bids:
            print("No bids received.")
            return
        # Sort bids and determine winner
        self.bids.sort(key=lambda x: x[1], reverse=True)
        winner_hash, winning_price = self.bids[0]
        second_highest_hash, second_highest_price = self.bids[1] if len(self.bids) > 1 else (None, None)

        print(f"Winner's Hash: {winner_hash}, Winning Price: {second_highest_price}")


        with open("auction_results.txt", "w") as file:
            file.write(f"Winner's Hash: {winner_hash}, Winning Price: {second_highest_price}\n")
            if second_highest_price is None:
                file.write(f"Winner's Hash: {winner_hash},Winning Price: {winning_price}\n")
        print("Winner's hash written to winner_hash.txt")

    # def encrypt_bid(self, bid):
    #     """Encrypt a bid using the auctioneer's public key."""
    #     if not self.public_key:
    #         raise ValueError("Public key not generated. Call generate_keys first.")
    #     return self.rsa.encrypt(bid)

    def decrypt_bid(self, encrypted_bid):
        """Decrypt a bid using the auctioneer's private key."""
        if not self.private_key:
            raise ValueError("Private key not generated. Call generate_keys first.")
        return self.rsa.decrypt(encrypted_bid)
    
    # Helper function to test the server
    def test_auction(self, encrypted_bid):
        """Helper function to simulate sending a bid to the auctioneer."""
        # encrypted_bid = self.encrypt_bid(bid_data)
        # print(f"Encrypted Bid: {encrypted_bid}")

        decrypted_bid = self.decrypt_bid(encrypted_bid)
        print(f"Decrypted Bid: {decrypted_bid}")
        
        # Simulate receiving and decrypting a bid (in the auctioneer's server)
        hashed_name, price = decrypted_bid.split(":")
        price = int(price)

        self.bids.append((hashed_name, price))
        
# Main Execution
if __name__ == "__main__":
    n = 2  # Number of bidders (change this to test with more bidders)

    # Initialize the auctioneer and generate keys
    auctioneer = Auctioneer()
    auctioneer.generate_keys()

    # Create bidders and store them in a list
    bidders = [Bidder(auctioneer.public_key) for _ in range(n)]

    # Simulate bidders generating and encrypting bids
    for i, bidder in enumerate(bidders, start=1):
        bid = bidder.generate_random_bid()  # Generate random bid
        encrypted_bid = bidder.encrypt_bid(bid)  # Encrypt the bid
        print(f"User {i} Bid: {bid}")
        # print(f"User {i} Encrypted Bid: {encrypted_bid}")

        # Test the auction with the encrypted bid
        auctioneer.test_auction(encrypted_bid)

    # End the auction and determine the winner
    auctioneer.end_auction()
