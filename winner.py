from hash import keccak_hash, sha256_hash, md5_hash

class WinnerChecker:
    def __init__(self, hash_method):
        """
        Initialize the WinnerChecker with the specified hash method.
        Supported methods: 'keccak', 'sha256', 'md5'.
        """
        if hash_method not in {'keccak', 'sha256', 'md5'}:
            raise ValueError("Unsupported hash method. Choose 'keccak', 'sha256', or 'md5'.")
        self.hash_method = hash_method

    def hash_plaintext(self, plaintext):
        """Hash the given plaintext using the selected hash method."""
        if self.hash_method == 'keccak':
            return keccak_hash(plaintext)
        elif self.hash_method == 'sha256':
            return sha256_hash(plaintext)
        elif self.hash_method == 'md5':
            return md5_hash(plaintext)
    
    def bitwise_compare(self, hash1, hash2):
        """
        Perform a bitwise comparison between two hashes.
        Compares only up to the length of the shorter hash.
        """
        # Ensure comparison is only up to the length of the shorter hash
        return all(c1 == c2 for c1, c2 in zip(hash1[:len(hash2)], hash2))

    def check_winner(self, plaintext, result_file):
        """
        Check if the given plaintext's hash matches the winner's hash in the result file.
        Returns True and a congratulatory message if they match; otherwise, False and a rejection message.
        """
        try:
            with open("auction_results.txt", "r") as file:
                # Parse the winner's hash from the results file
                winner_data = file.readline().strip()
                winner_hash = winner_data.split("Winner's Hash:")[1].split(",")[0].strip()
                print(winner_hash)
        except (FileNotFoundError, IndexError) as e:
            print(f"Error reading results file: {e}")
            return False, "Could not verify the winner."

        # Hash the plaintext input
        user_hash = self.hash_plaintext(plaintext)

        # Perform a bitwise comparison
        if self.bitwise_compare(user_hash, winner_hash):
            return True, "Congrats! You are the winner!"
        else:
            return False, "Sorry, you are not the winner."


# Main Execution
if __name__ == "__main__":
    print("Winner Verification")
    print("===================")

    # Select hashing method
    print("Select hash method:")
    print("1. Keccak")
    print("2. SHA-256")
    print("3. MD5")
    choice = input("Enter your choice (1/2/3): ").strip()

    hash_method = {
        "1": "keccak",
        "2": "sha256",
        "3": "md5"
    }.get(choice, "keccak")  # Default to Keccak if input is invalid

    # Initialize the checker
    checker = WinnerChecker(hash_method)

    # Get plaintext input from the user
    plaintext = input("Enter your plaintext (name): ").strip()

    # Check if the user is the winner
    result_file = "auction_results.txt"  # File containing the winner's hash
    is_winner, message = checker.check_winner(plaintext, result_file)

    # Display the result
    print(message)


