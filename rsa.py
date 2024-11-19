import random
import math
import secrets
from sympy import isprime
from math import isqrt # added
from gmpy2 import powmod


# e has to start from 3
# if e = 1, encryption is meaningless, anything to power 1 = itself
# e has to be odd, because phi_n = (p-1)*(q-1) --> is always even, bcos p/q are odd, -1 is even
# and if e were even together with phi_n, gcd(e,phi_n) != 1
# can try using e = 65537 as default
# format for public key {e,n}
# format for private key {d,n}

# ToDo:
# Add in function to check size of decryption key > 1/3 * N^1/4
# Attacks


class RSA:
    def __init__(self):
        # # Generate two distinct primes p and q
        # self.p = self.generate_prime(min_prime, max_prime)
        # self.q = self.generate_prime(min_prime, max_prime)
        # while self.p == self.q:  # Ensure p and q are distinct
        #     self.q = self.generate_prime(min_prime, max_prime)
        
        # # Calculate n and phi_n
        # self.n = self.p * self.q
        # self.phi_n = (self.p - 1) * (self.q - 1)
        
        # # Generate the public key (e) and private key (d)
        # self.e = self.generate_e()
        # self.d = self.mod_inverse(self.e, self.phi_n)
        self.p = None
        self.q = None
        self.n = None
        self.phi_n = None
        self.e = None
        self.d = None

    def is_prime(self, number):
        """Check if a number is prime."""
        if number < 2:
            return False
        for i in range(2, number // 2 + 1):
            if number % i == 0:
                return False
        return True

    def generate_prime(self, min_value, max_value):
        """Generate a random prime number within the specified range."""
        prime = random.randint(min_value, max_value)
        while not self.is_prime(prime):
            prime = random.randint(min_value, max_value)
        return prime
    
    def generate_secure_prime(self,bits):
        while True:
            candidate = secrets.randbits(bits)
            if isprime(candidate):
                return candidate

    # to obtain decryption key
    # this is iteration approach, may have high overheads
    # look into Extended Euclid Algorithm for lower overhead in generating
    def mod_inverse(self, e, phi_n):
        # """Calculate the modular inverse of e mod phi_n.
        # takes O(phi_n) time
        # """
        # for d in range(3, phi_n):
        #     if (d * e) % phi_n == 1:
        #         return d
        # raise ValueError("mod_inverse does not exist")
        """
        Calculate the modular inverse of e mod phi_n using the Extended Euclidean Algorithm.
        takes O(log(phi_n)) time
        """
        original_phi = phi_n
        x0, x1 = 0, 1  # Coefficients for the Extended Euclidean Algorithm
        while e > 1:
            # Compute quotient
            q = e // phi_n
            # Update e and phi_n (similar to the Euclidean algorithm)
            e, phi_n = phi_n, e % phi_n
            # Update coefficients
            x0, x1 = x1 - q * x0, x0
        # If e becomes 1, x1 is the modular inverse, but ensure it's positive
        if x1 < 0:
            x1 += original_phi
        return x1

    def generate_e(self):
        """Generate a public exponent e with constraints for Wiener's attack."""
        while True:  # Keep retrying until a valid e is generated
            lower_bound = max(int(self.phi_n / (3 * (self.n ** (1 / 4)))), 3)
            upper_bound = self.phi_n - 1

            # Check if the range is valid
            if lower_bound < upper_bound:
                e = random.randint(lower_bound, upper_bound)
                while math.gcd(e, self.phi_n) != 1:
                    e = random.randint(lower_bound, upper_bound)
                print(f"Generated e: {e}")
                print(f"Bit size of e: {e.bit_length()}")
                return e
            else:
                print(f"Invalid range for e: lower_bound={lower_bound}, upper_bound={upper_bound}. Regenerating primes...")
                return None  # Signal to regenerate keys

    def calculate_e(self, wiener_threshold):
        """Calculate a public exponent e such that d is vulnerable to Wiener's attack."""
        n_quarter_root = isqrt(isqrt(self.n))  # Approximation of n^(1/4)

        print(f"Calculated Wiener's threshold: {wiener_threshold}, n^(1/4): {n_quarter_root}")

        # Iterate over potential values of d
        for d in range(3, wiener_threshold):
            if math.gcd(d, self.phi_n) == 1:  # Ensure d is coprime with φ(n)
                try:
                    # Calculate e as the modular inverse of d mod φ(n)
                    e = pow(d, -1, self.phi_n)
                    # Validate e: Ensure it's large enough and gcd(e, φ(n)) = 1
                    if e > self.n ** (3 / 4) and math.gcd(e, self.phi_n) == 1:
                        print(f"Mathematically calculated e: {e}, d: {d}")
                        return e, d
                except ValueError:
                    continue  # Skip if modular inverse fails
        raise ValueError("Failed to calculate a suitable e.")

    
    def generate_keys(self, min_value=1000, max_value=5000):
        while True:
            self.p = self.generate_prime(min_value, max_value)
            self.q = self.generate_prime(min_value, max_value)
            while self.p == self.q:
                self.q = self.generate_prime(min_value, max_value)

            self.n = self.p * self.q
            self.phi_n = (self.p - 1) * (self.q - 1)

            self.e = self.calculate_e()
            self.d = self.mod_inverse(self.e, self.phi_n)

            # Calculate Wiener's attack threshold
            wiener_threshold = int((1/3) * (self.n ** 0.25))

            # Compare d with numeric Wiener's threshold
            if self.d < wiener_threshold:
                # Print debug information
                print(f"Bit size of e: {self.e.bit_length()}")
                print(f"Bit size of d: {self.d.bit_length()}, d: {self.d}")
                print(f"Bit size of n: {self.n.bit_length()}")
                print(f"Wiener's threshold (numeric): {wiener_threshold}")
                break
            else:
                print(f"d ({self.d}) is too big. Regenerating keys for Wiener's attack...")

        return (self.e, self.n), (self.d, self.n)

    #faster version to generate keys
    def generate_keysv2(self, bits):
        """Generate RSA keys adjusted to ensure d is vulnerable to Wiener's attack."""
        while True:
            self.p = self.generate_secure_prime(bits // 2)
            self.q = self.generate_secure_prime(bits // 2)
            while self.p == self.q:
                self.q = self.generate_secure_prime(bits // 2)

            self.n = self.p * self.q
            self.phi_n = (self.p - 1) * (self.q - 1)

            # Calculate Wiener's threshold
            wiener_threshold = max(int((1 / 3) * isqrt(isqrt(self.n))), 3)

            try:
                self.e, self.d = self.calculate_e(wiener_threshold)
            except ValueError:
                print("Failed to find suitable e. Regenerating keys...")
                continue

            if self.d < wiener_threshold:
                print(f"Generated keys:")
                print(f"  Bit size of p: {self.p.bit_length()}")
                print(f"  Bit size of q: {self.q.bit_length()}")
                print(f"  Bit size of n: {self.n.bit_length()}")
                print(f"  Bit size of e: {self.e.bit_length()}")
                print(f"  Bit size of d: {self.d.bit_length()} ({self.d})")
                print(f"  Wiener's threshold (numeric): {wiener_threshold}")
                return (self.e, self.n), (self.d, self.n)
            else:
                print(f"d ({self.d}) is too big. Regenerating keys for Wiener's attack...")

    def encrypt(self, plaintext):
        """
        Encrypt a plaintext message using the public key (e, n).
        Args:
            plaintext (str): The message to be encrypted.
        Returns:
            list: The encrypted message as a list of integers.
        """
        block_size = self.n.bit_length() // 8 - 1  # Determine block size
        plaintext_bytes = plaintext.encode()
        cipher_text = []

        for i in range(0, len(plaintext_bytes), block_size):
            block = int.from_bytes(plaintext_bytes[i:i+block_size], byteorder='big')
            encrypted_block = pow(block, self.e, self.n)
            cipher_text.append(encrypted_block)

        return cipher_text



    def decrypted_numbers_to_bytes(self, decrypted_numbers):
        """
        Convert decrypted numbers into bytes safely, and decode them into a string.
        Args:
            decrypted_numbers: List of decrypted integers.
        Returns:
            str: Decoded plaintext message.
        """
        try:
            decoded_message = []
            for num in decrypted_numbers:
                # Convert each number into bytes
                num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
                # Decode the bytes to string, replacing invalid characters
                decoded_message.append(num_bytes.decode('utf-8', errors='replace'))
            # Join decoded parts into a single message
            return ''.join(decoded_message)
        except Exception as e:
            print(f"Error converting decrypted numbers to bytes: {e}")
            raise


    def decrypt(self, cipher_text):
        """
        Decrypt a cipher text message using the private key (d, n).
        Args:
            cipher_text: The encrypted message as a list of integers or a comma-separated string of integers.
        Returns:
            list: Decrypted integers.
        """
        try:
            # Convert cipher text from string to list of integers if needed
            if isinstance(cipher_text, str):
                cipher_text = list(map(int, cipher_text.split(',')))

            # Decrypt each integer in the cipher text
            decrypted_numbers = [pow(ch, self.d, self.n) for ch in cipher_text]
            #print(f"Decrypted numbers: {decrypted_numbers}")
            return decrypted_numbers
        except Exception as e:
            print(f"Decryption error: {e}")
            raise



    def get_public_key(self):
        """Return the public key."""
        return self.e, self.n

    #secret
    def get_private_key(self):
        """Return the private key (for testing/debugging purposes)."""
        return self.d
    
    #secret
    def get_pq_phi(self):
        """Return p,q, phi_n (for testing/debugging purposes)."""
        return self.p, self.q, self.phi_n

# Example Usage
rsa = RSA()

# Generate a 512-bit prime number
prime_number = rsa.generate_secure_prime(256)
#print(prime_number)

# rsa.generate_keys(min_value=1000, max_value=5000)

# print("{p,q, phi_n}: ", rsa.get_pq_phi()) #secret
# print("Public Key {e,n}: ", rsa.get_public_key())
# print("Private Key, d (for testing):", rsa.get_private_key()) #secret

# message = "Hello World"
# print("\nOriginal Message:", message)

# # Encrypt
# cipher_text = rsa.encrypt(message)
# print("Encrypted Message:", cipher_text)

# # Decrypt
# decrypted_message = rsa.decrypt(cipher_text)
# print("Decrypted Message:", decrypted_message)
