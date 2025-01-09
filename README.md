# Cryptography Project – Vickrey Auction Implementation with RSA and Hashing
_This project was completed as part of the requirements for Module CZ4010: Applied Cryptography, in partial fulfillment of the Computer Science degree program at Nanyang Technological University (NTU)._ <br>
****

### Description of Project:
- Implemented a Vickrey Auction Program using RSA-Public Key Cryptosystem and Multiple Hashing Algorithms (SHA256, MD5, Keccak).
- Simulated multiple Cryptographic attacks on deeloped program to demonstrate common security vulnerabilities in the algorithms used.

****
Attacks Simulated:
1) 2nd Preimage Resistant (Brute Force Attack)
2) Birthday Attack
3) Factoring Attack
4) Continued Fractions
5) Pollard Rho
****
### To clone Repository
run 
```pip install -r requirements.txt``` <br>
### To run program as a normal auction
1) run 
```python auctioneer.py``` to initiate start of aution. <br>
2) run
```python bidder.py``` to add a bidder. <br>
3) run
```python winner.py``` to verify winner when auction ends. <br>

### To test Cryptographic Attacks
1) run
```python hash_attacks.py``` to run Brute Force and Birthday Attack. <br>
2) run
```python factoring_attack.py``` to run Factoring Attack. <br>
3) run
```python continued_fractions.py``` to run Continued Fractions Attack. <br>
4) run
```python pollard_rho_attack.py``` to run Pollard Rho Attack. <br>
****

**Developed by: Poon Yan Xin Melise & Xing Kun**
