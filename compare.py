import time
import numpy as np
import matplotlib.pyplot as plt
from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# RSA performance
def measure_rsa_performance(key_size):
    start_time = time.time()
    key = RSA.generate(key_size)
    key_gen_time = time.time() - start_time

    cipher = PKCS1_OAEP.new(key)
    data = get_random_bytes(16)
    start_time = time.time()
    ciphertext = cipher.encrypt(data)
    encryption_time = time.time() - start_time

    start_time = time.time()
    decrypted_data = cipher.decrypt(ciphertext)
    decryption_time = time.time() - start_time

    return key_gen_time, encryption_time, decryption_time

#  ECC performance
def measure_ecc_performance():
    start_time = time.time()
    private_key = ec.generate_private_key(ec.SECP256R1())
    key_gen_time = time.time() - start_time

    public_key = private_key.public_key()
    data = get_random_bytes(16)
    start_time = time.time()
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    sign_time = time.time() - start_time

    start_time = time.time()
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    verify_time = time.time() - start_time

    return key_gen_time, sign_time, verify_time

#  DSA performance
def measure_dsa_performance(key_size):
    start_time = time.time()
    key = DSA.generate(key_size)
    key_gen_time = time.time() - start_time

    data = get_random_bytes(16)
    hash_obj = SHA256.new(data)
    signer = DSS.new(key, 'fips-186-3')
    start_time = time.time()
    signature = signer.sign(hash_obj)
    sign_time = time.time() - start_time

    verifier = DSS.new(key.publickey(), 'fips-186-3')
    start_time = time.time()
    verifier.verify(hash_obj, signature)
    verify_time = time.time() - start_time

    return key_gen_time, sign_time, verify_time

#  Diffie-Hellman performance
def measure_dh_performance(key_size):
    parameters = dh.generate_parameters(generator=2, key_size=key_size)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    start_time = time.time()
    peer_private_key = parameters.generate_private_key()
    peer_public_key = peer_private_key.public_key()
    shared_key = private_key.exchange(peer_public_key)
    key_gen_time = time.time() - start_time

    return key_gen_time

# Measure RSA performance
rsa_key_sizes = [1024, 2048, 3072]
rsa_times = [measure_rsa_performance(size) for size in rsa_key_sizes]
key_gen_times_rsa, encryption_times_rsa, decryption_times_rsa = zip(*rsa_times)

# Measure ECC performance
ecc_times = [measure_ecc_performance() for _ in range(len(rsa_key_sizes))]
key_gen_times_ecc, sign_times_ecc, verify_times_ecc = zip(*ecc_times)

# Measure DSA performance
dsa_key_sizes = [1024, 2048]
dsa_times = [measure_dsa_performance(size) for size in dsa_key_sizes]
key_gen_times_dsa, sign_times_dsa, verify_times_dsa = zip(*dsa_times)

# Measure Diffie-Hellman performance
dh_key_sizes = [2048, 3072]
dh_times = [measure_dh_performance(size) for size in dh_key_sizes]
key_gen_times_dh = dh_times  # Only key generation time

# Plotting all performance metrics
plt.figure(figsize=(18, 12))

# RSA Performance
plt.subplot(2, 2, 1)
plt.plot(rsa_key_sizes, key_gen_times_rsa, label='Key Generation', marker='o')
plt.plot(rsa_key_sizes, encryption_times_rsa, label='Encryption', marker='o')
plt.plot(rsa_key_sizes, decryption_times_rsa, label='Decryption', marker='o')
plt.xlabel('RSA Key Size (bits)')
plt.ylabel('Time (seconds)')
plt.title('RSA Performance')
plt.legend()

# ECC Performance
plt.subplot(2, 2, 2)
plt.plot([256] * len(ecc_times), key_gen_times_ecc, label='Key Generation', marker='o')
plt.plot([256] * len(ecc_times), sign_times_ecc, label='Signing', marker='o')
plt.plot([256] * len(ecc_times), verify_times_ecc, label='Verification', marker='o')
plt.xlabel('Key Size (bits)')
plt.ylabel('Time (seconds)')
plt.title('ECC Performance')
plt.legend()

# DSA Performance
plt.subplot(2, 2, 3)
plt.plot(dsa_key_sizes, key_gen_times_dsa, label='Key Generation', marker='o')
plt.plot(dsa_key_sizes, sign_times_dsa, label='Signing', marker='o')
plt.plot(dsa_key_sizes, verify_times_dsa, label='Verification', marker='o')
plt.xlabel('DSA Key Size (bits)')
plt.ylabel('Time (seconds)')
plt.title('DSA Performance')
plt.legend()

# Diffie-Hellman Performance
plt.subplot(2, 2, 4)
plt.plot(dh_key_sizes, key_gen_times_dh, label='Key Generation', marker='o')
plt.xlabel('DH Key Size (bits)')
plt.ylabel('Time (seconds)')
plt.title('Diffie-Hellman Performance')
plt.legend()

plt.tight_layout()
plt.show()
