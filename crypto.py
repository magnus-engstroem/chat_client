import asyncio
import nacl.bindings
import nacl.public
import hashlib
import binascii
import hmac
import time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import struct



def DH(private_key, public_key):
    return nacl.bindings.crypto_scalarmult(n=private_key, p=public_key)

def DH_Generate():
    private_key = nacl.public.PrivateKey.generate()
    return (private_key, private_key.public_key)

def Hash(text)-> bytes:
    """
    Blake2s hash function

    Parameters
    ---
    text: binary string
        data to be hashed

        
    Returns
    ---
    hash: 32 bytes
        hashed text    
    """
    hash = hashlib.blake2s(text).digest()
    return hash

def Mac(key, input) -> bytes:
    """
    Message Authentication Code using keyed Blake2s

    Parameters
    ---
    key: 32 bytes
        key to encrypt input with
    input: binary string
        text to be used for authentication

    Returns
    ---
    mac: 32 bytes
        blake2s digest
    """
    blake = hashlib.blake2s(key=key, data=input, digest_size=16)
    return blake.digest()

def Hmac(key: bytes, data: bytes) -> bytes:
    """
    blake2s in a hmac configuration
    
    """
    return hmac.new(key, data, hashlib.blake2s).digest()

def Kdf_n(key, input, n):
    """
    n_th kdf function
    
    """
    t0 = Hmac(key, input)
    t1 = Hmac(t0, b'\x01')
    kdf = [t1] * n
    for i in range(1, n):
        kdf[i] = Hmac(t0, kdf[i-1] + bytes([i + 1]))
    return tuple(kdf)

Kdf1 = lambda key, input: Kdf_n(key, input, 1)
Kdf2 = lambda key, input: Kdf_n(key, input, 2)
Kdf3 = lambda key, input: Kdf_n(key, input, 3)



def Timestamp(t):
    """
    Convert a time.time() float to a TAI64N timestamp (12 bytes).
    
    :param t: float (seconds since Unix epoch, as from time.time())
    :return: 12-byte TAI64N timestamp
    """


    #TAI_OFFSET = 37
    TAI_OFFSET_1970 = 10  # offset at Unix epoch
    TAI64_BIAS = 1 << 62

    seconds = int(t)
    nanoseconds = int((t - seconds) * 1_000_000_000)
    tai_seconds = seconds + TAI_OFFSET_1970 # - TAI_OFFSET
    tai64_seconds = tai_seconds + TAI64_BIAS
    stamp = tai64_seconds.to_bytes(8, 'big') + nanoseconds.to_bytes(4, 'big')

    return stamp

Nonce = b'\x00'*4 + b'\x00\x72\x65\x74\x6e\x75\x6f\x63'




def Aead_encrypt(key: bytes, counter: int, plain_text: bytes, auth_text: bytes) -> bytes:
    """
    ChaCha20Poly1305 AEAD as specified in RFC7539.
    Nonce: 32 bits of zeros || 64-bit little-endian counter (12 bytes total).
    Returns ciphertext + 16-byte Poly1305 tag.
    """
    nonce = b'\x00' * 4 + counter.to_bytes(8, 'little')
    return ChaCha20Poly1305(key).encrypt(nonce, plain_text, auth_text)


def Aead_decrypt(key: bytes, counter: int, cipher_text: bytes, auth_text: bytes) -> bytes:
    """
    ChaCha20Poly1305 AEAD decryption. Raises InvalidTag if authentication fails.
    """
    nonce = b'\x00' * 4 + counter.to_bytes(8, 'little')
    return ChaCha20Poly1305(key).decrypt(nonce, cipher_text, auth_text)




