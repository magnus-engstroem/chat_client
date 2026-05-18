import asyncio
import nacl.bindings
import nacl.public
import cryptography
import hashlib
import binascii


def DH(private_key, public_key):
    return nacl.bindings.crypto_scalarmult(n=private_key, p=public_key)

def DH_Generate():
    private_key = nacl.public.PrivateKey.generate()
    return (private_key, private_key.public_key)

def Hash(text):
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

def Mac(key, input):
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


def Hmac(key, input):
    hash = Hash(input)
    return Mac(key, hash)

key = b':\xb6\x90\xbd\n:\x18Z88"\xd8a\x08\x9f\xa7\x9c\xc7\xcb\x01\x99-\xfd\x9cGX\xdc\x9dO\x0c\xb3@'
text1 = b'I am a message without a MAC, but only for now.'
text2 = b'I am a message without an HMAC, but only for now.'
print(Mac(key, text1))

print(Hmac(key, text2))