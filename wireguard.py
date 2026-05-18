class WireGuardSession:
    def __init__(self, static_private, static_public, server_static_public):
        # store identities, precompute Hash(Label-Mac1 || S_R_pub)
        ...

    def create_initiation(self) -> bytes:
        # generates ephemeral keypair, computes chain_key and hash,
        # builds the type-1 message including mac1, stores intermediate
        # state on self for consume_response to use
        ...

    def consume_response(self, msg: bytes) -> None:
        # parses type-2 message, continues the chain_key/hash from
        # create_initiation, derives T_send / T_recv, zeroes ephemerals,
        # sets self.ready = True
        ...

    def encrypt_transport(self, plaintext: bytes) -> bytes:
        # builds type-4 message using T_send and N_send, increments N_send
        ...

    def decrypt_transport(self, msg: bytes) -> bytes:
        # parses type-4, decrypts with T_recv at the message's counter,
        # returns plaintext
        ...