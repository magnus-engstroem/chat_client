import asyncio


class WireGuardTransport:
    def __init__(self, session: WireGuardSession, ...):
        self.session = session
        # ...

    async def handshake(self):
        init_msg = self.session.create_initiation()      # sync
        await self._send(init_msg)                        # async — UDP I/O
        response = await self._recv()                     # async — waits
        self.session.consume_response(response)           # sync

    async def send(self, plaintext: bytes):
        ciphertext = self.session.encrypt_transport(plaintext)  # sync
        await self._send(ciphertext)                            # async

    async def recv(self) -> bytes:
        ciphertext = await self._recv()                          # async
        return self.session.decrypt_transport(ciphertext)        # sync