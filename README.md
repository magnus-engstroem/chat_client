# chat_client
Interactive chat client implementing simplified wireguard.


Structure:

```
chat_client/
├── crypto.py        # DH, AEAD, Hash, Mac, Hmac, Kdf1/2/3, Timestamp
├── wireguard.py     # Handshake state machine + transport encrypt/decrypt
├── transport.py     # UDP socket; CleartextTransport and WireGuardTransport
├── chat_protocol.py # MessagePack (un)packing, message type constants
├── session.py       # Session state, pending requests, dispatcher
├── ui.py            # CLI rendering, command parsing, input loop
├── utils.py         # Server host/port, keys, constants
└── main.py          # Runs the client as a whole

```
