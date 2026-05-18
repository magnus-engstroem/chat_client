import unittest
from wireguard import DH, Mac, Hmac, Kdf1, Kdf2, Kdf3, Timestamp, Aead_decrypt


KEY         = b':\xb6\x90\xbd\n:\x18Z88"\xd8a\x08\x9f\xa7\x9c\xc7\xcb\x01\x99-\xfd\x9cGX\xdc\x9dO\x0c\xb3@'







PRIVATE_KEY = b'\xb0)e\xdbZ\x01\x8f\x0f\xf5\x91\x88<\xab\x15\x14\x95\xb3\x92\xbd&3\xfe\x18<\x8f\xd6P\xeb\xd0k\xdb\x7f'
PUBLIC_KEY  = b'\x14\xde\xd1\x90m?\x0eaBa\xbb\xf8\\\x08\xdd\xfd\x08\xa7?^\x9f\xcb\x16Y\xdf\xa1\\B\x9d\t7k'

class TestDH(unittest.TestCase):
  def test_dh(self):
        expected = b'p\x06\xe4\x7f\xce\x87\x88\xe2\xb9\xd1\xb0\xb7\xf3\x0e}\xb1\xc6{g\xae\x17\x8b\x17{\x91}\x05&\x0cl\xbd:'
        self.assertEqual(DH(PRIVATE_KEY, PUBLIC_KEY), expected)


TEXT1       = b'I am a message without a MAC, but only for now.'

class TestMac(unittest.TestCase):
    def test_mac(self):
        expected = b'*\xbd\x8ak4%\xe4\xb0\xe7\x96\xe5z\x14q\xdd!'
        self.assertEqual(Mac(KEY, TEXT1), expected)

TEXT2       = b'I am a message without an HMAC, but only for now.'
class TestHmac(unittest.TestCase):
    def test_hmac(self):
        expected = b'\x1ew,:\x03\xdd\x0b\x1e\x96\n\x00J\x8c\xe1QzQ\xff\xb8\x02\xcb\xa29\xa8{\x00\x07(\xa6\xc0\x07\xde'
        self.assertEqual(Hmac(KEY, TEXT2), expected)



TEXT3       = b'Choose your LLM adventure folks.'
class TestKdf(unittest.TestCase):
    def test_kdf1(self):
        expected = (b'0fO\x0e\x0f\xb2\xf4\xaa\xcc\x14\x9c\x84\x8a\xb0D\xd3i\xa6\xac\xbf\xae\xdc^\xd0-D"64X\x93W')
        self.assertEqual(Kdf1(KEY, TEXT3), expected)

    def test_kdf2(self):
        expected = (b'0fO\x0e\x0f\xb2\xf4\xaa\xcc\x14\x9c\x84\x8a\xb0D\xd3i\xa6\xac\xbf\xae\xdc^\xd0-D"64X\x93W', b'\xaa\x9b\x0fh\xf9\x99z\\%\\\x0f\x8c9L\x7f~<\x1f\xa9G\x9d \x1dw\xba\xc3\x96\x9e\xbb\x8f\x12&')
        self.assertEqual(Kdf2(KEY, TEXT3), expected)

    def test_kdf3(self):
        expected = (b'0fO\x0e\x0f\xb2\xf4\xaa\xcc\x14\x9c\x84\x8a\xb0D\xd3i\xa6\xac\xbf\xae\xdc^\xd0-D"64X\x93W', b'\xaa\x9b\x0fh\xf9\x99z\\%\\\x0f\x8c9L\x7f~<\x1f\xa9G\x9d \x1dw\xba\xc3\x96\x9e\xbb\x8f\x12&', b'\\\xfb\xc9\xf8!\x88\x03\xa1u\xa8!gUk\xfd\x8b4E|\n5\x89\xb1\xb6\xc1\x1a\x8f\xae?\\\xac)')
        self.assertEqual(Kdf3(KEY, TEXT3), expected)

TIMESTAMP   = 1744366282.5143921

class TestTimestamp(unittest.TestCase):
    def test_timestamp(self):
        expected = b'@\x00\x00\x00g\xf8\xea\xd4\x00\x07\xd9X'
        self.assertEqual(Timestamp(TIMESTAMP), expected)


ENCRYPTED_DATA = b'\xfbv\x84\xea\xd0S\n\xc1\x16\x9et\xd5\xa4/\xeee\x9a\xa9MR\xe3\xd5p3\x85\r\xce\x15r\xcd'
AUTHTEXT = b'\x8e2\x89\xe2\x14\xfd\x16\x19o\x06\xc9\xb2\xd9\xe8F\xfd\xdaf\xdc\xa4\xf9\xe9\x98\xbc\xd8x\xb9\x90\x1e\n\xac\x98'
COUNTER = b'\x00'*12
KEY = b':\xb6\x90\xbd\n:\x18Z88"\xd8a\x08\x9f\xa7\x9c\xc7\xcb\x01\x99-\xfd\x9cGX\xdc\x9dO\x0c\xb3@'

class TestAead(unittest.TestCase):
    def test_aead(self):
        expected = b"attack at dawn"
        self.assertEqual(Aead_decrypt(KEY, COUNTER, ENCRYPTED_DATA, AUTHTEXT), self.expected)

if __name__ == "__main__":
    unittest.main()
