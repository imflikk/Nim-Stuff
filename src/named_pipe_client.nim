#[
    Reference: https://github.com/byt3bl33d3r/OffensiveNim

    - Tries to connect to named pipe
    - Collects current computer name using WinApi
    - Sends message to named pipe with computer name (if successful)
]#

import winim
import nativesockets

var pipe: HANDLE = CreateFile(r"\\.\pipe\flikk", GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)

if bool(pipe):
    echo "[*] Connected to name pipe server"

    var
        compName: string

    # This works using the nativesockets library.
    # Tried using winim for GetComputerName, but couldn't figure out the right way to pass the pointer arguments
    try:
        compName = getHostName()
    except:
        compName = "ERROR"


    try:
        var
            data: cstring = "Hello " & compName
            bytesWritten: DWORD

        var result: BOOL = WriteFile(pipe, data, (DWORD) data.len, addr bytesWritten, NULL)

    finally:
        CloseHandle(pipe)