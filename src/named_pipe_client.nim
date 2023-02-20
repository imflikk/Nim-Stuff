#[
  Reference: https://github.com/byt3bl33d3r/OffensiveNim

  - Tries to connect to named pipe
  - Collects current computer name using WinApi
  - Sends message to named pipe with computer name (if successful)
]#

import winim
import nativesockets

# Open a handle to an existing named pipe
var pipe: HANDLE = CreateFile(r"\\.\pipe\flikk", GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)

# If successful at getting a handle, do stuff
if bool(pipe):
  echo "[*] Connected to name pipe server"

  var
    compName: string

  # This works using the nativesockets library to get the computer name
  # Tried using winim for GetComputerName, but couldn't figure out the right way to pass the pointer arguments
  try:
    compName = getHostName()
  except:
    compName = "ERROR"

  # Create final message data to send and use WriteFile to write the data to the pipe
  try:
    var
      data: cstring = "Hello " & compName
      bytesWritten: DWORD

    var result: BOOL = WriteFile(pipe, data, (DWORD) data.len, addr bytesWritten, NULL)
    echo "[+] Wrote data to named pipe"

  # Close handle to the pipe
  finally:
      CloseHandle(pipe)