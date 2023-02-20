#[
  Reference: https://github.com/byt3bl33d3r/OffensiveNim

  - Starts named pipe and listens until a client connects
  - Then reads the data the client wrote
]#

import winim
import std/os
import strutils

# Create new named pipe 
var pipe: HANDLE = CreateNamedPipe(r"\\.\pipe\flikk", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 0, 0, 0, NULL)

# If this happens, pipe creation failed
if not bool(pipe) or pipe == INVALID_HANDLE_VALUE:
  echo "[-] Error starting server pipe"
  quit(1)

# If pipe creation successful, do connect to the pipe and wait for client connections
try:
  echo "[*] Waiting for connections"
  var result: BOOL = ConnectNamedPipe(pipe, NULL)
  echo "[+] Client connected to pipe"

  # Not sure if this is necessary, but sleep 2 seconds for the client to finish writing data
  sleep(2000)

  echo "[+] Reading client's message"


  var
    buffer: array[100, char]
    bytesRead: DWORD

  # Use ReadFile to read data from the pipe into the char array 'buffer'
  var readResult: BOOL = ReadFile(pipe, addr buffer, (DWORD)buffer.len, addr bytesRead, NULL)
  echo "[*] bytes read: ", bytesRead

  # Join the array into a single string and print it.  This may error if not a regular array of has non-printable characters
  let bufferString = join(buffer)
  echo "[+] Result: ", bufferString
finally:
    CloseHandle(pipe)
