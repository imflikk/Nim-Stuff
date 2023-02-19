#[
    Reference: https://github.com/byt3bl33d3r/OffensiveNim

    - Starts named pipe and listens until a client connects
    - Then reads the data the client wrote
]#

import winim
import std/os

var pipe: HANDLE = CreateNamedPipe(r"\\.\pipe\flikk", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 1024, 1024, 0, NULL)

if not bool(pipe) or pipe == INVALID_HANDLE_VALUE:
    echo "[-] Error starting server pipe"
    quit(1)

try:
    echo "[*] Waiting for connections"
    var result: BOOL = ConnectNamedPipe(pipe, NULL)
    echo "[+] Client connected to pipe"
    sleep(2000)

    echo "[+] Reading client's message"

    var
        buffer: array[100, char]
        bytesRead: DWORD

    var readResult: BOOL = ReadFile(pipe, addr buffer, (DWORD)buffer.len, addr bytesRead, NULL)
    echo "[*] bytes read: ", bytesRead
    echo repr(buffer)
finally:
    CloseHandle(pipe)
