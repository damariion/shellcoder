Shellcoder is a portable assembler that utilises Keystone and Capstone to
convert source files to a Python buffer with informative comments. It has been
designed to utilise the DLLs that are shipped with it to ensure usability
on all x86 Windows systems, as long as at least Python 3.9.6 is installed.

While `msfvenom` would dump a block of bytecode after its payload generation,
Shellcoder formats its buffer to match the original assembly code, providing
useful details while debugging your payload. Additionally, it features routine
enhancements such as bad-character highlighting ~~and a simple snippets system.~~

Below is an example of its usage, where we make use of the payload that
resolves `kernel32.dll` by walking the Process Environment Block (PEB):

```nasm
; PS C:\Users\Administrator> type payload.asm

getkrnl32:
    int3
    push ebp
    mov ebp, esp
    sub esp, 0x20
    xor edx, edx
    mov dword ptr [ebp-0x04], esi
    mov esi, fs:[edx+0x30]
    mov esi, [esi+0x0C]
    mov esi, [esi+0x1C]
getkrnl32_next:
    mov eax, [esi+0x08]
    mov ecx, [esi+0x20]
    mov esi, [esi]
    cmp dword ptr [ecx+0x18], edx
    jne getkrnl32_next
getkrnl32_exit:
    mov esi, [ebp-0x04]
    mov esp, ebp
    pop ebp
    ret
```

```python
# PS C:\Users\Administrator> python .\shellcoder.py -f payload.asm

bytecode size: 42
mnemonic size: 18

buffer  = b''
buffer += b"\xCC"             #  0 | int3
buffer += b"\x55"             #  1 | push ebp
buffer += b"\x89\xE5"         #  2 | mov ebp, esp
buffer += b"\x83\xEC\x20"     #  4 | sub esp, 0x20
buffer += b"\x31\xD2"         #  7 | xor edx, edx
buffer += b"\x89\x75\xFC"     #  9 | mov dword ptr [ebp - 4], esi
buffer += b"\x64\x8B\x72\x30" #  c | mov esi, dword ptr fs:[edx + 0x30]
buffer += b"\x8B\x76\x0C"     # 10 | mov esi, dword ptr [esi + 0xc]
buffer += b"\x8B\x76\x1C"     # 13 | mov esi, dword ptr [esi + 0x1c]
buffer += b"\x8B\x46\x08"     # 16 | mov eax, dword ptr [esi + 8]
buffer += b"\x8B\x4E\x20"     # 19 | mov ecx, dword ptr [esi + 0x20]
buffer += b"\x8B\x36"         # 1c | mov esi, dword ptr [esi]
buffer += b"\x39\x51\x18"     # 1e | cmp dword ptr [ecx + 0x18], edx
buffer += b"\x75\xF3"         # 21 | jne 0x16
buffer += b"\x8B\x75\xFC"     # 23 | mov esi, dword ptr [ebp - 4]
buffer += b"\x89\xEC"         # 26 | mov esp, ebp
buffer += b"\x5D"             # 28 | pop ebp
buffer += b"\xC3"             # 29 | ret
```

This script is meant to be run on Windows 10 (x86). To support this expectation,
the following design choices have been made during its development:

- All provided DLLs are compiled in 32-bit mode;
- The code has been tested on Python 3.9.6;
- ~~Script enables ANSI for colour support in the native CMD;~~

Finally, I'd like to mention that this script does not contain any intelligent
features; it merely attempts to minimise tedium.