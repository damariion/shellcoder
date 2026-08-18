init:

    push ebp
    mov ebp, esp
    sub esp, 0x20

    ; ? resolve kernel32
    
    xor eax, eax
    mov edx, dword ptr fs:[eax+0x30]    ; _TEB_->_PEB
    mov edx, dword ptr [edx+0x0C]       ; _PEB->_PEB_LDR_DATA
    mov edx, dword ptr [edx+0x1C]       ; _PEB_LDR_DATA->_LIST_ENTRY (first)

init_next_modl:

    mov ebx, dword ptr [edx+0x08]       ; DllBase
    mov edi, dword ptr [edx+0x20]       ; BaseDllName->Buffer
    mov edx, dword ptr [edx]            ; _PEB_LDR_DATA->_LIST_ENTRY (next)
    cmp word ptr [edi+(12*2)], ax       ; check if ((wchar*)Buffer)[12] == 0x0
    jne init_next_modl                  ; repeat until this is the case...
    mov dword ptr [ebp-0x04], ebx       ; store handle to kernel32 locally

    ; ? resolve kernel32!GetProcAddress
    
    mov ecx, dword ptr [ebx+0x3C]       ; _IMAGE_DOS_HEADER->_IMAGE_NT_HEADERS
    mov edx, dword ptr [ebx+ecx+0x78]   ; VirtualAddress
    add edx, ebx                        ; RVA->VA
    mov dword ptr [ebp-0x10], edx       ; store _IMAGE_EXPORT_DIRECTORY
    mov ecx, dword ptr [edx+0x18]       ; NumberOfNames
    mov edx, dword ptr [edx+0x20]       ; AddressOfNames
    add edx, ebx                        ; RVA->VA

init_next_name:

    xor edi, edi                        ; prepare for hashing
    dec ecx                             ; decrement counter..
    mov esi, dword ptr [edx+ecx*4]      ; store the function's identifier
    add esi, ebx                        ; RVA->VA

init_next_byte:

    lodsb                               ; al = *(esi++)
    test al, al                         ; end of string reached?
    je init_bool                        ; jmp if this is the case
    ror edi, 0xD                        ; ror 13
    add edi, eax                        ; add char value to
    jmp init_next_byte                  ; repeat steps...

init_bool:

    cmp edi, 0x7C0DFCAA                 ; GetProcAddress
    jne init_next_name                  ; repeat until this is the case
    
    mov edx, dword ptr [ebp-0x10]       ; recover _IMAGE_EXPORT_DIRECTORY
    mov eax, dword ptr [edx+0x24]       ; AddressOfNameOrdinals
    add eax, ebx                        ; RVA->VA
    mov cx, word ptr [eax+ecx*2]        ; store ordinal for AddressOfFunctions
    mov eax, dword ptr [edx+0x1C]       ; AddressOfFunctions
    add eax, ebx                        ; RVA->VA
    mov eax, dword ptr [eax+ecx*4]      ; store RVA of function's VA
    add eax, ebx                        ; RVA->VA
    mov dword ptr [ebp-0x08], eax       ; store VA to GetProcAddress locally

main:

    ; * STACK LAYOUT
    ; * -0x04 | kernel32
    ; * -0x08 | kernel32!GetProcAddress
    ; * -0x20 | ... (esp)

    int3