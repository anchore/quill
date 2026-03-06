// minimal macOS ARM64 executable - raw assembly
// exits immediately with code 0

.global _main
.align 4

_main:
    mov x0, #0          // exit code 0
    mov x16, #1         // syscall: exit
    svc #0x80           // invoke syscall
