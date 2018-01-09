
BITS 64

global jump_to

jump_to:
  jmp rdi

; this appears to be necessary for gcc to mark the binary to use NX by default
SECTION .note.GNU-stack noalloc
