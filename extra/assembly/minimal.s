.global _start
.align 2

_start:
  mov     X0, #0  // Use 0 return code
  mov     X16, #1 // 1 = exit
  svc     0       // syscall
