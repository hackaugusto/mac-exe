// convention:
// X0-X2 - syscall parameters
// X16 - syscall function
.global _start // linker start address
.align 2

_start:
  mov X0, #1   // 1 = StdOut
  adr X1, str  // string to print
  mov X2, #13  // length of our string
  mov X16, #4  // 4 = write syscall
  svc 0        // syscall

  mov     X0, #0  // Use 0 return code
  mov     X16, #1 // 1 = exit
  svc     0       // syscall

str:      .ascii  "Hello World!\n"
