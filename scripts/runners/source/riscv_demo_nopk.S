.section .text
.globl _start
_start:
  addi a0, zero, 1
  addi a1, zero, 2
loop:
  add  a2, a0, a1
  j loop
