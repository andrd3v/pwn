# arm64 basics 

### registers
`x0 - x30 SP PC (64-bit) - each has a 32-bit version w0 – w30 (the lower 32 bits of the corresponding x-register).`<br>
`X0–X7 - function arguments / return values (X0 — main)`<br>
X8 — temporary / indirect result / ABI-dependent (often used as scratch).<br>
X16, X17 — IP0/IP1; used for calls via plt/pc-rel (thunks), the compiler/linker often place there addresses for blr x17.<br>
X18 — platform register (by convention, may be reserved).<br>
X19–X28 — callee-saved (must be saved by the called function if used).<br>
`X29 (FP) - frame pointer. usually points to the base of the current stack frame (a fixed point in the frame), used to access local variables and to build the call chain. (where the current function’s stack begins)`<br>
`X30 (LP) - Link Pointer - stores the return address (where to jump after the function finishes (if it is not no-return))`<br>
`SP - Stack Pointer - points to the start address of the stack (the stack top). (kind of where you can write to the stack right now, see the diagram below)`<br>
`PC - program counter (address of the current instruction).`<br><br><br>

### stack (grows down) (here for convenience the opposite — the stack top is at the bottom and addresses grow upward, in reality it’s the other way around)
```
addresses ↑
───────────────────────
0x1000   ←  old data 9 (4096)
0x0FF0   (4080)
0x0FE0   (4064)
0x0FD0   ←  SP (stack top) (4048)
───────────────────────
addresses ↓
```
we do
```asm
sub sp, sp, #0x10   ; freed 16 bytes for new data
str x0, [sp]        ; wrote something to the top
```
Now SP = 0x0FC0, and the data lies in the range [0x0FC0–0x0FD0).<br>
```
ldr x0, [sp]
add sp, sp, #0x10   ; removed 16 bytes
```
— the stack “shrinks upward”, and SP again points to 0x0FD0.<br><br>
`The stack top (SP) is the plate you can touch right now (the top one).`<br>
`But memory goes from top to bottom — that is, each new plate is placed below the previous one in addresses.`
```
       ↑  higher addresses
       │
       │        (old data)
0x1000 ──────────────────────────────
       │
       │   ← old SP (stack top)
0x0FF0 ──────────────────────────────
       │
       │   PUSH (new plate):
       │   sub sp, sp, #0x10
       │   now SP points lower!
0x0FE0 ──────────────────────────────  ← new SP (stack top)
       │        (new data)
       │
       ↓  lower addresses
```
In real memory, addresses increase downward on the screen (toward larger values).<br>
In the ARM64 stack it’s the opposite: on push the address decreases,
because the stack “grows downward” (toward smaller addresses).<br>
# Unconditional branch — B and BL

b loop_start      ; jump to label loop_start
- Does not save the return address.<br><br>

BL <label> — Branch with Link<br>
A jump that saves the return address in X30 (LR)<br>
bl printf          ; call the printf function<br>
Saves the address of the next instruction in LR.<br>
After the function finishes — return via ret, which uses LR.<br>

```
     +--------------------+
     | caller (main)      |
     | ...                |
     | bl func ---------->+--+
     +--------------------+  |
                             |
                             v
                   +----------------------+
                   | callee (func)        |
                   | LR = return addr  <--+
                   | ...                  |
                   | ret                  |
                   +----------------------+
                            |
                            v
                 return to main (LR)
```



## RET
Return to the address that lies in X30 (LR) or another register.<br>
ret             ; by default ret x30<br>
ret x19         ; return to the address in x19<br>

## Conditional branches — B.<cond>
The jump is performed only if the condition (flag in PSTATE) is true.
```
| Abbrev | Meaning                     | Checks            |
| ------ | --------------------------- | ----------------- |
| `eq`   | equal                       | Z == 1            |
| `ne`   | not equal                   | Z == 0            |
| `lt`   | less than (signed)          | N != V            |
| `le`   | less or equal (signed)      | Z == 1 or N != V  |
| `gt`   | greater than (signed)       | Z == 0 and N == V |
| `ge`   | greater or equal (signed)   | N == V            |
| `lo`   | lower (unsigned <)          | C == 0            |
| `ls`   | lower or same (unsigned ≤)  | C == 0 or Z == 1  |
| `hi`   | higher (unsigned >)         | C == 1 and Z == 0 |
| `hs`   | higher or same (unsigned ≥) | C == 1            |
| `mi`   | minus                       | N == 1            |
| `pl`   | plus                        | N == 0            |
| `vs`   | overflow set                | V == 1            |
| `vc`   | overflow clear              | V == 0            |
| `al`   | always (equivalent of `b`)  | always jumps      |
```
<br>

```
cmp x0, #0
b.eq zero_case      ; if x0 == 0
b.ne non_zero_case  ; if x0 != 0
```

```
| Flag | Purpose   | Set by                                  |
| ---- | --------- | ---------------------------------------- |
| **N**| Negative  | result < 0                               |
| **Z**| Zero      | result == 0                              |
| **C**| Carry     | carry in arithmetic ops (unsigned)       |
| **V**| Overflow  | overflow (signed)                        |
```

```
cmp x0, #5     ; subtraction x0 - 5
b.ge label     ; if x0 >= 5 (N == V)
```

# Register-indirect branches — BR, BLR
Used for jumps to an address stored in a register (analog of jmp rax in x86).<br>
BR <Xt> - Jump without saving the return address.<br>
```
mov x1, #0x1000
br x1              ; jump to 0x1000
```
<br>
BLR <Xt> - Jump with saving the return address (analog of call rax).<br>
       
```
mov x17, #func
blr x17            ; call a function by the address in x17
```
<br>  
Saves the return address in LR (x30).<br> 
Used for calls via PLT/GOT tables and virtual functions.<br><br> 

RET — returns to the address in X30 (LR) (by default)<br>
RET <Xt> — returns to the address from any register (used in obfuscation or trampolines)<br>
<br>
```
cbz x0, zero_case      ; if x0 == 0
cbnz x0, not_zero      ; if x0 != 0
tbz x1, #2, bit_clear  ; if bit 2 = 0
tbnz x1, #2, bit_set   ; if bit 2 = 1
```

```
| Instruction            | Meaning                         | What it does                 |
| ---------------------- | --------------------------------| ---------------------------- |
| `cbz Xt, label`        | Compare and Branch if Zero      | Jump if the register == 0    |
| `cbnz Xt, label`       | Compare and Branch if Not Zero  | Jump if the register != 0    |
| `tbz Xt, #bit, label`  | Test Bit and Branch if Zero     | Jump if the bit is clear     |
| `tbnz Xt, #bit, label` | Test Bit and Branch if Non-Zero | Jump if the bit is set       |
```
<br><br>
```
adrp x0, some_label@page
add  x0, x0, some_label@pageoff
bl   puts
```
<br>
adr — places current PC + offset (up to ±1 MB) into a register.<br>
adrp — the same, but by pages (with 4K step, ±4 GB from PC).<br>
Together with add they allow obtaining an absolute address of a symbol without using ldr.<br>

<br><br>
