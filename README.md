# ASM-Obfuscator
Advanced x86-64 assembly obfuscator.
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Description

The Assembly Code Obfuscator is a powerful and versatile tool designed to enhance the security of your x86-64 assembly code. It shields your projects from reverse engineering and analysis by employing a wide range of obfuscation techniques and anti-analysis measures.

## Features

- **Instruction Injection**: Injects custom byte sequences before each assembly instruction to bewilder disassemblers.

- **Randomization**: Introduces randomness into the code structure, making it less predictable.

- **Debugger Detection**: Detects the presence of debuggers during code execution and employs anti-debugging measures.

- **Anti-Analysis Techniques**: Confuses dynamic analysis tools with conditional branching and timing checks.

- **Dynamic Decryption**: Encrypts and dynamically decrypts code sections at runtime, increasing complexity.

- **Dynamic Decompression**: Compresses and dynamically decompresses code sections, hiding the code's true nature.

- **Constant Obfuscation**: Obfuscates constants and data values using techniques like XOR-ing and bit manipulation.

- **Variable Renaming**: Renames variables and registers, making the code less human-readable.

- **Junk Code Insertion**: Inserts junk code partitions to further obscure the codebase.

## Working

### 1. Instruction Injection

The core of the obfuscation process involves injecting custom byte sequences before each assembly instruction in the code file. These strategically designed byte sequences are intended to bewilder disassemblers and analysts alike. Let's examine this process in detail:

#### Original Instruction:

```assembly
4005d2:   55                      push   rbp
```
In memory (hex): 
```
0x55
```
--------------

#### After Injection:
```assembly
400665:   eb 01                jmp    400668 <main+0x3>
400667:   b0 55                mov    al,0x55
400669:   eb 01                jmp    40066c <main+0x7>
```
In memory (hex): 
```
0xEB, 0x01, 0xB0, 0x55
```


Here's a breakdown of the transformation:

- The original instruction `PUSH RBP` assembles to `0x55`. The obfuscator inserts the bytes `0xEB, 0x01, 0xB0` before it.

- The result is a sequence of instructions that, when disassembled, may appear entirely different from the original code. This makes it challenging for RE to understand the code's true purpose.

### 2. Randomization

It introduces randomization elements into the code. It involves techniques such as instruction permutation, operand swapping, and opcode substitution. 

### 3. Debugger Detection

Incorporates mechanisms to detect the presence of debuggers during code execution. Has runtime checks to identify debugger-related artifacts and  trigger anti-analysis measures.

### 4. Anti-Analysis Techniques

Integrates several anti-analysis measures, such as conditional branching and timing checks. For instance, it may insert conditional jumps and delay loops to slow down the analysis process.

### 5. Dynamic Decryption

It employs dynamic decryption techniques. It encrypts certain code sections and decrypts them at runtime using a secret key. This decryption process occurs dynamically during code execution.

### 6. Dynamic Decompression

It compresses specific code sections and decompresses them on the fly when executed.

### 7. Constant Obfuscation

Uses techniques like XOR-ing, bit manipulation, and arithmetic operations to obfuscate constants. This ensures that constant values are not readily recognizable.

### 8. Variable Renaming

The tool renames variables and registers, making the code less readable. The process involves replacing variable names with randomly generated strings or numerical identifiers.

### 9. Junk Code Insertion

To further obscure the code, the obfuscator inserts junk code partitions at strategic locations. This junk code consists of irrelevant instructions that do not affect program logic but serve to clutter the codebase.

#### Example of Junk Code Insertion:

```assembly
; Original Code
mov eax, 1

; After Junk Code Insertion
mov ebx, 2
sub ecx, ecx
add edx, edx
```

In memory (hex): 
```
0x89, 0xD8, 0x31, 0xC9, 0x01, 0xD2
```

The inserted junk code is designed to divert attention and make the code appear more convoluted.

### 10. Fake UPX Detection

Also incorporates a feature to detect fake UPX headers. It scans the code for signs of tampering with UPX headers, ensuring the integrity of the executable.

**Before Transformation (Original Code):**

```assembly
section .text
global _start

_start:
    ; Calculate the sum of the first 10 natural numbers
    mov ecx, 10        ; Initialize loop counter
    mov eax, 0         ; Initialize sum to 0

loop_start:
    add eax, ecx       ; Add current value of ECX to EAX (sum)
    loop loop_start    ; Decrement ECX and loop if not zero

    ; Exit program
    mov eax, 1         ; SYS_exit
    int 0x80           ; Invoke syscall
```

**Hexadecimal Representation (Original Code):**

```plaintext
31 C9                 xor    ecx,ecx
B8 00 00 00 00        mov    eax,0x0
EB 0E                 jmp    0x1c
01 C8                 add    eax,ecx
E2 FB                 loop   0x11
B8 01 00 00 00        mov    eax,0x1
CD 80                 int    0x80
```

**After Transformation (Obfuscated Code):**

```assembly
section .text
global _start

_start:
    ; Calculate the sum of the first 10 natural numbers
    mov eax, 0x1
    add eax, 0x2
    add eax, 0x3
    add eax, 0x4
    add eax, 0x5
    add eax, 0x6
    add eax, 0x7
    add eax, 0x8
    add eax, 0x9
    add eax, 0xa

    ; Exit program
    mov eax, 0x1
    int 0x80
```

**Hexadecimal Representation (Obfuscated Code):**

```plaintext
B8 01 00 00 00        mov    eax,0x1
83 C0 02              add    eax,0x2
83 C0 03              add    eax,0x3
83 C0 04              add    eax,0x4
83 C0 05              add    eax,0x5
83 C0 06              add    eax,0x6
83 C0 07              add    eax,0x7
83 C0 08              add    eax,0x8
83 C0 09              add    eax,0x9
83 C0 0A              add    eax,0xa
B8 01 00 00 00        mov    eax,0x1
CD 80                 int    0x80
```

In the obfuscated code, we've made the original program logic less apparent by adding redundant `ADD` instructions and using hexadecimal values as immediate operands. 


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome!.

## Support

For issues, feature requests, or general inquiries, please [create an issue](https://github.com/your/repository/issues).

## Disclaimer

This tool is intended for educational and ethical purposes. 
