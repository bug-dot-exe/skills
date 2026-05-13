# Memory Corruption Vulnerabilities

Format templates for memory corruption proof-of-concept output.

## Buffer Overflow

**Preferred format:** C program or Python script generating the trigger input

**Stack-based overflow:**
```c
// Generates input that overflows the buffer in vulnerable_function()
// at source.c:42. The buffer is 64 bytes but read() accepts up to 256.
#include <stdio.h>
#include <string.h>

int main() {
    // 64 bytes fill buffer + 8 bytes saved RBP + 8 bytes canary/padding
    char payload[80];
    memset(payload, 'A', sizeof(payload));
    // Write to stdout for piping to vulnerable binary
    fwrite(payload, 1, sizeof(payload), stdout);
    return 0;
}
```

**Heap overflow/use-after-free:** Provide allocation/free sequence with commentary
on heap layout. Include GDB/LLDB commands to inspect the crash.

Include the crash output (segfault address, register state, backtrace) as evidence.

## Format String

**Preferred format:** Minimal input + expected output

```bash
# The name parameter is passed directly to printf() at handler.c:87
# without a format specifier
./vulnerable_binary "$(python3 -c "print('%x.' * 20)")"
# Expected output: leaked stack values (hex addresses)
```
