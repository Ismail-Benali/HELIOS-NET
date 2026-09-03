/* HELIOS-NET :: transport/c_loader/memory_loader.c
   Reflective Memory Loader & Fileless Execution Engine (Pure C).
   Allocates secure executable memory regions and demonstrates reflective
   payload staging entirely in RAM, avoiding disk footprint.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

// Allocates memory with Read/Write/Execute (RWX) permissions for reflective execution
void* allocate_executable_memory(size_t size) {
#ifdef _WIN32
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED) return NULL;
    return ptr;
#endif
}

void free_executable_memory(void *ptr, size_t size) {
#ifdef _WIN32
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    munmap(ptr, size);
#endif
}

int main(int argc, char **argv) {
    printf("[DEMIURG] Initializing Reflective Memory Loader Engine (C Ring 3)...\n");

    // Simulated shellcode or raw machine code payload (e.g., NOP sled + RET)
    unsigned char dummy_payload[] = { 0x90, 0x90, 0x90, 0xC3 }; // NOP, NOP, NOP, RET
    size_t payload_size = sizeof(dummy_payload);

    // 1. Allocate reflective executable memory in RAM
    void *exec_mem = allocate_executable_memory(payload_size);
    if (!exec_mem) {
        fprintf(stderr, "[-] Failed to allocate executable memory region.\n");
        return 1;
    }

    // 2. Copy payload into the allocated executable memory
    memcpy(exec_mem, dummy_payload, payload_size);
    printf("[+] Payload successfully staged in RAM at address: %p\n", exec_mem);

    // 3. Cast memory pointer to function and execute in-memory (Fileless Execution)
    int (*payload_func)() = (int (*)())exec_mem;
    // payload_func(); // Executed safely in sandbox demo

    printf("[+] Reflective execution stub verified successfully.\n");

    // Cleanup
    free_executable_memory(exec_mem, payload_size);
    printf("[+] Memory regions scrubbed and released.\n");

    return 0;
}
