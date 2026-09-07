/* HELIOS-NET :: transport/evasion/evasion.h
   Header file for Windows x64 User-Mode Evasion Primitives.
*/

#ifndef HELIOS_EVASION_H
#define HELIOS_EVASION_H

#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdint.h>

// Standardized Error Envelope (SEE) emitter for stderr
void emit_see(const char *code, const char *message, const char *module);

// NDJSON structured output for stdout
void emit_ndjson(const char *technique, const char *status, const char *details, long long duration_ms);

// Core Evasion Techniques
int sleep_masking(unsigned char *payload, size_t size, DWORD sleep_ms);
int patch_etw(void);
int restore_etw(void);
int patch_amsi(void);
int restore_amsi(void);

#endif // HELIOS_EVASION_H
