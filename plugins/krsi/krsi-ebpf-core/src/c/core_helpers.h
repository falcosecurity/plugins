#ifndef __CORE_HELPERS_H__
#define __CORE_HELPERS_H__

#if defined(__bpf__)
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef long long unsigned int u64;

#define inline __attribute__((always_inline))

// Define structure and helpers here.

#if defined(__bpf__)
#pragma clang attribute pop
#endif

#endif
