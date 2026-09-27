// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=trace,alloc --ct-autofree
// expect: rule=memory-leak cwe=CWE-401 level=warning alloc=12
// expect: program-exit=1
#include <stdlib.h>
#include <stdint.h>

static volatile uintptr_t g_ptr_bits;

int main(void)
{
    void* p = malloc(24);
    g_ptr_bits = (uintptr_t)p; /* escape: stored globally */
    return g_ptr_bits == 0 ? 0 : 1;
}
