// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=trace,alloc --ct-autofree
// expect: rule=memory-leak cwe=CWE-401 level=warning alloc=13
// expect: program-exit=1
#include <stdlib.h>
#include <stdint.h>

static volatile uintptr_t g_bits;
static volatile void* g_ptr;

int main(void)
{
    void* p = malloc(24);

    g_bits = (uintptr_t)p; /* escape: stored globally as integer */

    void* q = (void*)g_bits; /* inttoptr */
    g_ptr = q;               /* escape: stored globally as pointer */

    return g_ptr == NULL ? 0 : 1;
}
