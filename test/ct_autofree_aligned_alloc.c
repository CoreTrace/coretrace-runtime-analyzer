// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=trace,alloc --ct-autofree
// expect: none
// expect: output="auto-free ptr="
#include <stdlib.h>

int main(void)
{
    void* p = aligned_alloc(64, 256);
    (void)p;
    return 0;
}
