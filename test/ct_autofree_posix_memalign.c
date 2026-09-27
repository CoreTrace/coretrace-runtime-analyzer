// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=trace,alloc --ct-autofree
// expect: none
// expect: output="auto-free ptr="
#include <stdlib.h>

int main(void)
{
    void* p = NULL;
    if (posix_memalign(&p, 64, 128) != 0)
    {
        return 0;
    }
    (void)p;
    return 0;
}
