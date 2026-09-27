// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=trace,alloc --ct-autofree
// sbrk is a real allocation on Linux; macOS emulates it outside the runtime's view.
// expect: none
// expect[linux]: output="auto-free ptr="
#include <unistd.h>

int main(void)
{
    void* p = sbrk(64);
    if (p == (void*)-1)
    {
        return 0;
    }
    (void)p;
    return 0;
}
