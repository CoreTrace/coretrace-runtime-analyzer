// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=trace,alloc --ct-autofree
// expect: none
// expect: output="auto-free ptr="
#include <stdlib.h>

void* bar(void)
{
    return malloc(sizeof(void*));
}

int main(void)
{
    bar();
    free(bar());
    return 0;
}
