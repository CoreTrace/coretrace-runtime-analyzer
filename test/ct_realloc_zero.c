// SPDX-License-Identifier: Apache-2.0
// realloc(p, 0) frees on glibc; macOS returns a new block that is never freed.
// expect[linux]: none
// expect[darwin]: rule=memory-leak cwe=CWE-401 level=warning alloc=10
#include <stdlib.h>

int main(void)
{
    char* p = (char*)malloc(32);
    p = (char*)realloc(p, 0); // free-like behavior per libc
    (void)p;
    return 0;
}
