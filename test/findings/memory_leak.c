// SPDX-License-Identifier: Apache-2.0
// expect: rule=memory-leak cwe=CWE-401 level=warning alloc=7
#include <stdlib.h>

int main(void)
{
    int* values = malloc(4 * sizeof(int));
    values[0] = 1;
    return 0;
}
