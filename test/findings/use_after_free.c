// SPDX-License-Identifier: Apache-2.0
// expect: rule=heap-use-after-free cwe=CWE-416 level=error line=9 alloc=7
#include <stdlib.h>

int main(void)
{
    int* values = malloc(4 * sizeof(int));
    free(values);
    return values[0];
}
