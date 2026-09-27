// SPDX-License-Identifier: Apache-2.0
// expect: rule=heap-buffer-overflow cwe=CWE-125 level=error line=8 alloc=7
#include <stdlib.h>

int main(void)
{
    int* values = calloc(4, sizeof(int));
    int value = values[4];
    free(values);
    return value;
}
