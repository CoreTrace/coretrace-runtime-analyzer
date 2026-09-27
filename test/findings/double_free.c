// SPDX-License-Identifier: Apache-2.0
// expect: rule=double-free cwe=CWE-415 level=error line=9 alloc=7
#include <stdlib.h>

int main(void)
{
    int* values = malloc(4 * sizeof(int));
    free(values);
    free(values);
    return 0;
}
