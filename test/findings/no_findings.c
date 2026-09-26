// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>

// Exits non-zero without any memory error: the program's status is not a finding.
int main(void)
{
    int* values = malloc(4 * sizeof(int));
    values[3] = 1;
    free(values);
    return 3;
}
