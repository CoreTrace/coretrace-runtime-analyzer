// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>

int main(void)
{
    int* values = malloc(4 * sizeof(int));
    values[4] = 1;
    free(values);
    return 0;
}
