// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>

int main(void)
{
    int* values = malloc(4 * sizeof(int));
    free(values);
    free(values);
    return 0;
}
