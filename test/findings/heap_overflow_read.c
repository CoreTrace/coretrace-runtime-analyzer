// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>

int main(void)
{
    int* values = calloc(4, sizeof(int));
    int value = values[4];
    free(values);
    return value;
}
