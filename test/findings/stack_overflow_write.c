// SPDX-License-Identifier: Apache-2.0
// expect: rule=stack-buffer-overflow cwe=CWE-121 level=error line=8 alloc=4
// Writes one element past a local array, at an index the compiler cannot see.
int main(void)
{
    int values[4] = {1, 2, 3, 4};
    volatile int index = 4;
    values[index] = 5;
    return values[0];
}
