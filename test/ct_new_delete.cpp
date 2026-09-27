// SPDX-License-Identifier: Apache-2.0
// expect: rule=memory-leak cwe=CWE-401 level=warning alloc=11
int main()
{
    int* p = new int(7);
    delete p;

    int* a = new int[4];
    delete[] a;

    new int; // unreachable -> tracing-new-unreachable (+ autofree if enabled)
    return 0;
}
