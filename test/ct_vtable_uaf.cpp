// SPDX-License-Identifier: Apache-2.0
// The access faults before the vtable module sees the freed vptr: the alloc module
// reports the use after free.
// expect: rule=heap-use-after-free cwe=CWE-416 level=error line=27 alloc=24
#include <cstdio>
struct Base
{
    virtual ~Base() = default;
    virtual int value() const
    {
        return 1;
    }
};
struct Derived : Base
{
    int value() const override
    {
        return 2;
    }
};

int main()
{
    Base* ptr = new Derived();
    delete ptr;
    // UAF volontaire pour tester le diag
    std::printf("%d\n", ptr->value());
    return 0;
}
