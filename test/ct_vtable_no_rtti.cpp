// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=alloc,vtable --ct-vtable-diag -fno-rtti
// expect: rule=vtable-diagnostic cwe=CWE-843 level=warning line=24
#include <cstdio>

struct Base
{
    virtual int Value() const
    {
        return 1;
    }
};

struct Derived : Base
{
    int Value() const override
    {
        return 2;
    }
};

[[gnu::noinline]] int Call(const Base& base)
{
    return base.Value();
}

int main()
{
    Derived derived;
    std::printf("%d\n", Call(derived));
    return 0;
}
