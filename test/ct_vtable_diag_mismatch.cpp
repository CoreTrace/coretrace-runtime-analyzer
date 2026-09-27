// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=alloc,vtable --ct-vtable-diag
// expect: rule=vtable-type-mismatch cwe=CWE-843 level=warning line=41
#include <cstdio>
#include <dlfcn.h>

extern "C" void __ct_vcall_trace(void* this_ptr, void* target, const char* site,
                                 const char* static_type);

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
    std::puts("ct_vtable_diag_mismatch");

    Derived obj;
    Base* base = &obj;

    void* target = dlsym(RTLD_DEFAULT, "puts");
    if (!target)
    {
        std::puts("ct_vtable_diag_mismatch: dlsym failed");
        return 1;
    }

    __ct_vcall_trace(base, target, "ct_vtable_diag_mismatch.cpp:41:5", "Base");

    return 0;
}
