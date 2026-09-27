// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=alloc,vtable --ct-vtable-diag
// expect: rule=vtable-null-this cwe=CWE-476 level=error line=11
#include <cstdio>

extern "C" void __ct_vtable_dump(void* this_ptr, const char* site, const char* static_type);

int main()
{
    std::puts("ct_vtable_diag_null");
    __ct_vtable_dump(nullptr, "ct_vtable_diag_null.cpp:11:5", "Base");
    return 0;
}
