// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=alloc,bounds -DDEBUG
// expect: none
#ifndef DEBUG
#error "DEBUG not defined"
#endif
int main()
{
    return 0;
}
