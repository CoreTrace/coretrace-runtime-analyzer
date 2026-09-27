// SPDX-License-Identifier: Apache-2.0
// args: --ct-modules=alloc,bounds -x c++
// expect: none
#include <string>

int main()
{
    std::string s = "hello";
    return (static_cast<int>(s.size()) == 5) ? 0 : 1;
}
