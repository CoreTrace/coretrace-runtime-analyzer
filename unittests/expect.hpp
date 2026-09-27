// SPDX-License-Identifier: Apache-2.0
// The one check the unit tests share: print [PASS] or [FAIL] and count the failures.
#ifndef CORETRACE_RUNTIME_ANALYZER_UNITTESTS_EXPECT_HPP
#define CORETRACE_RUNTIME_ANALYZER_UNITTESTS_EXPECT_HPP

#include <iostream>
#include <string_view>

namespace unittests
{
    inline int failures = 0;

    inline void Expect(bool condition, std::string_view what)
    {
        std::cout << (condition ? "[PASS] " : "[FAIL] ") << what << '\n';
        if (!condition)
        {
            ++failures;
        }
    }

    // The exit status of a test executable: 1 with a failed check, 0 otherwise.
    inline int Finish(std::string_view name)
    {
        if (failures != 0)
        {
            std::cerr << failures << " check(s) failed\n";
            return 1;
        }
        std::cout << name << ": all checks passed\n";
        return 0;
    }
} // namespace unittests

#endif // CORETRACE_RUNTIME_ANALYZER_UNITTESTS_EXPECT_HPP
