// SPDX-License-Identifier: Apache-2.0
// Checks the rule that points coretrace-compiler at the Clang headers shipped next to the CLI.
#include "shipped_toolchain.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    using coretrace::runtime_analyzer::ShippedLinkArguments;
    using coretrace::runtime_analyzer::UseShippedClangHeaders;

    int failures = 0;

    void Expect(bool condition, std::string_view what)
    {
        std::cout << (condition ? "[PASS] " : "[FAIL] ") << what << '\n';
        if (!condition)
        {
            ++failures;
        }
    }

    [[nodiscard]] std::string Env(const char* name)
    {
        const char* value = std::getenv(name);
        return value != nullptr ? value : "";
    }

    // <root>/bin/runtime-analyzer, with the headers at <root>/lib/clang/20/include when asked.
    [[nodiscard]] std::filesystem::path Layout(std::string_view name, bool with_headers)
    {
        const std::filesystem::path root =
            std::filesystem::temp_directory_path() / ("shipped_toolchain_" + std::string(name));
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root / "bin");
        if (with_headers)
        {
            std::filesystem::create_directories(root / "lib" / "clang" / "20" / "include");
            std::ofstream(root / "lib" / "clang" / "20" / "include" / "stddef.h") << "\n";
        }
        return root / "bin" / "runtime-analyzer";
    }

    void PointsAtItselfWhenHeadersAreShipped()
    {
        unsetenv("CT_CLANG");
        const std::filesystem::path executable = Layout("shipped", true);
        Expect(UseShippedClangHeaders(executable), "shipped headers: used");
        Expect(Env("CT_CLANG") == executable.string(), "shipped headers: CT_CLANG is the CLI");
    }

    void LeavesTheUsersClangAlone()
    {
        setenv("CT_CLANG", "/opt/llvm/bin/clang", 1);
        const std::filesystem::path executable = Layout("user", true);
        Expect(!UseShippedClangHeaders(executable), "user's CT_CLANG: shipped headers not used");
        Expect(Env("CT_CLANG") == "/opt/llvm/bin/clang", "user's CT_CLANG: kept");
        unsetenv("CT_CLANG");
    }

    void LinksAgainstTheShippedCxxRuntime()
    {
        const std::filesystem::path executable = Layout("cxx", false);
        const std::filesystem::path lib =
            (executable.parent_path() / ".." / "lib").lexically_normal();
        std::filesystem::create_directories(lib);
        std::ofstream(lib / "libstdc++.so") << "\n";
        const std::vector<std::string> arguments = ShippedLinkArguments(executable);
        Expect(arguments ==
                   std::vector<std::string>{"-L" + lib.string(), "-Wl,-rpath," + lib.string()},
               "shipped libstdc++: -L and -rpath on the shipped lib directory");
        Expect(ShippedLinkArguments(Layout("nocxx", false)).empty(),
               "no shipped libstdc++: no link argument");
        Expect(ShippedLinkArguments({}).empty(), "unknown executable: no link argument");
    }

    void DoesNothingWithoutHeaders()
    {
        unsetenv("CT_CLANG");
        const std::filesystem::path executable = Layout("bare", false);
        Expect(!UseShippedClangHeaders(executable), "no headers: not used");
        Expect(Env("CT_CLANG").empty(), "no headers: CT_CLANG stays unset");
        Expect(!UseShippedClangHeaders({}), "unknown executable: not used");
    }
} // namespace

int main()
{
    PointsAtItselfWhenHeadersAreShipped();
    LeavesTheUsersClangAlone();
    LinksAgainstTheShippedCxxRuntime();
    DoesNothingWithoutHeaders();
    if (failures != 0)
    {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "shipped_toolchain_test: all checks passed\n";
    return 0;
}
