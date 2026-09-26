// SPDX-License-Identifier: Apache-2.0
#include "shipped_toolchain.hpp"

#include <cstdlib>
#include <system_error>

namespace coretrace::runtime_analyzer
{
    bool UseShippedClangHeaders(const std::filesystem::path& executable)
    {
        const char* configured = std::getenv("CT_CLANG");
        if (executable.empty() || (configured != nullptr && *configured != '\0'))
        {
            return false;
        }
        std::error_code error;
        const std::filesystem::path clang_dir = executable.parent_path() / ".." / "lib" / "clang";
        for (const auto& version : std::filesystem::directory_iterator(clang_dir, error))
        {
            if (std::filesystem::is_regular_file(version.path() / "include" / "stddef.h", error))
            {
                return setenv("CT_CLANG", executable.string().c_str(), /*overwrite=*/1) == 0;
            }
        }
        return false;
    }
} // namespace coretrace::runtime_analyzer
