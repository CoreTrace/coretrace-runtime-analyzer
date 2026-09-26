// SPDX-License-Identifier: Apache-2.0
// Checks the runtime report parser against output captured from CoreTrace's runtime.
#include "findings.hpp"

#include <iostream>
#include <string_view>

namespace
{
    using coretrace::runtime_analyzer::Finding;
    using coretrace::runtime_analyzer::ParseFindings;
    using coretrace::runtime_analyzer::Severity;
    using coretrace::runtime_analyzer::SourceLocation;

    int failures = 0;

    void Expect(bool condition, std::string_view what)
    {
        std::cout << (condition ? "[PASS] " : "[FAIL] ") << what << '\n';
        if (!condition)
        {
            ++failures;
        }
    }

    [[nodiscard]] bool IsAt(const std::optional<SourceLocation>& location, std::string_view file,
                            unsigned line, unsigned column)
    {
        return location && location->file == file && location->line == line &&
               location->column == column;
    }

    void HeapOverflowWrite()
    {
        constexpr std::string_view output =
            "|91461| ==ct== [INFO] tracing-malloc :: tid=40929695 site=sub/oob.c:4:19\n"
            "|91461| ==ct== [ERROR] ct: heap-buffer-overflow WRITE of size 4\n"
            "  access=sub/oob.c:5:15 ptr=0x60000066c040 offset=16\n"
            "  alloc_size=16 alloc_site=sub/oob.c:4:19 base=0x60000066c030\n"
            "|91461| ==ct== [INFO] tracing-free ptr=0x60000066c030 size=16\n";
        const std::vector<Finding> findings = ParseFindings(output);
        Expect(findings.size() == 1, "heap overflow write: one finding");
        if (findings.size() != 1)
        {
            return;
        }
        const Finding& finding = findings[0];
        Expect(finding.rule == "heap-buffer-overflow", "heap overflow write: rule");
        Expect(finding.cwe == "CWE-122", "heap overflow write: CWE-122");
        Expect(finding.severity == Severity::Error, "heap overflow write: error");
        Expect(finding.message == "heap-buffer-overflow WRITE of size 4",
               "heap overflow write: message without addresses");
        Expect(IsAt(finding.location, "sub/oob.c", 5, 15), "heap overflow write: access site");
        Expect(IsAt(finding.allocation, "sub/oob.c", 4, 19), "heap overflow write: alloc site");
    }

    void StackOverflowWriteKeepsTheFunctionLine()
    {
        constexpr std::string_view output =
            "|91485| ==ct== [ERROR] ct: stack-buffer-overflow WRITE of size 4\n"
            "  access=stack.c:5:19 ptr=0x16bd52800 offset=16\n"
            "  alloc_size=16 alloc_site=stack.c:1 base=0x16bd527f0\n";
        const std::vector<Finding> findings = ParseFindings(output);
        Expect(findings.size() == 1, "stack overflow write: one finding");
        if (findings.size() != 1)
        {
            return;
        }
        Expect(findings[0].rule == "stack-buffer-overflow", "stack overflow write: rule");
        Expect(findings[0].cwe == "CWE-121", "stack overflow write: CWE-121");
        Expect(IsAt(findings[0].location, "stack.c", 5, 19), "stack overflow write: access site");
        Expect(IsAt(findings[0].allocation, "stack.c", 1, 0),
               "stack overflow write: the object's line without a column");
    }

    void ReadOverflowsAreOutOfBoundsReads()
    {
        const std::vector<Finding> heap =
            ParseFindings("|1| ==ct== [ERROR] ct: heap-buffer-overflow READ of size 4\n"
                          "  access=a.c:7:15 ptr=0x1 offset=16\n"
                          "  alloc_size=16 alloc_site=a.c:6:18 base=0x0\n");
        Expect(heap.size() == 1 && heap[0].cwe == "CWE-125", "heap overflow read: CWE-125");
        const std::vector<Finding> stack =
            ParseFindings("|1| ==ct== [ERROR] ct: stack-buffer-overflow READ of size 4\n"
                          "  access=a.c:7:15 ptr=0x1 offset=16\n"
                          "  alloc_size=16 alloc_site=a.c:3 base=0x0\n");
        Expect(stack.size() == 1 && stack[0].cwe == "CWE-125", "stack overflow read: CWE-125");
    }

    void UseAfterFree()
    {
        const std::vector<Finding> findings =
            ParseFindings("|1| ==ct== [ERROR] ct: heap-use-after-free READ of size 4\n"
                          "  access=uaf.c:8:12 ptr=0x1 offset=0\n"
                          "  alloc_size=16 alloc_site=uaf.c:6:19 base=0x1\n"
                          "  usable_size=32\n");
        Expect(findings.size() == 1, "use after free: one finding");
        if (findings.size() != 1)
        {
            return;
        }
        Expect(findings[0].rule == "heap-use-after-free", "use after free: rule");
        Expect(findings[0].cwe == "CWE-416", "use after free: CWE-416");
        Expect(findings[0].message == "heap-use-after-free READ of size 4",
               "use after free: message");
        Expect(IsAt(findings[0].location, "uaf.c", 8, 12), "use after free: access site");
        Expect(IsAt(findings[0].allocation, "uaf.c", 6, 19), "use after free: alloc site");
    }

    void UnknownSitesGiveNoLocation()
    {
        const std::vector<Finding> findings =
            ParseFindings("|1| ==ct== [ERROR] ct: heap-buffer-overflow WRITE of size 1\n"
                          "  access=<unknown> ptr=0x1 offset=16\n"
                          "  alloc_size=16 alloc_site=<unknown> base=0x0\n");
        Expect(findings.size() == 1, "unknown sites: one finding");
        if (findings.size() != 1)
        {
            return;
        }
        Expect(!findings[0].location, "unknown sites: no access location");
        Expect(!findings[0].allocation, "unknown sites: no allocation location");
    }

    void DoubleFree()
    {
        const std::vector<Finding> findings =
            ParseFindings("|1| ==ct== [INFO] tracing-free ptr=0x60000066c040 size=16\n"
                          "|1| ==ct== [WARN] tracing-free ptr=0x60000066c040 (double free) "
                          "site=sub/oob.c:11:5 alloc_site=sub/oob.c:9:18\n");
        Expect(findings.size() == 1, "double free: one finding");
        if (findings.size() != 1)
        {
            return;
        }
        Expect(findings[0].rule == "double-free", "double free: rule");
        Expect(findings[0].cwe == "CWE-415", "double free: CWE-415");
        Expect(findings[0].severity == Severity::Error, "double free: error");
        Expect(findings[0].message == "double free", "double free: message");
        Expect(IsAt(findings[0].location, "sub/oob.c", 11, 5), "double free: second free site");
        Expect(IsAt(findings[0].allocation, "sub/oob.c", 9, 18), "double free: alloc site");
    }

    void MemoryLeak()
    {
        const std::vector<Finding> findings = ParseFindings(
            "|1| ==ct== [ERROR] ct: leaks detected count=1\n"
            "|1| ==ct== [WARN] ct: leak ptr=0x60000066c030 size=16 alloc_site=sub/oob.c:7:19\n");
        Expect(findings.size() == 1, "memory leak: one finding per leaked block");
        if (findings.size() != 1)
        {
            return;
        }
        Expect(findings[0].rule == "memory-leak", "memory leak: rule");
        Expect(findings[0].cwe == "CWE-401", "memory leak: CWE-401");
        Expect(findings[0].severity == Severity::Warning, "memory leak: warning");
        Expect(findings[0].message == "memory leak of 16 bytes", "memory leak: message");
        Expect(!findings[0].location, "memory leak: no access location");
        Expect(IsAt(findings[0].allocation, "sub/oob.c", 7, 19), "memory leak: alloc site");
    }

    void TracingLinesAreNotFindings()
    {
        const std::vector<Finding> findings =
            ParseFindings("|1| ==ct== [INFO] tracing-malloc :: tid=1 site=a.c:4:19\n"
                          "|1| ==ct== [INFO] | ptr              : 0x60000305c030 |\n"
                          "|1| ==ct== [INFO] tracing-free ptr=0x60000305c030 size=16\n"
                          "|1| ==ct== [INFO] [ENTRY-FUNCTION] main\n"
                          "  alloc_size=16 alloc_site=a.c:4:19 base=0x0\n");
        Expect(findings.empty(), "tracing lines: no finding");
    }
} // namespace

int main()
{
    HeapOverflowWrite();
    StackOverflowWriteKeepsTheFunctionLine();
    ReadOverflowsAreOutOfBoundsReads();
    UseAfterFree();
    UnknownSitesGiveNoLocation();
    DoubleFree();
    MemoryLeak();
    TracingLinesAreNotFindings();
    if (failures != 0)
    {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "findings_test: all checks passed\n";
    return 0;
}
