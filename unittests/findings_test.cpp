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

    // The vtable module logs each suspicious virtual call or vtable access as a box, at WARN
    // level when it lists warnings.
    constexpr std::string_view kNullThisBox =
        "|72292| ==ct== [WARN] [VTABLE]\n"
        "|72292| ==ct== [WARN] ┌─ vtable ─────────────────────────────┐\n"
        "|72292| ==ct== [WARN] │ site   : ct_vtable_diag_null.cpp:7:5 │\n"
        "|72292| ==ct== [WARN] │ this   : <null>                      │\n"
        "|72292| ==ct== [WARN] │ type   : <unknown>                   │\n"
        "|72292| ==ct== [WARN] │ static : Base                        │\n"
        "|72292| ==ct== [WARN] │ warn   : null this pointer           │\n"
        "|72292| ==ct== [WARN] │ warn   : no vptr                     │\n"
        "|72292| ==ct== [WARN] └──────────────────────────────────────┘\n";

    void VtableWarningBoxIsAFinding()
    {
        const std::vector<Finding> findings = ParseFindings(kNullThisBox);
        Expect(findings.size() == 1, "vtable null this: one finding");
        if (findings.size() != 1)
        {
            return;
        }
        Expect(findings[0].rule == "vtable-null-this", "vtable null this: most specific rule");
        Expect(findings[0].cwe == "CWE-476", "vtable null this: CWE-476");
        Expect(findings[0].severity == Severity::Error, "vtable null this: error");
        Expect(findings[0].message == "null this pointer; no vptr",
               "vtable null this: message lists the box's warnings");
        Expect(IsAt(findings[0].location, "ct_vtable_diag_null.cpp", 7, 5),
               "vtable null this: site");
        Expect(!findings[0].allocation, "vtable null this: no allocation site");
    }

    void VtableInfoBoxIsTracing()
    {
        const std::vector<Finding> findings =
            ParseFindings("|1| ==ct== [INFO] [VCALL]\n"
                          "|1| ==ct== [INFO] ┌─ vcall ───────────────────────────────┐\n"
                          "|1| ==ct== [INFO] │ site      : ct_vtable_basic.cpp:24:20 │\n"
                          "|1| ==ct== [INFO] │ type      : Derived                   │\n"
                          "|1| ==ct== [INFO] │ vmod      : main                      │\n"
                          "|1| ==ct== [INFO] └───────────────────────────────────────┘\n");
        Expect(findings.empty(), "vtable info box: no finding");
    }

    void VcallBoxJoinsWrappedValues()
    {
        const std::vector<Finding> findings = ParseFindings(
            "|1| ==ct== [WARN] [VCALL]\n"
            "|1| ==ct== [WARN] ┌─ vcall ──────────────────────────────────────────────┐\n"
            "|1| ==ct== [WARN] │ site      : ct_vtable_diag_mismatch.cpp:24:5         │\n"
            "|1| ==ct== [WARN] │ type      : Derived                                  │\n"
            "|1| ==ct== [WARN] │ static    : Base                                     │\n"
            "|1| ==ct== [WARN] │ warn      : static!=dynamic type                     │\n"
            "|1| ==ct== [WARN] │ warn      : module mismatch: vtable=main target=libs │\n"
            "|1| ==ct== [WARN] │           : ystem_c.dylib                            │\n"
            "|1| ==ct== [WARN] └──────────────────────────────────────────────────────┘\n");
        Expect(findings.size() == 1, "vcall mismatch: one finding");
        if (findings.size() != 1)
        {
            return;
        }
        Expect(findings[0].rule == "vtable-type-mismatch", "vcall mismatch: rule");
        Expect(findings[0].cwe == "CWE-843", "vcall mismatch: CWE-843");
        Expect(findings[0].severity == Severity::Warning, "vcall mismatch: warning");
        Expect(findings[0].message ==
                   "static!=dynamic type; module mismatch: vtable=main target=libsystem_c.dylib",
               "vcall mismatch: wrapped value joined");
        Expect(IsAt(findings[0].location, "ct_vtable_diag_mismatch.cpp", 24, 5),
               "vcall mismatch: site");
    }

    [[nodiscard]] std::vector<Finding> WarnBox(std::string_view tag, std::string_view warnings)
    {
        std::string output;
        output += "|1| ==ct== [WARN] [" + std::string(tag) + "]\n";
        output += "|1| ==ct== [WARN] ┌─ box ──────┐\n";
        output += "|1| ==ct== [WARN] │ site : a.cpp:22:5 │\n";
        for (std::size_t start = 0; start < warnings.size();)
        {
            std::size_t end = warnings.find('|', start);
            if (end == std::string_view::npos)
            {
                end = warnings.size();
            }
            output +=
                "|1| ==ct== [WARN] │ warn : " + std::string(warnings.substr(start, end - start)) +
                " │\n";
            start = end + 1;
        }
        output += "|1| ==ct== [WARN] └────────────┘\n";
        return ParseFindings(output);
    }

    void VtableRulesByWarning()
    {
        struct Case
        {
            std::string_view warnings;
            std::string_view rule;
            std::string_view cwe;
            Severity severity;
        };
        constexpr Case cases[] = {
            {"vptr on freed object", "vtable-use-after-free", "CWE-416", Severity::Error},
            {"missing typeinfo|vtable resolve failed", "vtable-corrupted", "CWE-843",
             Severity::Error},
            {"no vptr", "vtable-corrupted", "CWE-843", Severity::Error},
            {"target in non-exec memory", "vcall-invalid-target", "CWE-843", Severity::Error},
            {"static!=dynamic type", "vtable-type-mismatch", "CWE-843", Severity::Warning},
            {"module mismatch: vtable=main target=libs", "vtable-type-mismatch", "CWE-843",
             Severity::Warning},
            // The most specific warning decides.
            {"no vptr|vptr on freed object", "vtable-use-after-free", "CWE-416", Severity::Error},
            {"static!=dynamic type|target in non-exec memory", "vcall-invalid-target", "CWE-843",
             Severity::Error},
        };
        for (const Case& c : cases)
        {
            const std::vector<Finding> findings = WarnBox("VCALL", c.warnings);
            std::string message(c.warnings);
            for (std::size_t bar = message.find('|'); bar != std::string::npos;
                 bar = message.find('|'))
            {
                message.replace(bar, 1, "; ");
            }
            const std::string what = "vtable rule for \"" + message + "\"";
            Expect(findings.size() == 1 && findings[0].rule == c.rule && findings[0].cwe == c.cwe &&
                       findings[0].severity == c.severity && findings[0].message == message &&
                       IsAt(findings[0].location, "a.cpp", 22, 5),
                   what);
        }
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
    VtableWarningBoxIsAFinding();
    VtableInfoBoxIsTracing();
    VcallBoxJoinsWrappedValues();
    VtableRulesByWarning();
    if (failures != 0)
    {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "findings_test: all checks passed\n";
    return 0;
}
