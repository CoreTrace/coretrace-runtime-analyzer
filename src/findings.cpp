// SPDX-License-Identifier: Apache-2.0
#include "findings.hpp"

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_os_ostream.h>

#include <charconv>
#include <filesystem>
#include <optional>
#include <utility>

namespace coretrace::runtime_analyzer
{
    namespace
    {
        // A runtime bounds report ("ct: <kind> WRITE of size 4") and its CWE by access.
        struct BoundsReport
        {
            std::string_view kind;
            std::string_view write_cwe;
            std::string_view read_cwe;
        };

        constexpr BoundsReport kBoundsReports[] = {
            {"heap-buffer-overflow", "CWE-122", "CWE-125"},
            {"stack-buffer-overflow", "CWE-121", "CWE-125"},
            {"heap-use-after-free", "CWE-416", "CWE-416"},
        };

        [[nodiscard]] bool Contains(std::string_view haystack, std::string_view needle)
        {
            return haystack.find(needle) != std::string_view::npos;
        }

        // The value of a "key=value" field of a report line, up to the next space.
        [[nodiscard]] std::optional<std::string_view> Field(std::string_view line,
                                                            std::string_view key)
        {
            for (std::size_t at = line.find(key); at != std::string_view::npos;
                 at = line.find(key, at + 1))
            {
                const std::size_t start = at + key.size();
                if ((at == 0 || line[at - 1] == ' ') && start < line.size() && line[start] == '=')
                {
                    const std::string_view value = line.substr(start + 1);
                    return value.substr(0, value.find(' '));
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] std::string ResolveSource(std::string_view name,
                                                const std::vector<std::string>& sources)
        {
            const std::string* match = nullptr;
            for (const std::string& source : sources)
            {
                if (std::filesystem::path(source).filename() == name)
                {
                    if (match != nullptr)
                    {
                        return std::string(name); // ambiguous: keep the runtime's name
                    }
                    match = &source;
                }
            }
            return match != nullptr ? *match : std::string(name);
        }

        // Removes a trailing ":<number>" from `site` into `value`.
        [[nodiscard]] bool TakeNumber(std::string_view& site, unsigned& value)
        {
            const std::size_t colon = site.rfind(':');
            if (colon == std::string_view::npos)
            {
                return false;
            }
            const char* first = site.data() + colon + 1;
            const char* last = site.data() + site.size();
            const auto [end, error] = std::from_chars(first, last, value);
            if (first == last || error != std::errc{} || end != last)
            {
                return false;
            }
            site = site.substr(0, colon);
            return true;
        }

        // A runtime site, "file:line[:column]"; nothing for "<unknown>".
        [[nodiscard]] std::optional<SourceLocation>
        ParseSite(std::string_view site, const std::vector<std::string>& sources)
        {
            SourceLocation location;
            unsigned last = 0;
            if (!TakeNumber(site, last))
            {
                return std::nullopt;
            }
            unsigned line = 0;
            if (TakeNumber(site, line))
            {
                location.line = line;
                location.column = last;
            }
            else
            {
                location.line = last;
            }
            if (site.empty() || location.line == 0)
            {
                return std::nullopt;
            }
            location.file = ResolveSource(site, sources);
            return location;
        }

        [[nodiscard]] std::optional<Finding> BoundsFinding(std::string_view line)
        {
            for (const BoundsReport& report : kBoundsReports)
            {
                const std::size_t at = line.find("ct: " + std::string(report.kind) + " ");
                if (at == std::string_view::npos)
                {
                    continue;
                }
                Finding finding;
                finding.rule = report.kind;
                finding.message = line.substr(at + 4);
                const bool write = Contains(finding.message, " WRITE ");
                finding.cwe = write ? report.write_cwe : report.read_cwe;
                return finding;
            }
            return std::nullopt;
        }

        [[nodiscard]] llvm::json::Object Location(const SourceLocation& location)
        {
            llvm::json::Object region{{"startLine", location.line}};
            if (location.column != 0)
            {
                region["startColumn"] = location.column;
            }
            return llvm::json::Object{
                {"physicalLocation",
                 llvm::json::Object{
                     {"artifactLocation", llvm::json::Object{{"uri", location.file}}},
                     {"region", std::move(region)},
                 }},
            };
        }
    } // namespace

    std::vector<Finding> ParseFindings(std::string_view output,
                                       const std::vector<std::string>& sources)
    {
        std::vector<Finding> findings;
        bool in_bounds_report = false;
        std::size_t start = 0;
        while (start < output.size())
        {
            std::size_t end = output.find('\n', start);
            if (end == std::string_view::npos)
            {
                end = output.size();
            }
            const std::string_view line = output.substr(start, end - start);
            start = end + 1;

            // A bounds report goes on over indented lines that carry no log prefix.
            if (in_bounds_report && line.starts_with("  "))
            {
                if (const auto site = Field(line, "access"))
                {
                    findings.back().location = ParseSite(*site, sources);
                }
                if (const auto site = Field(line, "alloc_site"))
                {
                    findings.back().allocation = ParseSite(*site, sources);
                }
                continue;
            }

            in_bounds_report = false;
            if (std::optional<Finding> finding = BoundsFinding(line))
            {
                findings.push_back(std::move(*finding));
                in_bounds_report = true;
            }
            else if (Contains(line, "(double free)"))
            {
                findings.push_back({"double-free", "CWE-415", Severity::Error, "double free",
                                    std::nullopt, std::nullopt});
            }
            else if (Contains(line, "ct: leak ptr="))
            {
                const auto size = Field(line, "size");
                std::string message = "memory leak";
                if (size)
                {
                    message += " of " + std::string(*size) + " bytes";
                }
                findings.push_back({"memory-leak", "CWE-401", Severity::Warning, std::move(message),
                                    std::nullopt, std::nullopt});
            }
        }
        return findings;
    }

    void WriteSarif(std::ostream& out, const std::vector<Finding>& findings)
    {
        llvm::json::Array results;
        for (const Finding& finding : findings)
        {
            llvm::json::Object result{
                {"ruleId", finding.rule},
                {"level", finding.severity == Severity::Error ? "error" : "warning"},
                {"message", llvm::json::Object{{"text", finding.message}}},
                {"properties", llvm::json::Object{{"cwe", finding.cwe}}},
            };
            if (finding.location)
            {
                result["locations"] = llvm::json::Array{Location(*finding.location)};
            }
            if (finding.allocation)
            {
                llvm::json::Object allocated = Location(*finding.allocation);
                allocated["id"] = 0;
                allocated["message"] = llvm::json::Object{{"text", "allocated here"}};
                result["relatedLocations"] = llvm::json::Array{std::move(allocated)};
            }
            results.push_back(std::move(result));
        }

        const llvm::json::Value log = llvm::json::Object{
            {"version", "2.1.0"},
            {"$schema", "https://json.schemastore.org/sarif-2.1.0.json"},
            {"runs",
             llvm::json::Array{llvm::json::Object{
                 {"tool",
                  llvm::json::Object{
                      {"driver",
                       llvm::json::Object{
                           {"name", "coretrace-runtime-analyzer"},
                           {"informationUri",
                            "https://github.com/CoreTrace/coretrace-runtime-analyzer"},
                       }},
                  }},
                 {"results", std::move(results)},
             }}},
        };
        llvm::raw_os_ostream stream(out);
        stream << llvm::formatv("{0:2}", log) << '\n';
    }
} // namespace coretrace::runtime_analyzer
