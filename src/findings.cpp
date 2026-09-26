// SPDX-License-Identifier: Apache-2.0
#include "findings.hpp"

#include <charconv>
#include <optional>
#include <utility>

namespace coretrace::runtime_analyzer
{
    namespace
    {
        // A bounds report line, "ct: <kind> WRITE|READ of size N", and its CWE by access.
        struct BoundsRule
        {
            std::string_view kind;
            std::string_view write_cwe;
            std::string_view read_cwe;
        };

        constexpr BoundsRule kBoundsRules[] = {
            {"heap-buffer-overflow", "CWE-122", "CWE-125"},
            {"stack-buffer-overflow", "CWE-121", "CWE-125"},
            {"heap-use-after-free", "CWE-416", "CWE-416"},
        };

        // The value of a "key=value" field, up to the next space. The key must start the line
        // or follow a space, so that "site=" never matches inside "alloc_site=".
        [[nodiscard]] std::optional<std::string_view> Field(std::string_view line,
                                                            std::string_view key)
        {
            for (std::size_t at = line.find(key); at != std::string_view::npos;
                 at = line.find(key, at + 1))
            {
                const std::size_t value_start = at + key.size();
                if ((at == 0 || line[at - 1] == ' ') && value_start < line.size() &&
                    line[value_start] == '=')
                {
                    const std::string_view value = line.substr(value_start + 1);
                    return value.substr(0, value.find(' '));
                }
            }
            return std::nullopt;
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

        // A runtime site, "file:line[:column]", parsed from the right.
        [[nodiscard]] std::optional<SourceLocation> ParseSite(std::string_view site)
        {
            SourceLocation location;
            unsigned last = 0;
            if (!TakeNumber(site, last))
            {
                return std::nullopt;
            }
            if (TakeNumber(site, location.line))
            {
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
            location.file = site;
            return location;
        }

        [[nodiscard]] std::optional<Finding> BoundsFinding(std::string_view line)
        {
            for (const BoundsRule& rule : kBoundsRules)
            {
                const std::size_t at = line.find("ct: " + std::string(rule.kind) + " ");
                if (at == std::string_view::npos)
                {
                    continue;
                }
                Finding finding;
                finding.rule = rule.kind;
                finding.message = line.substr(at + 4);
                const bool write = finding.message.find(" WRITE ") != std::string::npos;
                finding.cwe = write ? rule.write_cwe : rule.read_cwe;
                return finding;
            }
            return std::nullopt;
        }

        // The site fields of a one-line report: "site=" is the faulting access and
        // "alloc_site=" the allocation.
        [[nodiscard]] Finding OneLineFinding(std::string_view line, std::string_view rule,
                                             std::string_view cwe, Severity severity,
                                             std::string message)
        {
            Finding finding;
            finding.rule = rule;
            finding.cwe = cwe;
            finding.severity = severity;
            finding.message = std::move(message);
            if (const auto site = Field(line, "site"))
            {
                finding.location = ParseSite(*site);
            }
            if (const auto site = Field(line, "alloc_site"))
            {
                finding.allocation = ParseSite(*site);
            }
            return finding;
        }
    } // namespace

    std::vector<Finding> ParseFindings(std::string_view output)
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
                    findings.back().location = ParseSite(*site);
                }
                if (const auto site = Field(line, "alloc_site"))
                {
                    findings.back().allocation = ParseSite(*site);
                }
                continue;
            }

            in_bounds_report = false;
            if (std::optional<Finding> finding = BoundsFinding(line))
            {
                findings.push_back(std::move(*finding));
                in_bounds_report = true;
            }
            else if (line.find("(double free)") != std::string_view::npos)
            {
                findings.push_back(
                    OneLineFinding(line, "double-free", "CWE-415", Severity::Error, "double free"));
            }
            else if (line.find("ct: leak ptr=") != std::string_view::npos)
            {
                std::string message = "memory leak";
                if (const auto size = Field(line, "size"))
                {
                    message += " of " + std::string(*size) + " bytes";
                }
                findings.push_back(OneLineFinding(line, "memory-leak", "CWE-401", Severity::Warning,
                                                  std::move(message)));
            }
        }
        return findings;
    }
} // namespace coretrace::runtime_analyzer
