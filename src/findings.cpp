// SPDX-License-Identifier: Apache-2.0
#include "findings.hpp"

#include <charconv>
#include <optional>
#include <string>
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

        // A vtable diagnostic box's warning and the finding it names. The box's rule is the
        // earliest entry here matched by any of its warnings, so the most specific one wins.
        struct VtableRule
        {
            std::string_view warning; // matched as a prefix of the box's "warn" values
            std::string_view rule;
            std::string_view cwe;
            Severity severity;
        };

        constexpr VtableRule kVtableRules[] = {
            {"null this pointer", "vtable-null-this", "CWE-476", Severity::Error},
            {"vptr on freed object", "vtable-use-after-free", "CWE-416", Severity::Error},
            {"vtable resolve failed", "vtable-corrupted", "CWE-843", Severity::Error},
            {"no vptr", "vtable-corrupted", "CWE-843", Severity::Error},
            {"missing typeinfo", "vtable-corrupted", "CWE-843", Severity::Error},
            {"target in non-exec memory", "vcall-invalid-target", "CWE-843", Severity::Error},
            {"static!=dynamic type", "vtable-type-mismatch", "CWE-843", Severity::Warning},
            {"module mismatch: ", "vtable-type-mismatch", "CWE-843", Severity::Warning},
        };

        // A box the runtime logged at WARN level: "[VTABLE]" or "[VCALL]", then "│ label : value │"
        // rows between "┌" and "└". A row with an empty label continues the previous value.
        struct DiagnosticBox
        {
            std::vector<std::pair<std::string, std::string>> rows;

            [[nodiscard]] static bool Opens(std::string_view line)
            {
                return line.find("[WARN]") != std::string_view::npos &&
                       (line.ends_with("[VTABLE]") || line.ends_with("[VCALL]"));
            }

            [[nodiscard]] static bool Closes(std::string_view line)
            {
                return line.find("└") != std::string_view::npos;
            }

            void AddRow(std::string_view line)
            {
                constexpr std::string_view kOpen = "│ ";
                constexpr std::string_view kClose = " │";
                const std::size_t open = line.find(kOpen);
                const std::size_t close = line.rfind(kClose);
                if (open == std::string_view::npos || close == std::string_view::npos ||
                    close < open + kOpen.size())
                {
                    return;
                }
                const std::string_view text =
                    line.substr(open + kOpen.size(), close - open - kOpen.size());
                const std::size_t colon = text.find(':');
                if (colon == std::string_view::npos)
                {
                    return;
                }
                const std::string label = Trim(text.substr(0, colon));
                const std::string value = Trim(text.substr(colon + 1));
                if (label.empty() && !rows.empty())
                {
                    rows.back().second += value;
                }
                else
                {
                    rows.emplace_back(label, value);
                }
            }

            [[nodiscard]] std::optional<Finding> ToFinding() const
            {
                Finding finding;
                const VtableRule* rule = nullptr;
                for (const auto& [label, value] : rows)
                {
                    if (label == "site")
                    {
                        finding.location = ParseSite(value);
                        continue;
                    }
                    if (label != "warn")
                    {
                        continue;
                    }
                    if (!finding.message.empty())
                    {
                        finding.message += "; ";
                    }
                    finding.message += value;
                    for (const VtableRule& candidate : kVtableRules)
                    {
                        if (value.starts_with(candidate.warning))
                        {
                            if (rule == nullptr || &candidate < rule)
                            {
                                rule = &candidate;
                            }
                            break;
                        }
                    }
                }
                if (finding.message.empty())
                {
                    return std::nullopt;
                }
                finding.rule = rule != nullptr ? rule->rule : "vtable-diagnostic";
                finding.cwe = rule != nullptr ? rule->cwe : "CWE-843";
                finding.severity = rule != nullptr ? rule->severity : Severity::Warning;
                return finding;
            }

          private:
            [[nodiscard]] static std::string Trim(std::string_view text)
            {
                const std::size_t first = text.find_first_not_of(' ');
                if (first == std::string_view::npos)
                {
                    return {};
                }
                return std::string(text.substr(first, text.find_last_not_of(' ') - first + 1));
            }
        };

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
        std::optional<DiagnosticBox> box;
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

            if (box)
            {
                if (DiagnosticBox::Closes(line))
                {
                    if (std::optional<Finding> finding = box->ToFinding())
                    {
                        findings.push_back(std::move(*finding));
                    }
                    box.reset();
                }
                else
                {
                    box->AddRow(line);
                }
                continue;
            }
            if (DiagnosticBox::Opens(line))
            {
                in_bounds_report = false;
                box.emplace();
                continue;
            }

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
