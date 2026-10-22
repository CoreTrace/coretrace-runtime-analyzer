// SPDX-License-Identifier: Apache-2.0
// Checks the SARIF writer against the exact log a consumer reads.
#include "sarif.hpp"

#include "expect.hpp"

#include <llvm/Support/JSON.h>

#include <sstream>
#include <string>
#include <vector>

namespace
{
    using coretrace::runtime_analyzer::Finding;
    using coretrace::runtime_analyzer::Severity;
    using coretrace::runtime_analyzer::SourceLocation;
    using coretrace::runtime_analyzer::WriteSarif;
    using unittests::Expect;

    [[nodiscard]] std::string Sarif(const std::vector<Finding>& findings)
    {
        std::ostringstream out;
        WriteSarif(out, findings);
        return out.str();
    }

    constexpr std::string_view kHead = R"({
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "results": )";

    constexpr std::string_view kTail = R"(,
      "tool": {
        "driver": {
          "informationUri": "https://github.com/CoreTrace/coretrace-runtime-analyzer",
          "name": "coretrace-runtime-analyzer"
        }
      }
    }
  ],
  "version": "2.1.0"
}
)";

    [[nodiscard]] std::string Log(std::string_view results)
    {
        return std::string(kHead) + std::string(results) + std::string(kTail);
    }

    void EmptyLog()
    {
        Expect(Sarif({}) == Log("[]"), "no finding: an empty results array");
    }

    void FindingWithLocations()
    {
        Finding finding{"heap-buffer-overflow",
                        "CWE-122",
                        Severity::Error,
                        "heap-buffer-overflow WRITE of size 4",
                        SourceLocation{"a.c", 7, 15},
                        SourceLocation{"a.c", 6, 19}};
        const std::string expected = Log(R"([
        {
          "level": "error",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "a.c"
                },
                "region": {
                  "startColumn": 15,
                  "startLine": 7
                }
              }
            }
          ],
          "message": {
            "text": "heap-buffer-overflow WRITE of size 4"
          },
          "properties": {
            "cwe": "CWE-122"
          },
          "relatedLocations": [
            {
              "id": 0,
              "message": {
                "text": "allocated here"
              },
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "a.c"
                },
                "region": {
                  "startColumn": 19,
                  "startLine": 6
                }
              }
            }
          ],
          "ruleId": "heap-buffer-overflow"
        }
      ])");
        Expect(Sarif({finding}) == expected,
               "one error: location, allocation site as related location 0, rule, CWE");
    }

    void WarningWithoutLocation()
    {
        Finding finding{"memory-leak",      "CWE-401",    Severity::Warning,
                        "leak of 16 bytes", std::nullopt, SourceLocation{"a.c", 6, 0}};
        const std::string expected = Log(R"([
        {
          "level": "warning",
          "message": {
            "text": "leak of 16 bytes"
          },
          "properties": {
            "cwe": "CWE-401"
          },
          "relatedLocations": [
            {
              "id": 0,
              "message": {
                "text": "allocated here"
              },
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "a.c"
                },
                "region": {
                  "startLine": 6
                }
              }
            }
          ],
          "ruleId": "memory-leak"
        }
      ])");
        Expect(Sarif({finding}) == expected,
               "one warning: no locations, no column when the runtime gave none");
    }

    // The one run of the log Sarif() writes for `findings`.
    [[nodiscard]] llvm::json::Object Run(const std::vector<Finding>& findings)
    {
        llvm::Expected<llvm::json::Value> log = llvm::json::parse(Sarif(findings));
        if (!log)
        {
            llvm::consumeError(log.takeError());
            return {};
        }
        const llvm::json::Array* runs = log->getAsObject()->getArray("runs");
        return runs != nullptr && !runs->empty() ? *(*runs)[0].getAsObject() : llvm::json::Object{};
    }

    [[nodiscard]] Finding OfRule(std::string rule)
    {
        return Finding{std::move(rule), "CWE-0", Severity::Error, "m", std::nullopt, std::nullopt};
    }

    // A SARIF consumer (GitHub code scanning, an IDE, CoreTrace's merged log) explains a finding
    // from its rule: every rule the analyzer reports is listed once, with a title and a
    // description.
    void EveryRuleIsDescribed()
    {
        const std::vector<std::string> rules = {
            "heap-buffer-overflow",  "stack-buffer-overflow", "heap-use-after-free",
            "double-free",           "memory-leak",           "vtable-null-this",
            "vtable-use-after-free", "vtable-corrupted",      "vcall-invalid-target",
            "vtable-type-mismatch",  "vtable-diagnostic"};
        for (const std::string& rule : rules)
        {
            llvm::json::Object run = Run({OfRule(rule), OfRule(rule)});
            const llvm::json::Object* driver = run.getObject("tool") != nullptr
                                                   ? run.getObject("tool")->getObject("driver")
                                                   : nullptr;
            const llvm::json::Array* listed =
                driver != nullptr ? driver->getArray("rules") : nullptr;
            const llvm::json::Object* entry =
                listed != nullptr && listed->size() == 1 ? (*listed)[0].getAsObject() : nullptr;
            const auto text = [&](llvm::StringRef key) -> llvm::StringRef
            {
                const llvm::json::Object* message =
                    entry != nullptr ? entry->getObject(key) : nullptr;
                const std::optional<llvm::StringRef> value =
                    message != nullptr ? message->getString("text") : std::nullopt;
                return value.value_or("");
            };
            Expect(entry != nullptr && entry->getString("id") == rule &&
                       !text("shortDescription").empty() && !text("fullDescription").empty() &&
                       text("shortDescription") != rule,
                   rule + ": listed once, with a title and a description");
        }
    }
} // namespace

int main()
{
    EmptyLog();
    FindingWithLocations();
    WarningWithoutLocation();
    EveryRuleIsDescribed();
    return unittests::Finish("sarif_test");
}
