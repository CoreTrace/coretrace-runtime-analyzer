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

    constexpr std::string_view kDriver = R"(,
      "tool": {
        "driver": {
          "informationUri": "https://github.com/CoreTrace/coretrace-runtime-analyzer",
          "name": "coretrace-runtime-analyzer",
          "rules": )";

    constexpr std::string_view kTail = R"(
        }
      }
    }
  ],
  "version": "2.1.0"
}
)";

    // The log of `results`, its driver listing `rules`.
    [[nodiscard]] std::string Log(std::string_view results, std::string_view rules = "[]")
    {
        return std::string(kHead) + std::string(results) + std::string(kDriver) +
               std::string(rules) + std::string(kTail);
    }

    void EmptyLog()
    {
        Expect(Sarif({}) == Log("[]"), "no finding: empty results and rules arrays");
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
            "confidence": "high",
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
      ])",
                                         R"([
            {
              "fullDescription": {
                "text": "A read or a write past the bounds of a heap allocation, observed while the program ran."
              },
              "id": "heap-buffer-overflow",
              "shortDescription": {
                "text": "Heap buffer overflow"
              }
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
            "confidence": "high",
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
      ])",
                                         R"([
            {
              "fullDescription": {
                "text": "Heap memory the program allocated and had not freed when it ended."
              },
              "id": "memory-leak",
              "shortDescription": {
                "text": "Memory leak"
              }
            }
          ])");
        Expect(Sarif({finding}) == expected,
               "one warning: no locations, no column when the runtime gave none");
    }

    // The one run of the SARIF log `text`, or an empty object when the log has none.
    [[nodiscard]] llvm::json::Object RunOf(std::string_view text)
    {
        llvm::Expected<llvm::json::Value> log = llvm::json::parse(text);
        if (!log)
        {
            llvm::consumeError(log.takeError());
            return {};
        }
        const llvm::json::Object* root = log->getAsObject();
        const llvm::json::Array* runs = root != nullptr ? root->getArray("runs") : nullptr;
        const llvm::json::Object* run =
            runs != nullptr && !runs->empty() ? (*runs)[0].getAsObject() : nullptr;
        return run != nullptr ? *run : llvm::json::Object{};
    }

    // The one run of the log Sarif() writes for `findings`.
    [[nodiscard]] llvm::json::Object Run(const std::vector<Finding>& findings)
    {
        return RunOf(Sarif(findings));
    }

    // A log of the wrong shape has no run, so the checks on it fail instead of crashing.
    void MalformedLogHasNoRun()
    {
        for (const std::string_view text : {R"([])", R"({"runs": [1]})"})
        {
            Expect(RunOf(text).empty(), std::string(text) + ": no run");
        }
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

    // How sure a finding is: a fault observed while the program ran is certain; a vtable type
    // mismatch may be a legitimate cast; an unrecognized vtable report says little.
    void EveryFindingHasAConfidence()
    {
        const std::vector<std::pair<std::string, std::string>> expected = {
            {"heap-buffer-overflow", "high"},
            {"memory-leak", "high"},
            {"vtable-type-mismatch", "medium"},
            {"vtable-diagnostic", "low"}};
        for (const auto& [rule, confidence] : expected)
        {
            llvm::json::Object run = Run({OfRule(rule)});
            const llvm::json::Array* results = run.getArray("results");
            const llvm::json::Object* result =
                results != nullptr && results->size() == 1 ? (*results)[0].getAsObject() : nullptr;
            const llvm::json::Object* properties =
                result != nullptr ? result->getObject("properties") : nullptr;
            Expect(properties != nullptr && properties->getString("confidence") == confidence,
                   rule + ": confidence " + confidence);
        }
    }
} // namespace

int main()
{
    EmptyLog();
    FindingWithLocations();
    WarningWithoutLocation();
    MalformedLogHasNoRun();
    EveryRuleIsDescribed();
    EveryFindingHasAConfidence();
    return unittests::Finish("sarif_test");
}
