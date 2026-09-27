// SPDX-License-Identifier: Apache-2.0
// Checks the SARIF writer against the exact log a consumer reads.
#include "sarif.hpp"

#include "expect.hpp"

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
} // namespace

int main()
{
    EmptyLog();
    FindingWithLocations();
    WarningWithoutLocation();
    return unittests::Finish("sarif_test");
}
