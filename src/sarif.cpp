// SPDX-License-Identifier: Apache-2.0
#include "sarif.hpp"

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_os_ostream.h>

#include <utility>

namespace coretrace::runtime_analyzer
{
    namespace
    {
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

        [[nodiscard]] llvm::json::Object Result(const Finding& finding)
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
            return result;
        }
    } // namespace

    void WriteSarif(std::ostream& out, const std::vector<Finding>& findings)
    {
        llvm::json::Array results;
        for (const Finding& finding : findings)
        {
            results.push_back(Result(finding));
        }

        llvm::json::Object driver{
            {"name", "coretrace-runtime-analyzer"},
            {"informationUri", "https://github.com/CoreTrace/coretrace-runtime-analyzer"},
        };
        llvm::json::Object run{
            {"tool", llvm::json::Object{{"driver", std::move(driver)}}},
            {"results", std::move(results)},
        };
        const llvm::json::Value log = llvm::json::Object{
            {"version", "2.1.0"},
            {"$schema", "https://json.schemastore.org/sarif-2.1.0.json"},
            {"runs", llvm::json::Array{std::move(run)}},
        };
        llvm::raw_os_ostream stream(out);
        stream << llvm::formatv("{0:2}", log) << '\n';
    }
} // namespace coretrace::runtime_analyzer
