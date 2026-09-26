// SPDX-License-Identifier: Apache-2.0
#ifndef CORETRACE_RUNTIME_ANALYZER_SARIF_HPP
#define CORETRACE_RUNTIME_ANALYZER_SARIF_HPP

#include "runtime_analyzer.hpp"

#include <ostream>
#include <vector>

namespace coretrace::runtime_analyzer
{
    // Writes a SARIF 2.1.0 log with one run holding `findings`.
    void WriteSarif(std::ostream& out, const std::vector<Finding>& findings);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_SARIF_HPP
