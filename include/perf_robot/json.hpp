#pragma once

#include <string>
#include <string_view>

namespace perf_robot {

// Escapes a value for use inside a JSON string literal (quotes not included).
// All control characters are escaped, so arbitrary text yields valid JSON.
std::string json_escape(std::string_view value);

}  // namespace perf_robot
