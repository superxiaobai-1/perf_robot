#include "perf_robot/json.hpp"

#include <cstdio>

namespace perf_robot {

std::string json_escape(std::string_view value) {
  std::string output;
  output.reserve(value.size());
  for (const char ch : value) {
    switch (ch) {
      case '\\': output += "\\\\"; break;
      case '"': output += "\\\""; break;
      case '\n': output += "\\n"; break;
      case '\r': output += "\\r"; break;
      case '\t': output += "\\t"; break;
      default:
        if (static_cast<unsigned char>(ch) < 0x20) {
          char escaped[7];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x",
                        static_cast<unsigned>(static_cast<unsigned char>(ch)));
          output += escaped;
        } else {
          output += ch;
        }
        break;
    }
  }
  return output;
}

}  // namespace perf_robot
