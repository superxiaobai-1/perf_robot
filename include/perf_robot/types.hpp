#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace perf_robot {

using SteadyTime = std::chrono::steady_clock::time_point;

enum class CaptureState {
  Normal,
  Capturing,
  Sealing,
  Cooldown,
};

struct Sample {
  std::uint64_t sequence{0};
  std::int64_t monotonic_ns{0};
  std::int64_t realtime_ns{0};
  std::unordered_map<std::string, double> values;
};

const char *to_string(CaptureState state) noexcept;

}  // namespace perf_robot
