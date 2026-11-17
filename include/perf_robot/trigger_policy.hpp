#pragma once

#include "perf_robot/config.hpp"
#include "perf_robot/types.hpp"

#include <optional>
#include <string>

namespace perf_robot {

// Consecutive-hit policy suppresses one-sample spikes while keeping evaluation
// allocation-free on the non-triggering path.
class TriggerPolicy {
 public:
  explicit TriggerPolicy(const Config &config);

  std::optional<std::string> evaluate(const Sample &sample);
  void reset() noexcept;

 private:
  unsigned update_counter(bool hit, unsigned &counter);

  bool enabled_;
  double cpu_percent_;
  double memory_available_bytes_;
  double thermal_celsius_;
  unsigned consecutive_samples_;
  unsigned cpu_hits_{0};
  unsigned memory_hits_{0};
  unsigned thermal_hits_{0};
};

}  // namespace perf_robot
