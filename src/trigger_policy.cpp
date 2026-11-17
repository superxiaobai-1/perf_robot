#include "perf_robot/trigger_policy.hpp"

#include <algorithm>

namespace perf_robot {
namespace {

std::optional<double> value_of(const Sample &sample, const char *key) {
  const auto found = sample.values.find(key);
  if (found == sample.values.end()) return std::nullopt;
  return found->second;
}

}  // namespace

TriggerPolicy::TriggerPolicy(const Config &config)
    : enabled_(config.auto_trigger_enabled),
      cpu_percent_(config.cpu_trigger_percent),
      memory_available_bytes_(static_cast<double>(config.memory_available_trigger_mb) * 1024.0 * 1024.0),
      thermal_celsius_(config.thermal_trigger_celsius),
      consecutive_samples_(config.trigger_consecutive_samples) {}

unsigned TriggerPolicy::update_counter(bool hit, unsigned &counter) {
  counter = hit ? std::min(counter + 1, consecutive_samples_) : 0;
  return counter;
}

void TriggerPolicy::reset() noexcept {
  cpu_hits_ = 0;
  memory_hits_ = 0;
  thermal_hits_ = 0;
}

std::optional<std::string> TriggerPolicy::evaluate(const Sample &sample) {
  if (!enabled_) return std::nullopt;

  const auto cpu = value_of(sample, "cpu.busy_percent");
  if (update_counter(cpu && *cpu >= cpu_percent_, cpu_hits_) >= consecutive_samples_) {
    cpu_hits_ = 0;
    return "auto-high-cpu";
  }

  const auto memory = value_of(sample, "memory.available_bytes");
  if (update_counter(memory && *memory <= memory_available_bytes_, memory_hits_) >= consecutive_samples_) {
    memory_hits_ = 0;
    return "auto-low-memory";
  }

  bool thermal_hit = false;
  for (const auto &[key, value] : sample.values) {
    if (key.rfind("thermal.", 0) == 0 && value >= thermal_celsius_) {
      thermal_hit = true;
      break;
    }
  }
  if (update_counter(thermal_hit, thermal_hits_) >= consecutive_samples_) {
    thermal_hits_ = 0;
    return "auto-high-temperature";
  }
  return std::nullopt;
}

}  // namespace perf_robot
