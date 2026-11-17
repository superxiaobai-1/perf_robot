#pragma once

#include "perf_robot/collector.hpp"

#include <cstdint>

namespace perf_robot {

class ProcCollector final : public ICollector {
 public:
  std::string_view name() const noexcept override { return "proc"; }
  void collect(Sample &sample) override;

 private:
  std::uint64_t previous_total_{0};
  std::uint64_t previous_idle_{0};
  bool have_cpu_baseline_{false};
};

}  // namespace perf_robot
