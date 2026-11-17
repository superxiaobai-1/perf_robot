#pragma once

#include "perf_robot/collector.hpp"

#include <string>
#include <vector>

namespace perf_robot {

class ProcessCollector final : public ICollector {
 public:
  explicit ProcessCollector(std::vector<int> pids);

  std::string_view name() const noexcept override { return "process"; }
  void collect(Sample &sample) override;

 private:
  struct Target {
    int pid;
    std::string prefix;
  };
  std::vector<Target> targets_;
};

}  // namespace perf_robot
