#pragma once

#include "perf_robot/types.hpp"

#include <string_view>

namespace perf_robot {

// Strategy port. Future ROS 2, GPU and eBPF adapters implement this contract.
class ICollector {
 public:
  virtual ~ICollector() = default;
  virtual std::string_view name() const noexcept = 0;
  virtual void collect(Sample &sample) = 0;
};

}  // namespace perf_robot
