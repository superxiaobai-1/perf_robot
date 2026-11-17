#pragma once

#include "perf_robot/types.hpp"

#include <cstddef>
#include <deque>
#include <vector>

namespace perf_robot {

// Bounded in-memory ring: push is O(1), and normal operation performs no I/O.
class FlightRecorder {
 public:
  explicit FlightRecorder(std::size_t capacity);

  void push(Sample sample);
  std::vector<Sample> snapshot() const;
  std::size_t size() const noexcept { return samples_.size(); }
  std::size_t capacity() const noexcept { return capacity_; }
  std::uint64_t overwritten() const noexcept { return overwritten_; }

 private:
  std::size_t capacity_;
  std::deque<Sample> samples_;
  std::uint64_t overwritten_{0};
};

}  // namespace perf_robot
