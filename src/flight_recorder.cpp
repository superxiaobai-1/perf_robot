#include "perf_robot/flight_recorder.hpp"

#include <stdexcept>
#include <utility>

namespace perf_robot {

FlightRecorder::FlightRecorder(std::size_t capacity) : capacity_(capacity) {
  if (capacity == 0) throw std::invalid_argument("flight recorder capacity is zero");
}

void FlightRecorder::push(Sample sample) {
  if (samples_.size() == capacity_) {
    samples_.pop_front();
    ++overwritten_;
  }
  samples_.push_back(std::move(sample));
}

std::vector<Sample> FlightRecorder::snapshot() const {
  return {samples_.begin(), samples_.end()};
}

}  // namespace perf_robot
