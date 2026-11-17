#pragma once

#include "perf_robot/types.hpp"

#include <chrono>

namespace perf_robot {

class CaptureStateMachine {
 public:
  CaptureState state() const noexcept { return state_; }
  bool begin_capture(SteadyTime now, std::chrono::seconds duration);
  bool capture_expired(SteadyTime now) const noexcept;
  void begin_sealing();
  void begin_cooldown(SteadyTime now, std::chrono::seconds duration);
  bool update_cooldown(SteadyTime now);

 private:
  CaptureState state_{CaptureState::Normal};
  SteadyTime deadline_{};
};

}  // namespace perf_robot
