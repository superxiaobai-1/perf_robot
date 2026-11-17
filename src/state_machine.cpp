#include "perf_robot/state_machine.hpp"

#include <stdexcept>

namespace perf_robot {

const char *to_string(CaptureState state) noexcept {
  switch (state) {
    case CaptureState::Normal: return "NORMAL";
    case CaptureState::Capturing: return "CAPTURING";
    case CaptureState::Sealing: return "SEALING";
    case CaptureState::Cooldown: return "COOLDOWN";
  }
  return "UNKNOWN";
}

bool CaptureStateMachine::begin_capture(SteadyTime now, std::chrono::seconds duration) {
  if (state_ != CaptureState::Normal) return false;
  state_ = CaptureState::Capturing;
  deadline_ = now + duration;
  return true;
}

bool CaptureStateMachine::capture_expired(SteadyTime now) const noexcept {
  return state_ == CaptureState::Capturing && now >= deadline_;
}

void CaptureStateMachine::begin_sealing() {
  if (state_ != CaptureState::Capturing) throw std::logic_error("invalid sealing transition");
  state_ = CaptureState::Sealing;
}

void CaptureStateMachine::begin_cooldown(SteadyTime now, std::chrono::seconds duration) {
  if (state_ != CaptureState::Sealing) throw std::logic_error("invalid cooldown transition");
  state_ = CaptureState::Cooldown;
  deadline_ = now + duration;
}

bool CaptureStateMachine::update_cooldown(SteadyTime now) {
  if (state_ == CaptureState::Cooldown && now >= deadline_) {
    state_ = CaptureState::Normal;
    return true;
  }
  return false;
}

}  // namespace perf_robot
