#pragma once

#include "perf_robot/incident_repository.hpp"

#include <thread>

namespace perf_robot {

// Persists one incident at a time on a worker thread so that disk I/O never
// runs on the Agent's 10 Hz epoll thread. Completion is signalled through an
// eventfd that the Agent watches alongside its other descriptors.
class AsyncIncidentWriter {
 public:
  explicit AsyncIncidentWriter(const IncidentRepository &repository);
  ~AsyncIncidentWriter();

  AsyncIncidentWriter(const AsyncIncidentWriter &) = delete;
  AsyncIncidentWriter &operator=(const AsyncIncidentWriter &) = delete;

  // Starts persisting the incident. Returns false only if a write is already
  // in progress. If a worker thread cannot be created, the incident is saved
  // synchronously as a last resort and completion is still signalled.
  bool start(Incident incident) noexcept;
  bool active() const noexcept { return active_; }
  int completion_fd() const noexcept { return completion_fd_; }
  // Call when completion_fd() is readable. Joins the worker; returns true if
  // a write finished.
  bool consume_completion() noexcept;
  // Blocks until any in-progress write has finished (used during shutdown).
  void wait() noexcept;

 private:
  void write(const Incident &incident) noexcept;
  void signal_completion() noexcept;

  const IncidentRepository &repository_;
  int completion_fd_{-1};
  Incident pending_;
  std::thread worker_;
  bool active_{false};
};

}  // namespace perf_robot
