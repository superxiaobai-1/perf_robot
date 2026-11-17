#pragma once

#include "perf_robot/collector.hpp"
#include "perf_robot/burst_collector.hpp"
#include "perf_robot/config.hpp"
#include "perf_robot/flight_recorder.hpp"
#include "perf_robot/incident_repository.hpp"
#include "perf_robot/incident_writer.hpp"
#include "perf_robot/resource_guard.hpp"
#include "perf_robot/state_machine.hpp"
#include "perf_robot/trigger_policy.hpp"

#include <memory>
#include <vector>

namespace perf_robot {

class Agent {
 public:
  explicit Agent(Config config);
  ~Agent();

  Agent(const Agent &) = delete;
  Agent &operator=(const Agent &) = delete;

  void add_collector(std::unique_ptr<ICollector> collector);
  void add_burst_collector(std::unique_ptr<IBurstCollector> collector);
  int run();

 private:
  void collect_once();
  void trigger_capture(const char *reason);
  void seal_capture();
  void start_incident_write();
  void finish_seal();
  std::string status_json() const;
  void create_runtime_files();
  void remove_pid_file() noexcept;

  Config config_;
  FlightRecorder recorder_;
  IncidentRepository repository_;
  AsyncIncidentWriter incident_writer_;
  ResourceGuard resource_guard_;
  TriggerPolicy trigger_policy_;
  BurstManager burst_manager_;
  CaptureStateMachine state_machine_;
  std::vector<std::unique_ptr<ICollector>> collectors_;
  std::vector<Sample> post_trigger_;
  std::vector<Sample> pre_trigger_;
  std::uint64_t sequence_{0};
  std::uint64_t missed_deadlines_{0};
  std::uint64_t rejected_captures_{0};
  std::uint64_t trigger_monotonic_ns_{0};
  std::uint64_t trigger_realtime_ns_{0};
  std::string trigger_reason_;
  std::string incident_id_;
  std::filesystem::path burst_artifact_root_;
  bool stop_requested_{false};
  bool burst_worker_active_{false};
};

}  // namespace perf_robot
