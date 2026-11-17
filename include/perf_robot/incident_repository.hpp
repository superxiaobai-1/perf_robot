#pragma once

#include "perf_robot/types.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace perf_robot {

struct Incident {
  std::string id;
  std::string trigger;
  std::uint64_t trigger_monotonic_ns{0};
  std::uint64_t trigger_realtime_ns{0};
  std::uint64_t overwritten_samples{0};
  std::filesystem::path artifact_root;
  std::vector<Sample> pre_trigger;
  std::vector<Sample> post_trigger;
};

class IncidentRepository {
 public:
  explicit IncidentRepository(std::filesystem::path root);

  std::filesystem::path save(const Incident &incident) const;

 private:
  std::filesystem::path root_;
};

}  // namespace perf_robot
