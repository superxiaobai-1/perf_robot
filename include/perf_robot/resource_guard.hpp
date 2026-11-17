#pragma once

#include <filesystem>
#include <string>

namespace perf_robot {

class ResourceGuard {
 public:
  ResourceGuard(std::filesystem::path incident_root, unsigned min_free_disk_mb);

  bool allow_capture(std::string &reason) const;

 private:
  std::filesystem::path incident_root_;
  std::uintmax_t min_free_bytes_;
};

}  // namespace perf_robot
