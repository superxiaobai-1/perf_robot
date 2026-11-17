#include "perf_robot/resource_guard.hpp"

#include <system_error>

namespace perf_robot {

ResourceGuard::ResourceGuard(std::filesystem::path incident_root, unsigned min_free_disk_mb)
    : incident_root_(std::move(incident_root)),
      min_free_bytes_(static_cast<std::uintmax_t>(min_free_disk_mb) * 1024U * 1024U) {}

bool ResourceGuard::allow_capture(std::string &reason) const {
  std::error_code error;
  auto probe = incident_root_;
  while (!probe.empty() && !std::filesystem::exists(probe, error)) probe = probe.parent_path();
  if (probe.empty()) probe = "/";
  const auto info = std::filesystem::space(probe, error);
  if (error) {
    reason = "cannot query incident filesystem space: " + error.message();
    return false;
  }
  if (info.available < min_free_bytes_) {
    reason = "incident filesystem free space below configured minimum";
    return false;
  }
  return true;
}

}  // namespace perf_robot
