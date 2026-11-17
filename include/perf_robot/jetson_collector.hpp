#pragma once

#include "perf_robot/collector.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace perf_robot {

// Reads Jetson thermal and GPU devfreq sysfs files. Discovery happens once at
// construction; collect() never recursively scans sysfs.
class JetsonCollector final : public ICollector {
 public:
  JetsonCollector();

  std::string_view name() const noexcept override { return "jetson"; }
  void collect(Sample &sample) override;
  std::size_t discovered_metric_count() const noexcept { return metrics_.size(); }

 private:
  struct MetricFile {
    std::string key;
    std::filesystem::path path;
    double scale;
    bool gpu_load;
  };

  void discover_thermal();
  void discover_gpu_devfreq();
  std::vector<MetricFile> metrics_;
};

}  // namespace perf_robot
