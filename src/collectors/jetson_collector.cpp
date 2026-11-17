#include "perf_robot/jetson_collector.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <system_error>

namespace perf_robot {
namespace {

std::string read_text(const std::filesystem::path &path) {
  std::ifstream input(path);
  std::string value;
  std::getline(input, value);
  return value;
}

std::string sanitize(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return std::isalnum(ch) ? static_cast<char>(std::tolower(ch)) : '_';
  });
  return value;
}

bool contains_gpu(const std::string &value) {
  auto lower = value;
  std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return lower.find("gpu") != std::string::npos || lower.find("17000000") != std::string::npos;
}

}  // namespace

JetsonCollector::JetsonCollector() {
  discover_thermal();
  discover_gpu_devfreq();
}

void JetsonCollector::discover_thermal() {
  const std::filesystem::path root("/sys/class/thermal");
  std::error_code error;
  for (std::filesystem::directory_iterator it(root, error), end; !error && it != end; it.increment(error)) {
    const auto type_path = it->path() / "type";
    const auto temp_path = it->path() / "temp";
    if (!std::filesystem::exists(type_path, error) || !std::filesystem::exists(temp_path, error)) continue;
    const auto type = sanitize(read_text(type_path));
    if (!type.empty()) metrics_.push_back({"thermal." + type + ".celsius", temp_path, 0.001, false});
  }
}

void JetsonCollector::discover_gpu_devfreq() {
  const std::filesystem::path root("/sys/class/devfreq");
  std::error_code error;
  for (std::filesystem::directory_iterator it(root, error), end; !error && it != end; it.increment(error)) {
    const auto name = it->path().filename().string();
    if (!contains_gpu(name)) continue;
    const auto cur_freq = it->path() / "cur_freq";
    const auto load = it->path() / "load";
    if (std::filesystem::exists(cur_freq, error)) {
      metrics_.push_back({"gpu.frequency_hz", cur_freq, 1.0, false});
    }
    if (std::filesystem::exists(load, error)) {
      metrics_.push_back({"gpu.busy_percent", load, 1.0, true});
    }
    break;
  }
}

void JetsonCollector::collect(Sample &sample) {
  sample.values["platform.sysfs_metric_count"] = static_cast<double>(metrics_.size());
  for (const auto &metric : metrics_) {
    std::ifstream input(metric.path);
    double value = 0.0;
    if (!(input >> value)) continue;
    if (metric.gpu_load && value > 100.0) value /= 10.0;
    sample.values[metric.key] = value * metric.scale;
  }
}

}  // namespace perf_robot
