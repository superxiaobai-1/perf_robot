#include "perf_robot/process_collector.hpp"

#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

namespace perf_robot {

ProcessCollector::ProcessCollector(std::vector<int> pids) {
  targets_.reserve(pids.size());
  for (int pid : pids) {
    if (pid == 0) pid = static_cast<int>(::getpid());
    targets_.push_back(Target{pid, "process." + std::to_string(pid) + "."});
  }
}

void ProcessCollector::collect(Sample &sample) {
  const auto page_size = static_cast<double>(::sysconf(_SC_PAGESIZE));
  const auto ticks_per_second = static_cast<double>(::sysconf(_SC_CLK_TCK));

  for (const auto &target : targets_) {
    const auto proc = std::string("/proc/") + std::to_string(target.pid);
    std::ifstream stat(proc + "/stat");
    std::string line;
    if (!std::getline(stat, line)) {
      sample.values[target.prefix + "alive"] = 0.0;
      continue;
    }

    const auto command_end = line.rfind(')');
    if (command_end == std::string::npos || command_end + 2 >= line.size()) {
      sample.values[target.prefix + "alive"] = 0.0;
      continue;
    }
    std::istringstream fields(line.substr(command_end + 2));
    std::vector<std::string> values;
    std::string value;
    while (fields >> value) values.push_back(value);
    if (values.size() < 22) {
      sample.values[target.prefix + "alive"] = 0.0;
      continue;
    }

    try {
      const auto user_ticks = std::stoull(values[11]);
      const auto system_ticks = std::stoull(values[12]);
      const auto threads = std::stoull(values[17]);
      const auto rss_pages = std::stoll(values[21]);
      sample.values[target.prefix + "alive"] = 1.0;
      sample.values[target.prefix + "cpu_seconds"] =
          static_cast<double>(user_ticks + system_ticks) / ticks_per_second;
      sample.values[target.prefix + "threads"] = static_cast<double>(threads);
      sample.values[target.prefix + "rss_bytes"] = static_cast<double>(rss_pages) * page_size;
    } catch (const std::exception &) {
      sample.values[target.prefix + "alive"] = 0.0;
    }
  }
}

}  // namespace perf_robot
