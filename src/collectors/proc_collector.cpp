#include "perf_robot/proc_collector.hpp"

#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

namespace perf_robot {
namespace {

void read_meminfo(Sample &sample) {
  std::ifstream input("/proc/meminfo");
  std::string line;
  while (std::getline(input, line)) {
    std::istringstream fields(line);
    std::string key;
    std::uint64_t value = 0;
    fields >> key >> value;
    if (key == "MemTotal:") sample.values["memory.total_bytes"] = value * 1024.0;
    else if (key == "MemAvailable:") sample.values["memory.available_bytes"] = value * 1024.0;
    else if (key == "SwapFree:") sample.values["swap.free_bytes"] = value * 1024.0;
  }
}

void read_loadavg(Sample &sample) {
  std::ifstream input("/proc/loadavg");
  input >> sample.values["load.1m"] >> sample.values["load.5m"] >> sample.values["load.15m"];
}

void read_self_rss(Sample &sample) {
  std::ifstream input("/proc/self/statm");
  std::uint64_t pages = 0;
  std::uint64_t resident_pages = 0;
  input >> pages >> resident_pages;
  sample.values["agent.virtual_bytes"] = static_cast<double>(pages) * sysconf(_SC_PAGESIZE);
  sample.values["agent.rss_bytes"] = static_cast<double>(resident_pages) * sysconf(_SC_PAGESIZE);
}

}  // namespace

void ProcCollector::collect(Sample &sample) {
  std::ifstream cpu("/proc/stat");
  std::string label;
  std::uint64_t user = 0, nice = 0, system = 0, idle = 0, iowait = 0;
  std::uint64_t irq = 0, softirq = 0, steal = 0;
  cpu >> label >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
  const auto idle_all = idle + iowait;
  const auto total = user + nice + system + idle + iowait + irq + softirq + steal;

  if (have_cpu_baseline_ && total > previous_total_) {
    const auto delta_total = total - previous_total_;
    const auto delta_idle = idle_all - previous_idle_;
    sample.values["cpu.busy_percent"] =
        100.0 * static_cast<double>(delta_total - delta_idle) / static_cast<double>(delta_total);
  }
  previous_total_ = total;
  previous_idle_ = idle_all;
  have_cpu_baseline_ = true;

  read_meminfo(sample);
  read_loadavg(sample);
  read_self_rss(sample);
}

}  // namespace perf_robot
