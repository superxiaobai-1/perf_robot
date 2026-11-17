#include "perf_robot/agent.hpp"
#include "perf_robot/burst_collector.hpp"
#include "perf_robot/config.hpp"
#include "perf_robot/jetson_collector.hpp"
#include "perf_robot/proc_collector.hpp"
#include "perf_robot/process_collector.hpp"

#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>

int main(int argc, char **argv) {
  try {
    const std::filesystem::path config_path =
        argc > 1 ? argv[1] : std::filesystem::path("config/perf_robot.conf");
    auto config = perf_robot::Config::load(config_path);
    perf_robot::Agent agent(config);
    agent.add_collector(std::make_unique<perf_robot::ProcCollector>());
    agent.add_collector(std::make_unique<perf_robot::ProcessCollector>(config.tracked_pids));
    agent.add_collector(std::make_unique<perf_robot::JetsonCollector>());
    agent.add_burst_collector(perf_robot::make_lttng_burst_collector(config));
    agent.add_burst_collector(perf_robot::make_ebpf_burst_collector(config));
    return agent.run();
  } catch (const std::exception &error) {
    std::cerr << "perf_robot fatal: " << error.what() << '\n';
    return 1;
  }
}
