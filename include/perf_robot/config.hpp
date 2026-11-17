#pragma once

#include "perf_robot/ebpf_options.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace perf_robot {

struct Config {
  unsigned sample_hz{10};
  unsigned retention_seconds{60};
  unsigned capture_seconds{10};
  unsigned cooldown_seconds{5};
  bool auto_trigger_enabled{true};
  double cpu_trigger_percent{95.0};
  unsigned memory_available_trigger_mb{512};
  double thermal_trigger_celsius{95.0};
  unsigned trigger_consecutive_samples{10};
  unsigned min_free_disk_mb{512};
  std::vector<int> tracked_pids{0};
  std::filesystem::path incident_root{"/tmp/perf_robot/incidents"};
  std::filesystem::path pid_file{"/tmp/perf_robot/perf_robot.pid"};
  std::string control_socket{"@perf_robot.control"};
  bool l2_lttng_enabled{true};
  bool l2_ebpf_enabled{true};
  std::filesystem::path ros_prefix{"/opt/ros/jazzy"};
  std::filesystem::path lttng_path{"/usr/bin/lttng"};
  bool lttng_no_sessiond{true};
  std::vector<std::string> lttng_events{
      "ros2:rcl_init", "ros2:rcl_node_init", "ros2:rcl_publisher_init",
      "ros2:rcl_subscription_init", "ros2:rclcpp_subscription_callback_added",
      "ros2:rclcpp_callback_register", "ros2:callback_start",
      "ros2:callback_end", "ros2:rclcpp_publish", "ros2:rcl_publish",
      "ros2:rmw_publish", "ros2:rmw_take", "ros2:rcl_take"};
  std::vector<int> lttng_target_pids{};
  unsigned lttng_subbuf_size_kb{256};
  unsigned lttng_num_subbuf{4};
  std::filesystem::path ebpf_runner_path{"build/perf_robot_ebpf_runner"};
  std::filesystem::path ebpf_object_path{"build/perf_robot_sched.bpf.o"};
  // All other ebpf_* keys; handed to the runner as one runner.conf file.
  EbpfOptions ebpf{};

  std::size_t recorder_capacity() const;
  void validate() const;

  static Config load(const std::filesystem::path &path);
};

}  // namespace perf_robot
