#include "perf_robot/config.hpp"

#include "perf_robot/parse_util.hpp"

#include <stdexcept>
#include <string>

namespace perf_robot {

std::size_t Config::recorder_capacity() const {
  return static_cast<std::size_t>(sample_hz) * retention_seconds;
}

void Config::validate() const {
  if (sample_hz == 0 || sample_hz > 1000) {
    throw std::runtime_error("sample_hz must be in [1, 1000]");
  }
  if (retention_seconds == 0 || retention_seconds > 3600) {
    throw std::runtime_error("retention_seconds must be in [1, 3600]");
  }
  if (capture_seconds == 0 || capture_seconds > 3600) {
    throw std::runtime_error("capture_seconds must be in [1, 3600]");
  }
  if (cpu_trigger_percent < 0.0 || cpu_trigger_percent > 100.0) {
    throw std::runtime_error("cpu_trigger_percent must be in [0, 100]");
  }
  if (thermal_trigger_celsius < -100.0 || thermal_trigger_celsius > 250.0) {
    throw std::runtime_error("thermal_trigger_celsius is out of range");
  }
  if (trigger_consecutive_samples == 0 || trigger_consecutive_samples > sample_hz * 60U) {
    throw std::runtime_error("trigger_consecutive_samples must be in [1, sample_hz * 60]");
  }
  if (incident_root.empty() || pid_file.empty()) {
    throw std::runtime_error("incident_root and pid_file cannot be empty");
  }
  if (control_socket.size() < 2 || control_socket.front() != '@') {
    throw std::runtime_error("control_socket must be a Linux abstract address beginning with @");
  }
  if (l2_lttng_enabled && (lttng_path.empty() || ros_prefix.empty())) {
    throw std::runtime_error("LTTng burst requires lttng_path and ros_prefix");
  }
  if (l2_lttng_enabled && lttng_events.empty()) {
    throw std::runtime_error("lttng_events cannot be empty when LTTng is enabled");
  }
  if (lttng_target_pids.size() > 256) {
    throw std::runtime_error("lttng_target_pids supports at most 256 process IDs");
  }
  if (lttng_subbuf_size_kb < 64 || lttng_subbuf_size_kb > 16384 ||
      (lttng_subbuf_size_kb & (lttng_subbuf_size_kb - 1U)) != 0) {
    throw std::runtime_error(
        "lttng_subbuf_size_kb must be a power of two in [64, 16384]");
  }
  if (lttng_num_subbuf < 2 || lttng_num_subbuf > 64 ||
      (lttng_num_subbuf & (lttng_num_subbuf - 1U)) != 0) {
    throw std::runtime_error(
        "lttng_num_subbuf must be a power of two in [2, 64]");
  }
  if (l2_ebpf_enabled && (ebpf_runner_path.empty() || ebpf_object_path.empty())) {
    throw std::runtime_error("eBPF burst requires ebpf_runner_path and ebpf_object_path");
  }
  ebpf.validate();
}

Config Config::load(const std::filesystem::path &path) {
  Config config;
  for_each_config_entry(path, [&config](const std::string &key, const std::string &value) {
    if (key == "sample_hz") config.sample_hz = parse_unsigned(key, value);
    else if (key == "retention_seconds") config.retention_seconds = parse_unsigned(key, value);
    else if (key == "capture_seconds") config.capture_seconds = parse_unsigned(key, value);
    else if (key == "cooldown_seconds") config.cooldown_seconds = parse_unsigned(key, value);
    else if (key == "auto_trigger_enabled") config.auto_trigger_enabled = parse_bool(key, value);
    else if (key == "cpu_trigger_percent") config.cpu_trigger_percent = parse_double(key, value);
    else if (key == "memory_available_trigger_mb") config.memory_available_trigger_mb = parse_unsigned(key, value);
    else if (key == "thermal_trigger_celsius") config.thermal_trigger_celsius = parse_double(key, value);
    else if (key == "trigger_consecutive_samples") config.trigger_consecutive_samples = parse_unsigned(key, value);
    else if (key == "min_free_disk_mb") config.min_free_disk_mb = parse_unsigned(key, value);
    else if (key == "tracked_pids") config.tracked_pids = parse_pids(key, value, true);
    else if (key == "incident_root") config.incident_root = value;
    else if (key == "pid_file") config.pid_file = value;
    else if (key == "control_socket") config.control_socket = value;
    else if (key == "l2_lttng_enabled") config.l2_lttng_enabled = parse_bool(key, value);
    else if (key == "l2_ebpf_enabled") config.l2_ebpf_enabled = parse_bool(key, value);
    else if (key == "ros_prefix") config.ros_prefix = value;
    else if (key == "lttng_path") config.lttng_path = value;
    else if (key == "lttng_no_sessiond") config.lttng_no_sessiond = parse_bool(key, value);
    else if (key == "lttng_events") config.lttng_events = parse_strings(value);
    else if (key == "lttng_target_pids") config.lttng_target_pids = parse_pids(key, value, false);
    else if (key == "lttng_subbuf_size_kb") config.lttng_subbuf_size_kb = parse_unsigned(key, value);
    else if (key == "lttng_num_subbuf") config.lttng_num_subbuf = parse_unsigned(key, value);
    else if (key == "ebpf_runner_path") config.ebpf_runner_path = value;
    else if (key == "ebpf_object_path") config.ebpf_object_path = value;
    else if (!config.ebpf.set(key, value)) throw std::runtime_error("unknown config key: " + key);
  });
  config.validate();
  return config;
}

}  // namespace perf_robot
