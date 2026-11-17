#include "perf_robot/ebpf_options.hpp"

#include "perf_robot/parse_util.hpp"

#include <ostream>
#include <stdexcept>
#include <type_traits>

namespace perf_robot {
namespace {

void assign(const std::string &key, const std::string &value, unsigned &field) {
  field = parse_unsigned(key, value);
}

void assign(const std::string &key, const std::string &value, bool &field) {
  field = parse_bool(key, value);
}

void assign(const std::string &key, const std::string &value, std::vector<int> &field) {
  field = parse_pids(key, value, false);
}

void emit(std::ostream &output, const char *key, unsigned value) {
  output << key << '=' << value << '\n';
}

void emit(std::ostream &output, const char *key, bool value) {
  output << key << '=' << (value ? "true" : "false") << '\n';
}

void emit(std::ostream &output, const char *key, const std::vector<int> &value) {
  output << key << '=';
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (index != 0) output << ',';
    output << value[index];
  }
  output << '\n';
}

}  // namespace

bool EbpfOptions::set(const std::string &key, const std::string &value) {
  if (key == "ebpf_threshold_us") {
    // Retained for existing deployments.
    runqueue_threshold_us = parse_unsigned(key, value);
    return true;
  }
  if (key == "ebpf_offcpu_stack_enabled") {
    // Backward compatibility: the old switch controlled both stacks.
    const bool enabled = parse_bool(key, value);
    user_stack_enabled = enabled;
    kernel_stack_enabled = enabled;
    return true;
  }
  bool matched = false;
  visit_fields([&](const char *name, auto &field) {
    if (!matched && key == name) {
      assign(key, value, field);
      matched = true;
    }
  });
  return matched;
}

void EbpfOptions::validate() const {
  constexpr unsigned max_threshold_us = 60U * 1000U * 1000U;
  if (runqueue_threshold_us == 0 || runqueue_threshold_us > max_threshold_us) {
    throw std::runtime_error("ebpf_runqueue_threshold_us must be in [1, 60000000]");
  }
  if (offcpu_min_us == 0 || offcpu_max_us < offcpu_min_us ||
      offcpu_max_us > max_threshold_us) {
    throw std::runtime_error(
        "eBPF off-CPU thresholds require 1 <= min <= max <= 60000000 us");
  }
  if (softirq_threshold_us == 0 || softirq_threshold_us > max_threshold_us ||
      hardirq_threshold_us == 0 || hardirq_threshold_us > max_threshold_us) {
    throw std::runtime_error("eBPF IRQ thresholds must be in [1, 60000000] us");
  }
  if (target_pids.size() > 256) {
    throw std::runtime_error("ebpf_target_pids supports at most 256 process IDs");
  }
  if (target_tids.size() > 4096) {
    throw std::runtime_error("ebpf_target_tids supports at most 4096 thread IDs");
  }
  if (stack_sample_rate == 0 || stack_sample_rate > 1024 ||
      (stack_sample_rate & (stack_sample_rate - 1U)) != 0) {
    throw std::runtime_error("ebpf_stack_sample_rate must be a power of two in [1, 1024]");
  }
  if (tid_refresh_seconds == 0 || tid_refresh_seconds > 60) {
    throw std::runtime_error("ebpf_tid_refresh_seconds must be in [1, 60]");
  }
  if (auto_deep_seconds == 0 || auto_deep_seconds > 3) {
    throw std::runtime_error("ebpf_auto_deep_seconds must be in [1, 3]");
  }
  if (auto_deep_max_tids == 0 || auto_deep_max_tids > 32) {
    throw std::runtime_error("ebpf_auto_deep_max_tids must be in [1, 32]");
  }
}

void EbpfOptions::write(std::ostream &output) const {
  output << "# Effective eBPF options for this burst, written by perf_robot_agent.\n";
  visit_fields([&output](const char *key, const auto &field) { emit(output, key, field); });
}

EbpfOptions EbpfOptions::load(const std::filesystem::path &path) {
  EbpfOptions options;
  for_each_config_entry(path, [&options](const std::string &key, const std::string &value) {
    if (!options.set(key, value)) throw std::runtime_error("unknown eBPF option: " + key);
  });
  options.validate();
  return options;
}

}  // namespace perf_robot
