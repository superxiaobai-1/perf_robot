#pragma once

#include <filesystem>
#include <iosfwd>
#include <string>
#include <vector>

namespace perf_robot {

// eBPF burst tunables shared by the Agent (perf_robot.conf) and the libbpf
// runner (runner.conf written per burst). Keys are identical in both files.
//
// To add an option: add the field, list it in visit_fields(), and add a range
// check to validate() if needed. Parsing, serialization and the runner
// hand-off follow automatically.
struct EbpfOptions {
  unsigned runqueue_threshold_us{1000};
  unsigned offcpu_min_us{200000};
  unsigned offcpu_max_us{5000000};
  unsigned softirq_threshold_us{1000};
  unsigned hardirq_threshold_us{1000};
  // L2 is intentionally stack-free. Enable either stack only for a short L3
  // capture and preferably combine it with an explicit TID whitelist.
  bool user_stack_enabled{false};
  bool kernel_stack_enabled{false};
  unsigned stack_sample_rate{16};
  bool irq_enabled{false};
  unsigned tid_refresh_seconds{2};
  bool auto_deep_enabled{true};
  unsigned auto_deep_seconds{2};
  unsigned auto_deep_max_tids{2};
  bool auto_deep_user_stack{true};
  bool auto_deep_kernel_stack{false};
  // Linux process IDs (TGIDs) are expanded through /proc/PID/task. Explicit
  // TIDs can narrow the scope further. Empty lists fail closed.
  std::vector<int> target_pids{};
  std::vector<int> target_tids{};

  template <typename Visitor>
  void visit_fields(Visitor &&visit) {
    visit("ebpf_runqueue_threshold_us", runqueue_threshold_us);
    visit("ebpf_offcpu_min_us", offcpu_min_us);
    visit("ebpf_offcpu_max_us", offcpu_max_us);
    visit("ebpf_softirq_threshold_us", softirq_threshold_us);
    visit("ebpf_hardirq_threshold_us", hardirq_threshold_us);
    visit("ebpf_user_stack_enabled", user_stack_enabled);
    visit("ebpf_kernel_stack_enabled", kernel_stack_enabled);
    visit("ebpf_stack_sample_rate", stack_sample_rate);
    visit("ebpf_irq_enabled", irq_enabled);
    visit("ebpf_tid_refresh_seconds", tid_refresh_seconds);
    visit("ebpf_auto_deep_enabled", auto_deep_enabled);
    visit("ebpf_auto_deep_seconds", auto_deep_seconds);
    visit("ebpf_auto_deep_max_tids", auto_deep_max_tids);
    visit("ebpf_auto_deep_user_stack", auto_deep_user_stack);
    visit("ebpf_auto_deep_kernel_stack", auto_deep_kernel_stack);
    visit("ebpf_target_pids", target_pids);
    visit("ebpf_target_tids", target_tids);
  }
  template <typename Visitor>
  void visit_fields(Visitor &&visit) const {
    const_cast<EbpfOptions *>(this)->visit_fields(
        [&visit](const char *key, const auto &field) { visit(key, field); });
  }

  // Applies one key=value entry. Returns false for a key that is not an eBPF
  // option; throws for a recognized key with an invalid value. Accepts the
  // legacy keys ebpf_threshold_us and ebpf_offcpu_stack_enabled.
  bool set(const std::string &key, const std::string &value);
  void validate() const;
  // Writes every option as key=value lines readable by load().
  void write(std::ostream &output) const;
  static EbpfOptions load(const std::filesystem::path &path);
};

}  // namespace perf_robot
