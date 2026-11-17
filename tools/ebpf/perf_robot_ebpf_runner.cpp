#include "perf_robot_ebpf.h"
#include "perf_robot/ebpf_options.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <sys/resource.h>
#include <time.h>
#include <vector>

namespace {

volatile std::sig_atomic_t stop_requested = 0;

void handle_signal(int) { stop_requested = 1; }

bool install_shutdown_handlers() {
  if (std::signal(SIGINT, handle_signal) == SIG_ERR ||
      std::signal(SIGTERM, handle_signal) == SIG_ERR) {
    return false;
  }
  sigset_t shutdown_signals;
  ::sigemptyset(&shutdown_signals);
  ::sigaddset(&shutdown_signals, SIGINT);
  ::sigaddset(&shutdown_signals, SIGTERM);
  return ::sigprocmask(SIG_UNBLOCK, &shutdown_signals, nullptr) == 0;
}

std::uint64_t clock_ns(clockid_t clock) {
  timespec value{};
  if (::clock_gettime(clock, &value) != 0) return 0;
  return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
         static_cast<std::uint64_t>(value.tv_nsec);
}

struct Options {
  std::string object_path;
  std::string output_path;
  // Parsed and validated by the same code as the Agent's perf_robot.conf.
  perf_robot::EbpfOptions ebpf;
  // ebpf.target_pids/target_tids converted to the BPF map key type.
  std::vector<std::uint32_t> target_pids;
  std::vector<std::uint32_t> target_tids;
};

struct OutputContext {
  FILE *output{};
  int stack_fd{-1};
  std::uint64_t monotonic_base{};
  std::uint64_t realtime_base{};
  std::set<std::int32_t> attempted_stack_ids;
  std::set<std::int32_t> persisted_stack_ids;
  std::uint64_t stack_lookup_failures{};
  std::set<std::uint32_t> observed_tgids;
  int deep_targets_fd{-1};
  bool auto_deep_enabled{false};
  std::chrono::seconds auto_deep_duration{0};
  std::size_t auto_deep_max_tids{0};
  std::map<std::uint32_t, std::chrono::steady_clock::time_point>
      active_deep_tids;
  std::set<std::uint32_t> completed_deep_tids;
  std::vector<std::uint32_t> triggered_deep_tids;
};

const char *event_name(std::uint32_t type) {
  switch (type) {
    case PERF_ROBOT_EVENT_RUNQUEUE: return "runqueue_latency";
    case PERF_ROBOT_EVENT_OFF_CPU: return "off_cpu";
    case PERF_ROBOT_EVENT_SOFTIRQ: return "softirq";
    case PERF_ROBOT_EVENT_HARDIRQ: return "hardirq";
    default: return "unknown";
  }
}

void write_json_string(FILE *output, const char *value, std::size_t capacity) {
  std::fputc('"', output);
  for (std::size_t index = 0; index < capacity && value[index] != '\0'; ++index) {
    const unsigned char ch = static_cast<unsigned char>(value[index]);
    if (ch == '"' || ch == '\\') {
      std::fputc('\\', output);
      std::fputc(ch, output);
    } else if (ch >= 0x20 && ch < 0x7f) {
      std::fputc(ch, output);
    } else {
      std::fprintf(output, "\\u%04x", ch);
    }
  }
  std::fputc('"', output);
}

void write_json_string(FILE *output, const std::string &value) {
  write_json_string(output, value.c_str(), value.size());
}

bool persist_stack_record(OutputContext &context, std::int32_t stack_id) {
  if (stack_id < 0 || context.attempted_stack_ids.count(stack_id) != 0) {
    return stack_id >= 0 && context.persisted_stack_ids.count(stack_id) != 0;
  }
  context.attempted_stack_ids.insert(stack_id);
  std::array<std::uint64_t, PERF_ROBOT_MAX_STACK_DEPTH> frames{};
  if (context.stack_fd < 0 ||
      bpf_map_lookup_elem(context.stack_fd, &stack_id, frames.data()) != 0) {
    ++context.stack_lookup_failures;
    return false;
  }
  std::fprintf(context.output,
               "{\"type\":\"stack_trace\",\"stack_id\":%d,\"frames\":[",
               stack_id);
  bool first = true;
  for (const auto address : frames) {
    if (address == 0) break;
    std::fprintf(context.output, "%s\"0x%" PRIx64 "\"", first ? "" : ",",
                 static_cast<std::uint64_t>(address));
    first = false;
  }
  std::fputs("]}\n", context.output);
  context.persisted_stack_ids.insert(stack_id);
  return true;
}

void arm_deep_capture(OutputContext &context, std::uint32_t tid) {
  if (!context.auto_deep_enabled || tid == 0 || context.deep_targets_fd < 0 ||
      context.active_deep_tids.count(tid) != 0 ||
      context.completed_deep_tids.count(tid) != 0 ||
      context.triggered_deep_tids.size() >= context.auto_deep_max_tids) {
    return;
  }
  const std::uint32_t enabled = 1;
  if (bpf_map_update_elem(context.deep_targets_fd, &tid, &enabled, BPF_ANY) != 0) {
    std::fprintf(stderr, "cannot arm automatic L3 for TID %u: %s\n", tid,
                 std::strerror(errno));
    return;
  }
  context.active_deep_tids[tid] =
      std::chrono::steady_clock::now() + context.auto_deep_duration;
  context.triggered_deep_tids.push_back(tid);
  std::fprintf(stderr, "automatic L3 armed for TID %u for %lld seconds\n", tid,
               static_cast<long long>(context.auto_deep_duration.count()));
}

void expire_deep_captures(
    OutputContext &context,
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) {
  for (auto iterator = context.active_deep_tids.begin();
       iterator != context.active_deep_tids.end();) {
    if (now < iterator->second) {
      ++iterator;
      continue;
    }
    const std::uint32_t tid = iterator->first;
    (void)bpf_map_delete_elem(context.deep_targets_fd, &tid);
    context.completed_deep_tids.insert(tid);
    std::fprintf(stderr, "automatic L3 closed for TID %u\n", tid);
    iterator = context.active_deep_tids.erase(iterator);
  }
}

int handle_event(void *context, void *data, std::size_t size) {
  if (size != sizeof(perf_robot_ebpf_event)) return 0;
  const auto *event = static_cast<const perf_robot_ebpf_event *>(data);
  auto *output = static_cast<OutputContext *>(context);
  // Persist the referenced stacks before the event line. If the process is
  // interrupted after a buffer boundary, an orphan stack record is harmless;
  // an event referring to a not-yet-persisted stack would not be.
  if (event->type == PERF_ROBOT_EVENT_OFF_CPU) {
    (void)persist_stack_record(*output, event->user_stack_id);
    (void)persist_stack_record(*output, event->kernel_stack_id);
  }
  const std::int64_t offset = static_cast<std::int64_t>(event->ktime_ns) -
                              static_cast<std::int64_t>(output->monotonic_base);
  const std::int64_t realtime = static_cast<std::int64_t>(output->realtime_base) + offset;
  std::fprintf(output->output,
               "{\"type\":\"%s\",\"monotonic_ns\":%" PRIu64
               ",\"realtime_ns\":%" PRId64 ",\"duration_ns\":%" PRIu64
               ",\"tid\":%u,\"tgid\":%u,\"cpu\":%u,\"task_state\":%" PRIu64
               ",\"other_id\":%u,\"user_stack_id\":%d"
               ",\"kernel_stack_id\":%d,\"waker_pid\":%u,\"waker_tid\":%u"
               ",\"comm\":",
               event_name(event->type), static_cast<std::uint64_t>(event->ktime_ns),
               realtime, static_cast<std::uint64_t>(event->duration_ns), event->tid,
               event->tgid, event->cpu, static_cast<std::uint64_t>(event->task_state),
               event->other_id, event->user_stack_id, event->kernel_stack_id,
               event->waker_pid, event->waker_tid);
  write_json_string(output->output, event->comm, sizeof(event->comm));
  std::fputs(",\"other_comm\":", output->output);
  write_json_string(output->output, event->other_comm, sizeof(event->other_comm));
  std::fputs(",\"waker_comm\":", output->output);
  write_json_string(output->output, event->waker_comm, sizeof(event->waker_comm));
  std::fputs("}\n", output->output);
  if (event->type == PERF_ROBOT_EVENT_OFF_CPU) {
    const bool has_stack = event->user_stack_id >= 0 || event->kernel_stack_id >= 0;
    if (has_stack) output->observed_tgids.insert(event->tgid);
    // The first long off-CPU interval is the L2 signal. Stack collection can
    // only explain subsequent occurrences, so arm a bounded L3 window now.
    arm_deep_capture(*output, event->tid);
  }
  return 0;
}

void usage(const char *program) {
  std::fprintf(stderr,
               "usage: %s --object FILE --output FILE --config FILE\n"
               "  --config takes ebpf_* key=value lines (same keys as perf_robot.conf)\n",
               program);
}

bool parse_u64(const char *text, std::uint64_t &value) {
  try {
    std::size_t parsed = 0;
    const std::string input(text);
    value = std::stoull(input, &parsed);
    return parsed == input.size();
  } catch (...) {
    return false;
  }
}

std::vector<std::uint32_t> to_map_keys(const std::vector<int> &ids) {
  // EbpfOptions guarantees positive, de-duplicated IDs.
  return {ids.begin(), ids.end()};
}

bool parse_options(int argc, char **argv, Options &options) {
  std::string config_path;
  for (int index = 1; index < argc; ++index) {
    const std::string argument(argv[index]);
    if (argument == "--object" && index + 1 < argc) {
      options.object_path = argv[++index];
    } else if (argument == "--output" && index + 1 < argc) {
      options.output_path = argv[++index];
    } else if (argument == "--config" && index + 1 < argc) {
      config_path = argv[++index];
    } else {
      return false;
    }
  }
  if (options.object_path.empty() || options.output_path.empty() ||
      config_path.empty()) {
    return false;
  }
  try {
    options.ebpf = perf_robot::EbpfOptions::load(config_path);
  } catch (const std::exception &error) {
    std::fprintf(stderr, "invalid eBPF options: %s\n", error.what());
    return false;
  }
  options.target_pids = to_map_keys(options.ebpf.target_pids);
  options.target_tids = to_map_keys(options.ebpf.target_tids);
  return true;
}

bool scan_process_tids(std::uint32_t pid, std::set<std::uint32_t> &result) {
  const std::string path = "/proc/" + std::to_string(pid) + "/task";
  DIR *directory = ::opendir(path.c_str());
  if (!directory) return false;
  while (dirent *entry = ::readdir(directory)) {
    if (entry->d_name[0] == '.') continue;
    std::uint64_t tid = 0;
    if (parse_u64(entry->d_name, tid) && tid > 0 && tid <= UINT32_MAX) {
      result.insert(static_cast<std::uint32_t>(tid));
    }
  }
  ::closedir(directory);
  return true;
}

std::size_t refresh_target_tids(
    int map_fd, const Options &options,
    std::set<std::uint32_t> &installed_tids) {
  std::set<std::uint32_t> desired(options.target_tids.begin(),
                                  options.target_tids.end());
  for (const auto pid : options.target_pids) {
    (void)scan_process_tids(pid, desired);
  }

  std::set<std::uint32_t> active;
  const std::uint32_t enabled = 1;
  for (const auto tid : desired) {
    if (installed_tids.count(tid) == 0) {
      if (bpf_map_update_elem(map_fd, &tid, &enabled, BPF_ANY) != 0) {
        std::fprintf(stderr,
                     "cannot add target TID %u to eBPF whitelist: %s\n",
                     tid, std::strerror(errno));
        continue;
      }
    }
    active.insert(tid);
  }
  for (const auto tid : installed_tids) {
    if (desired.count(tid) == 0) {
      (void)bpf_map_delete_elem(map_fd, &tid);
    }
  }
  installed_tids = std::move(active);
  return installed_tids.size();
}

std::size_t write_process_maps(FILE *output,
                               const std::set<std::uint32_t> &process_ids) {
  std::size_t written = 0;
  for (const auto tgid : process_ids) {
    std::ifstream input("/proc/" + std::to_string(tgid) + "/maps");
    if (!input) continue;
    std::fprintf(output, "{\"type\":\"process_maps\",\"tgid\":%u,\"maps\":[", tgid);
    std::string line;
    bool first = true;
    while (std::getline(input, line)) {
      if (!first) std::fputc(',', output);
      write_json_string(output, line);
      first = false;
    }
    std::fputs("]}\n", output);
    ++written;
  }
  return written;
}

bool add_link(bpf_link *link, const char *name, std::vector<bpf_link *> &links) {
  const long error = libbpf_get_error(link);
  if (!link || error) {
    std::fprintf(stderr, "cannot attach %s: %ld\n", name, error);
    return false;
  }
  links.push_back(link);
  return true;
}

void destroy_links(std::vector<bpf_link *> &links) {
  for (auto iterator = links.rbegin(); iterator != links.rend(); ++iterator) {
    bpf_link__destroy(*iterator);
  }
  links.clear();
}

bpf_program *program(bpf_object *object, const char *name) {
  bpf_program *result = bpf_object__find_program_by_name(object, name);
  if (!result) std::fprintf(stderr, "eBPF program missing: %s\n", name);
  return result;
}

bool set_program_autoload(bpf_object *object, const char *name, bool enabled) {
  bpf_program *item = program(object, name);
  if (!item) return false;
  const int result = bpf_program__set_autoload(item, enabled);
  if (result != 0) {
    std::fprintf(stderr, "cannot configure autoload for %s: %d\n", name,
                 result);
    return false;
  }
  return true;
}

bool configure_program_autoload(bpf_object *object, bool scheduler_enabled,
                                bool irq_enabled) {
  return set_program_autoload(object, "perf_robot_sched_waking",
                              scheduler_enabled) &&
         set_program_autoload(object, "perf_robot_sched_wakeup_new",
                              scheduler_enabled) &&
         set_program_autoload(object, "perf_robot_sched_switch",
                              scheduler_enabled) &&
         set_program_autoload(object, "perf_robot_softirq_entry", irq_enabled) &&
         set_program_autoload(object, "perf_robot_softirq_exit", irq_enabled) &&
         set_program_autoload(object, "perf_robot_hardirq_entry", irq_enabled) &&
         set_program_autoload(object, "perf_robot_hardirq_exit", irq_enabled);
}

bool set_map_capacity(bpf_object *object, const char *name,
                      std::uint32_t entries) {
  bpf_map *map = bpf_object__find_map_by_name(object, name);
  if (!map) {
    std::fprintf(stderr, "eBPF map missing: %s\n", name);
    return false;
  }
  const int result = bpf_map__set_max_entries(map, entries);
  if (result != 0) {
    std::fprintf(stderr, "cannot resize eBPF map %s: %d\n", name, result);
    return false;
  }
  return true;
}

bool minimize_disabled_maps(bpf_object *object, bool scheduler_enabled,
                            bool stack_enabled, bool irq_enabled,
                            bool auto_deep_enabled,
                            std::uint32_t auto_deep_max_tids) {
  if (!scheduler_enabled &&
      (!set_map_capacity(object, "wakeup_ns", 1) ||
       !set_map_capacity(object, "offcpu_starts", 1) ||
       !set_map_capacity(object, "target_tids", 1))) {
    return false;
  }
  if (!stack_enabled &&
      !set_map_capacity(object, "stack_traces", 1)) {
    return false;
  }
  if (!set_map_capacity(object, "deep_target_tids",
                        auto_deep_enabled ? auto_deep_max_tids : 1)) {
    return false;
  }
  if (!irq_enabled &&
      (!set_map_capacity(object, "softirq_starts", 1) ||
       !set_map_capacity(object, "hardirq_starts", 1))) {
    return false;
  }
  return true;
}

bool attach_programs(bpf_object *object, std::vector<bpf_link *> &links,
                     bool scheduler_enabled, bool irq_enabled) {
  if (scheduler_enabled) {
    bpf_program *waking = program(object, "perf_robot_sched_waking");
    bpf_program *wakeup_new = program(object, "perf_robot_sched_wakeup_new");
    bpf_program *switching = program(object, "perf_robot_sched_switch");
    if (!waking || !wakeup_new || !switching ||
        !add_link(bpf_program__attach_raw_tracepoint(waking, "sched_waking"),
                  "sched_waking", links) ||
        !add_link(bpf_program__attach_raw_tracepoint(wakeup_new,
                                                     "sched_wakeup_new"),
                  "sched_wakeup_new", links) ||
        !add_link(bpf_program__attach_raw_tracepoint(switching, "sched_switch"),
                  "sched_switch", links)) {
      return false;
    }
  }

  if (irq_enabled) {
    bpf_program *soft_entry = program(object, "perf_robot_softirq_entry");
    bpf_program *soft_exit = program(object, "perf_robot_softirq_exit");
    bpf_program *hard_entry = program(object, "perf_robot_hardirq_entry");
    bpf_program *hard_exit = program(object, "perf_robot_hardirq_exit");
    if (!soft_entry || !soft_exit || !hard_entry || !hard_exit ||
        !add_link(bpf_program__attach_tracepoint(soft_entry, "irq",
                                                 "softirq_entry"),
                  "softirq_entry", links) ||
        !add_link(bpf_program__attach_tracepoint(soft_exit, "irq",
                                                 "softirq_exit"),
                  "softirq_exit", links) ||
        !add_link(bpf_program__attach_tracepoint(hard_entry, "irq",
                                                 "irq_handler_entry"),
                  "irq_handler_entry", links) ||
        !add_link(bpf_program__attach_tracepoint(hard_exit, "irq",
                                                 "irq_handler_exit"),
                  "irq_handler_exit", links)) {
      return false;
    }
  }
  return true;
}

}  // namespace

int main(int argc, char **argv) {
  Options options;
  if (!parse_options(argc, argv, options)) {
    usage(argv[0]);
    return 2;
  }
  // Be robust when launched by an Agent using signalfd: signal dispositions
  // are reset by exec, but the blocked signal mask is inherited across exec.
  // Install handlers before unblocking so a pending stop signal is graceful.
  if (!install_shutdown_handlers()) {
    std::fprintf(stderr, "cannot install eBPF runner signal handlers: %s\n",
                 std::strerror(errno));
    return 1;
  }
  const bool scheduler_enabled =
      !options.target_pids.empty() || !options.target_tids.empty();
  // System-wide stack unwinding on every blocking switch is too intrusive for
  // a robot. A target list is mandatory for the scheduler path, and stacks are
  // independently opt-in on top of that whitelist.
  const bool manual_stack_enabled = options.ebpf.user_stack_enabled || options.ebpf.kernel_stack_enabled;
  const bool auto_deep_enabled =
      options.ebpf.auto_deep_enabled && scheduler_enabled && !manual_stack_enabled &&
      (options.ebpf.auto_deep_user_stack || options.ebpf.auto_deep_kernel_stack);
  const bool user_stack_enabled =
      scheduler_enabled &&
      (options.ebpf.user_stack_enabled ||
       (auto_deep_enabled && options.ebpf.auto_deep_user_stack));
  const bool kernel_stack_enabled =
      scheduler_enabled &&
      (options.ebpf.kernel_stack_enabled ||
       (auto_deep_enabled && options.ebpf.auto_deep_kernel_stack));
  const bool stack_capture_enabled =
      user_stack_enabled || kernel_stack_enabled;
  if ((options.ebpf.user_stack_enabled || options.ebpf.kernel_stack_enabled) && !scheduler_enabled) {
    std::fprintf(stderr,
                 "warning: off-CPU stacks disabled because PID/TID whitelist is empty\n");
  }
  if (!scheduler_enabled) {
    std::fprintf(stderr,
                 "notice: scheduler probes are not attached because PID/TID whitelist is empty\n");
  }

  const rlimit memlock{RLIM_INFINITY, RLIM_INFINITY};
  if (::setrlimit(RLIMIT_MEMLOCK, &memlock) != 0) {
    std::fprintf(stderr, "warning: cannot raise RLIMIT_MEMLOCK: %s\n", std::strerror(errno));
  }

  FILE *output = std::fopen(options.output_path.c_str(), "w");
  if (!output) {
    std::fprintf(stderr, "cannot open output %s: %s\n", options.output_path.c_str(),
                 std::strerror(errno));
    return 1;
  }
  // Batch JSON writes so event volume does not translate into one write(2)
  // per line. A periodic flush below bounds the crash-loss window.
  std::vector<char> output_buffer(1024U * 1024U);
  if (std::setvbuf(output, output_buffer.data(), _IOFBF,
                   output_buffer.size()) != 0) {
    std::fprintf(stderr, "warning: cannot configure buffered eBPF output\n");
  }

  bpf_object *object = bpf_object__open_file(options.object_path.c_str(), nullptr);
  const long open_error = libbpf_get_error(object);
  if (open_error) {
    std::fprintf(stderr, "bpf_object__open_file failed: %ld\n", open_error);
    std::fclose(output);
    return 1;
  }
  if (!configure_program_autoload(object, scheduler_enabled,
                                  options.ebpf.irq_enabled) ||
      !minimize_disabled_maps(object, scheduler_enabled,
                              stack_capture_enabled, options.ebpf.irq_enabled,
                              auto_deep_enabled,
                              static_cast<std::uint32_t>(
                                  options.ebpf.auto_deep_max_tids))) {
    bpf_object__close(object);
    std::fclose(output);
    return 1;
  }
  if (bpf_object__load(object) != 0) {
    std::fprintf(stderr,
                 "bpf_object__load failed; check CAP_BPF/CAP_PERFMON and verifier log\n");
    bpf_object__close(object);
    std::fclose(output);
    return 1;
  }

  const int config_fd = bpf_object__find_map_fd_by_name(object, "ebpf_config");
  const int events_fd = bpf_object__find_map_fd_by_name(object, "kernel_events");
  const int stats_fd = bpf_object__find_map_fd_by_name(object, "ebpf_stats");
  const int targets_fd = bpf_object__find_map_fd_by_name(object, "target_tids");
  const int deep_targets_fd =
      bpf_object__find_map_fd_by_name(object, "deep_target_tids");
  const int stack_fd = bpf_object__find_map_fd_by_name(object, "stack_traces");
  const std::uint32_t zero = 0;
  const perf_robot_ebpf_config config{
      options.ebpf.runqueue_threshold_us * 1000ULL,
      options.ebpf.offcpu_min_us * 1000ULL,
      options.ebpf.offcpu_max_us * 1000ULL,
      options.ebpf.softirq_threshold_us * 1000ULL,
      options.ebpf.hardirq_threshold_us * 1000ULL,
      user_stack_enabled ? 1U : 0U,
      kernel_stack_enabled ? 1U : 0U,
      static_cast<std::uint32_t>(options.ebpf.stack_sample_rate),
      auto_deep_enabled ? 1U : 0U,
  };
  if (config_fd < 0 || events_fd < 0 || targets_fd < 0 ||
      deep_targets_fd < 0 || stack_fd < 0 ||
      bpf_map_update_elem(config_fd, &zero, &config, BPF_ANY) != 0) {
    std::fprintf(stderr, "cannot configure eBPF maps: %s\n", std::strerror(errno));
    bpf_object__close(object);
    std::fclose(output);
    return 1;
  }
  std::set<std::uint32_t> active_target_tids;
  if (scheduler_enabled &&
      refresh_target_tids(targets_fd, options, active_target_tids) == 0) {
    std::fprintf(stderr,
                 "warning: no live TIDs resolved yet; probes remain fail-closed until refresh\n");
  }

  std::vector<bpf_link *> links;
  if (!attach_programs(object, links, scheduler_enabled, options.ebpf.irq_enabled)) {
    destroy_links(links);
    bpf_object__close(object);
    std::fclose(output);
    return 1;
  }

  OutputContext context;
  context.output = output;
  context.stack_fd = stack_fd;
  context.monotonic_base = clock_ns(CLOCK_MONOTONIC);
  context.realtime_base = clock_ns(CLOCK_REALTIME);
  context.deep_targets_fd = deep_targets_fd;
  context.auto_deep_enabled = auto_deep_enabled;
  context.auto_deep_duration =
      std::chrono::seconds(options.ebpf.auto_deep_seconds);
  context.auto_deep_max_tids =
      static_cast<std::size_t>(options.ebpf.auto_deep_max_tids);
  ring_buffer *ring = ring_buffer__new(events_fd, handle_event, &context, nullptr);
  if (!ring) {
    std::fprintf(stderr, "ring_buffer__new failed: %s\n", std::strerror(errno));
    destroy_links(links);
    bpf_object__close(object);
    std::fclose(output);
    return 1;
  }

  constexpr auto flush_interval = std::chrono::milliseconds(250);
  auto next_flush = std::chrono::steady_clock::now() + flush_interval;
  const auto refresh_interval =
      std::chrono::seconds(options.ebpf.tid_refresh_seconds);
  auto next_target_refresh =
      std::chrono::steady_clock::now() + refresh_interval;
  while (!stop_requested) {
    const int result = ring_buffer__poll(ring, 100);
    if (result < 0 && result != -EINTR) {
      std::fprintf(stderr, "ring buffer poll failed: %d\n", result);
      break;
    }
    const auto now = std::chrono::steady_clock::now();
    expire_deep_captures(context, now);
    if (now >= next_flush) {
      if (std::fflush(output) != 0) {
        std::fprintf(stderr, "warning: cannot flush eBPF event output: %s\n",
                     std::strerror(errno));
      }
      next_flush = now + flush_interval;
    }
    if (scheduler_enabled && now >= next_target_refresh) {
      (void)refresh_target_tids(targets_fd, options, active_target_tids);
      next_target_refresh = now + refresh_interval;
    }
  }

  // Referenced stacks were copied out as soon as their event reached user
  // space. Only process maps and final counters remain for sealing.
  const std::size_t stack_records = context.persisted_stack_ids.size();
  if (stack_capture_enabled) {
    context.observed_tgids.insert(options.target_pids.begin(),
                                  options.target_pids.end());
  }
  const std::size_t process_map_snapshots =
      write_process_maps(output, context.observed_tgids);

  const int cpu_count = libbpf_num_possible_cpus();
  if (stats_fd >= 0 && cpu_count > 0) {
    std::vector<perf_robot_ebpf_stats> per_cpu(static_cast<std::size_t>(cpu_count));
    if (bpf_map_lookup_elem(stats_fd, &zero, per_cpu.data()) == 0) {
      perf_robot_ebpf_stats total{};
      for (const auto &item : per_cpu) {
        total.wakeups += item.wakeups;
        total.preemptions += item.preemptions;
        total.sleeps += item.sleeps;
        total.runqueue_emitted += item.runqueue_emitted;
        total.offcpu_emitted += item.offcpu_emitted;
        total.softirq_emitted += item.softirq_emitted;
        total.hardirq_emitted += item.hardirq_emitted;
        total.ringbuf_drops += item.ringbuf_drops;
        total.user_stack_failures += item.user_stack_failures;
        total.kernel_stack_failures += item.kernel_stack_failures;
        total.waker_matches += item.waker_matches;
        total.stack_opportunities += item.stack_opportunities;
        total.stack_samples += item.stack_samples;
        total.stack_skipped += item.stack_skipped;
      }
      std::fprintf(output,
                   "{\"type\":\"summary\",\"wakeups\":%" PRIu64
                   ",\"preemptions\":%" PRIu64 ",\"sleeps\":%" PRIu64
                   ",\"runqueue_emitted\":%" PRIu64
                   ",\"offcpu_emitted\":%" PRIu64
                   ",\"softirq_emitted\":%" PRIu64
                   ",\"hardirq_emitted\":%" PRIu64
                   ",\"ringbuf_drops\":%" PRIu64
                   ",\"user_stack_failures\":%" PRIu64
                   ",\"kernel_stack_failures\":%" PRIu64
                   ",\"waker_matches\":%" PRIu64
                   ",\"stack_opportunities\":%" PRIu64
                   ",\"stack_samples\":%" PRIu64
                   ",\"stack_skipped\":%" PRIu64
                   ",\"offcpu_stack_requested\":%s,\"offcpu_stack_enabled\":%s"
                   ",\"user_stack_requested\":%s,\"user_stack_enabled\":%s"
                   ",\"kernel_stack_requested\":%s,\"kernel_stack_enabled\":%s"
                   ",\"stack_sample_rate\":%" PRIu64
                   ",\"stack_records\":%zu,\"stack_lookup_failures\":%" PRIu64
                   ",\"process_map_snapshots\":%zu,\"output_flush_interval_ms\":250"
                   ",\"scheduler_enabled\":%s,\"irq_enabled\":%s"
                   ",\"tid_refresh_seconds\":%" PRIu64
                   ",\"auto_deep_requested\":%s,\"auto_deep_enabled\":%s"
                   ",\"auto_deep_seconds\":%" PRIu64
                   ",\"auto_deep_max_tids\":%" PRIu64
                   ",\"auto_deep_triggered_count\":%zu"
                   ",\"auto_deep_completed_count\":%zu"
                   ",\"auto_deep_active_at_stop\":%zu"
                   ",\"auto_deep_user_stack\":%s"
                   ",\"auto_deep_kernel_stack\":%s"
                   ",\"target_filter_enabled\":%s,\"target_pid_count\":%zu"
                   ",\"target_tid_count\":%zu,\"active_target_tid_count\":%zu"
                   ",\"target_pids\":[",
                   static_cast<std::uint64_t>(total.wakeups),
                   static_cast<std::uint64_t>(total.preemptions),
                   static_cast<std::uint64_t>(total.sleeps),
                   static_cast<std::uint64_t>(total.runqueue_emitted),
                   static_cast<std::uint64_t>(total.offcpu_emitted),
                   static_cast<std::uint64_t>(total.softirq_emitted),
                   static_cast<std::uint64_t>(total.hardirq_emitted),
                   static_cast<std::uint64_t>(total.ringbuf_drops),
                   static_cast<std::uint64_t>(total.user_stack_failures),
                   static_cast<std::uint64_t>(total.kernel_stack_failures),
                   static_cast<std::uint64_t>(total.waker_matches),
                   static_cast<std::uint64_t>(total.stack_opportunities),
                   static_cast<std::uint64_t>(total.stack_samples),
                   static_cast<std::uint64_t>(total.stack_skipped),
                   ((options.ebpf.user_stack_enabled || options.ebpf.kernel_stack_enabled) ||
                    auto_deep_enabled) ? "true" : "false",
                   stack_capture_enabled ? "true" : "false",
                   options.ebpf.user_stack_enabled ? "true" : "false",
                   user_stack_enabled ? "true" : "false",
                   options.ebpf.kernel_stack_enabled ? "true" : "false",
                   kernel_stack_enabled ? "true" : "false",
                   static_cast<std::uint64_t>(options.ebpf.stack_sample_rate),
                   stack_records, context.stack_lookup_failures,
                   process_map_snapshots,
                   scheduler_enabled ? "true" : "false",
                   options.ebpf.irq_enabled ? "true" : "false",
                   static_cast<std::uint64_t>(options.ebpf.tid_refresh_seconds),
                   options.ebpf.auto_deep_enabled ? "true" : "false",
                   auto_deep_enabled ? "true" : "false",
                   static_cast<std::uint64_t>(options.ebpf.auto_deep_seconds),
                   static_cast<std::uint64_t>(options.ebpf.auto_deep_max_tids),
                   context.triggered_deep_tids.size(),
                   context.completed_deep_tids.size(),
                   context.active_deep_tids.size(),
                   options.ebpf.auto_deep_user_stack ? "true" : "false",
                   options.ebpf.auto_deep_kernel_stack ? "true" : "false",
                   scheduler_enabled ? "true" : "false",
                   options.target_pids.size(), options.target_tids.size(),
                   active_target_tids.size());
      for (std::size_t index = 0; index < options.target_pids.size(); ++index) {
        std::fprintf(output, "%s%u", index == 0 ? "" : ",",
                     options.target_pids[index]);
      }
      std::fputs("],\"target_tids\":[", output);
      for (std::size_t index = 0; index < options.target_tids.size(); ++index) {
        std::fprintf(output, "%s%u", index == 0 ? "" : ",",
                     options.target_tids[index]);
      }
      std::fputs("],\"auto_deep_tids\":[", output);
      for (std::size_t index = 0;
           index < context.triggered_deep_tids.size(); ++index) {
        std::fprintf(output, "%s%u", index == 0 ? "" : ",",
                     context.triggered_deep_tids[index]);
      }
      std::fputs("]}\n", output);
    }
  }

  ring_buffer__free(ring);
  destroy_links(links);
  bpf_object__close(object);
  std::fclose(output);
  return 0;
}
