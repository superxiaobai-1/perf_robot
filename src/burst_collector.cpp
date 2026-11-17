#include "perf_robot/burst_collector.hpp"

#include "perf_robot/json.hpp"

#include <chrono>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace perf_robot {
namespace {

std::string session_name(const std::string &incident_id) {
  std::string result = "perf_robot_" + incident_id;
  for (auto &ch : result) if (ch == '-') ch = '_';
  return result;
}

std::string join_pids(const std::vector<int> &pids) {
  std::ostringstream output;
  for (std::size_t index = 0; index < pids.size(); ++index) {
    if (index != 0) output << ',';
    output << pids[index];
  }
  return output.str();
}

std::string join_strings(const std::vector<std::string> &items) {
  std::ostringstream output;
  for (std::size_t index = 0; index < items.size(); ++index) {
    if (index != 0) output << ',';
    output << items[index];
  }
  return output.str();
}

// Agent uses signalfd and therefore blocks its handled signals process-wide.
// Threads and fork/exec children inherit that mask. External helpers must not
// inherit it, otherwise SIGINT/SIGTERM remain pending and shutdown escalates to
// SIGKILL. sigprocmask is safe to call in the post-fork child before exec.
bool reset_child_signal_mask() noexcept {
  sigset_t empty;
  return ::sigemptyset(&empty) == 0 &&
         ::sigprocmask(SIG_SETMASK, &empty, nullptr) == 0;
}

int run_command(const std::vector<std::string> &arguments,
                const std::filesystem::path &log_path,
                std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
  if (arguments.empty()) return 127;
  const int log_fd = ::open(log_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
  if (log_fd < 0) return 126;
  const pid_t pid = ::fork();
  if (pid == 0) {
    if (!reset_child_signal_mask()) _exit(126);
    (void)::setpgid(0, 0);
    (void)::setpriority(PRIO_PROCESS, 0, 10);
    ::dup2(log_fd, STDOUT_FILENO);
    ::dup2(log_fd, STDERR_FILENO);
    ::close(log_fd);
    std::vector<char *> argv;
    argv.reserve(arguments.size() + 1);
    for (const auto &argument : arguments) argv.push_back(const_cast<char *>(argument.c_str()));
    argv.push_back(nullptr);
    ::execv(argv.front(), argv.data());
    _exit(127);
  }
  ::close(log_fd);
  if (pid < 0) return 126;
  (void)::setpgid(pid, pid);
  int status = 0;
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    const auto result = ::waitpid(pid, &status, WNOHANG);
    if (result == pid) break;
    if (result < 0 && errno != EINTR) return 125;
    if (std::chrono::steady_clock::now() >= deadline) {
      (void)::kill(-pid, SIGTERM);
      const auto terminate_deadline = std::chrono::steady_clock::now() +
                                      std::chrono::milliseconds(200);
      while (std::chrono::steady_clock::now() < terminate_deadline) {
        if (::waitpid(pid, &status, WNOHANG) == pid) return 124;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      (void)::kill(-pid, SIGKILL);
      while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
      return 124;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 125;
}

class LttngBurstCollector final : public IBurstCollector {
 public:
  explicit LttngBurstCollector(const Config &config)
      : enabled_(config.l2_lttng_enabled), executable_(config.lttng_path),
        ros_prefix_(config.ros_prefix), no_sessiond_(config.lttng_no_sessiond),
        events_(config.lttng_events),
        target_pids_(config.lttng_target_pids.empty()
                         ? config.ebpf.target_pids
                         : config.lttng_target_pids),
        subbuf_size_kb_(config.lttng_subbuf_size_kb),
        num_subbuf_(config.lttng_num_subbuf) {
    report_.name = "lttng_ros2_ust";
  }

  std::string name() const override { return report_.name; }

  void start(const std::filesystem::path &artifact_root,
             const std::string &incident_id) override {
    report_ = BurstReport{};
    report_.name = "lttng_ros2_ust";
    if (!enabled_) {
      report_.error = "disabled by configuration";
      return;
    }
    report_.start_attempted = true;
    if (!std::filesystem::exists(executable_)) {
      report_.error = "lttng executable not found: " + executable_.string();
      return;
    }
    if (!std::filesystem::exists(ros_prefix_ / "lib/libtracetools.so")) {
      report_.error = "ROS 2 tracetools not found under " + ros_prefix_.string();
      return;
    }
    if (target_pids_.empty()) {
      report_.error =
          "no LTTng target PID; lttng_target_pids and ebpf_target_pids are empty";
      return;
    }

    const auto directory = artifact_root / "lttng";
    std::filesystem::create_directories(directory);
    log_path_ = directory / "control.log";
    session_ = session_name(incident_id);
    int code = run_lttng({"create", session_, "--output=" + directory.string()});
    if (code == 0) created_ = true;
    if (code == 0) {
      const auto subbuf_bytes =
          std::to_string(static_cast<unsigned long long>(subbuf_size_kb_) * 1024ULL);
      code = run_lttng({"enable-channel", "--userspace", "--session", session_,
                        "--discard", "--blocking-timeout=0", "--buffers-uid",
                        "--subbuf-size=" + subbuf_bytes,
                        "--num-subbuf=" + std::to_string(num_subbuf_),
                        "--switch-timer=200000", "--read-timer=200000",
                        channel_});
    }
    if (code == 0) {
      // Process tracking is a vpid admission filter applied before event
      // recording and is cheaper than evaluating a filter expression for
      // every ROS tracepoint.
      code = run_lttng({"untrack", "--userspace", "--session", session_,
                        "--all", "--vpid"});
    }
    if (code == 0) {
      code = run_lttng({"track", "--userspace", "--session", session_,
                        "--vpid=" + join_pids(target_pids_)});
    }
    if (code == 0) {
      code = run_lttng({"enable-event", "--userspace", "--session", session_,
                        "--channel", channel_, join_strings(events_)});
    }
    if (code == 0) {
      // Context failure is non-fatal; trace events are still useful.
      (void)run_lttng({"add-context", "--userspace", "--session", session_,
                       "--channel", channel_,
                       "--type=vpid", "--type=vtid", "--type=procname"});
      // start/stop/destroy take SESSION as a positional argument in LTTng
      // 2.13. --session is only accepted by commands such as enable-event.
      code = run_lttng({"start", session_});
    }
    report_.exit_code = code;
    if (code != 0) {
      report_.error = "lttng setup failed; inspect lttng/control.log";
      cleanup_session();
      return;
    }
    report_.started = true;
  }

  void stop() noexcept override {
    if (!created_) return;
    try {
      int code = 0;
      if (report_.started) {
        code = run_lttng({"stop", session_});
        // Keep the final channel configuration/statistics in control.log
        // before destroy removes the live session.
        (void)run_lttng({"list", session_, "--channel=" + channel_});
      }
      const int destroy_code = run_lttng({"destroy", session_});
      created_ = false;
      report_.stopped = code == 0 && destroy_code == 0;
      if (!report_.stopped && report_.error.empty()) {
        report_.error = "lttng stop/destroy failed; inspect lttng/control.log";
      }
      if (code != 0) report_.exit_code = code;
      else if (destroy_code != 0) report_.exit_code = destroy_code;
    } catch (const std::exception &error) {
      report_.error = error.what();
    }
  }

  BurstReport report() const override { return report_; }

 private:
  void cleanup_session() noexcept {
    if (!created_) return;
    try {
      (void)run_lttng({"destroy", session_});
    } catch (...) {}
    created_ = false;
  }

  int run_lttng(std::vector<std::string> arguments) const {
    std::vector<std::string> command;
    command.reserve(arguments.size() + 2);
    command.push_back(executable_.string());
    if (no_sessiond_) command.push_back("--no-sessiond");
    command.insert(command.end(), std::make_move_iterator(arguments.begin()),
                   std::make_move_iterator(arguments.end()));
    return run_command(command, log_path_);
  }

  bool enabled_;
  std::filesystem::path executable_;
  std::filesystem::path ros_prefix_;
  bool no_sessiond_;
  std::vector<std::string> events_;
  std::vector<int> target_pids_;
  unsigned subbuf_size_kb_;
  unsigned num_subbuf_;
  const std::string channel_{"perf_robot_ros2"};
  std::filesystem::path log_path_;
  std::string session_;
  bool created_{false};
  BurstReport report_;
};

class EbpfBurstCollector final : public IBurstCollector {
 public:
  explicit EbpfBurstCollector(const Config &config)
      : enabled_(config.l2_ebpf_enabled), runner_(config.ebpf_runner_path),
        object_(config.ebpf_object_path), options_(config.ebpf) {
    report_.name = "libbpf_kernel_events";
  }

  ~EbpfBurstCollector() override { stop(); }
  std::string name() const override { return report_.name; }

  void start(const std::filesystem::path &artifact_root,
             const std::string &) override {
    report_ = BurstReport{};
    report_.name = "libbpf_kernel_events";
    if (!enabled_) {
      report_.error = "disabled by configuration";
      return;
    }
    report_.start_attempted = true;
    if (!std::filesystem::exists(runner_)) {
      report_.error = "libbpf runner not found: " + runner_.string();
      return;
    }
    if (!std::filesystem::exists(object_)) {
      report_.error = "CO-RE eBPF object not found: " + object_.string();
      return;
    }

    const auto directory = artifact_root / "ebpf";
    std::filesystem::create_directories(directory);
    output_path_ = directory / "kernel_events.jsonl";
    error_path_ = directory / "stderr.log";
    // The effective options travel as one file in the runner's own format.
    // It also archives the exact eBPF configuration inside the incident.
    const auto options_path = directory / "runner.conf";
    {
      std::ofstream options_file(options_path, std::ios::trunc);
      options_.write(options_file);
      options_file.close();
      if (!options_file) {
        report_.error = "cannot write libbpf runner options";
        return;
      }
    }
    const int error_fd = ::open(error_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (error_fd < 0) {
      report_.error = "cannot create libbpf runner log";
      return;
    }

    // Build argv strings before fork: the child must only exec.
    const auto runner = runner_.string();
    const auto object = object_.string();
    const auto output = output_path_.string();
    const auto options = options_path.string();
    pid_ = ::fork();
    if (pid_ == 0) {
      if (!reset_child_signal_mask()) _exit(126);
      (void)::setpriority(PRIO_PROCESS, 0, 10);
      ::dup2(error_fd, STDOUT_FILENO);
      ::dup2(error_fd, STDERR_FILENO);
      ::close(error_fd);
      ::execl(runner.c_str(), runner.c_str(),
              "--object", object.c_str(),
              "--output", output.c_str(),
              "--config", options.c_str(), nullptr);
      _exit(127);
    }
    ::close(error_fd);
    if (pid_ < 0) {
      report_.error = "fork failed for libbpf runner";
      return;
    }
    report_.started = true;
  }

  void stop() noexcept override {
    if (pid_ <= 0) return;
    ::kill(pid_, SIGINT);
    int status = 0;
    bool exited = false;
    for (int attempt = 0; attempt < 50; ++attempt) {
      const auto result = ::waitpid(pid_, &status, WNOHANG);
      if (result == pid_) {
        exited = true;
        break;
      }
      if (result < 0 && errno != EINTR) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!exited) {
      ::kill(pid_, SIGTERM);
      for (int attempt = 0; attempt < 25; ++attempt) {
        const auto result = ::waitpid(pid_, &status, WNOHANG);
        if (result == pid_) {
          exited = true;
          break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
    }
    if (!exited) {
      ::kill(pid_, SIGKILL);
      while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
    }
    pid_ = -1;
    report_.stopped = true;
    if (WIFEXITED(status)) report_.exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) report_.exit_code = 128 + WTERMSIG(status);
    if (report_.exit_code != 0) {
      report_.error = "libbpf runner exited unsuccessfully; inspect ebpf/stderr.log";
    }
  }

  BurstReport report() const override { return report_; }

 private:
  bool enabled_;
  std::filesystem::path runner_;
  std::filesystem::path object_;
  EbpfOptions options_;
  std::filesystem::path output_path_;
  std::filesystem::path error_path_;
  pid_t pid_{-1};
  BurstReport report_;
};

}  // namespace

BurstManager::BurstManager()
    : completion_fd_(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)) {
  if (completion_fd_ < 0) throw std::runtime_error("cannot create burst completion eventfd");
}

BurstManager::~BurstManager() {
  request_stop();
  if (worker_.joinable()) worker_.join();
  if (completion_fd_ >= 0) ::close(completion_fd_);
}

void BurstManager::add(std::unique_ptr<IBurstCollector> collector) {
  if (!collector) throw std::invalid_argument("burst collector is null");
  collectors_.push_back(std::move(collector));
}

bool BurstManager::start_async(const std::filesystem::path &artifact_root,
                               const std::string &incident_id) noexcept {
  std::lock_guard lock(mutex_);
  if (running_ || worker_.joinable()) return false;
  running_ = true;
  stop_requested_ = false;
  try {
    worker_ = std::thread(&BurstManager::worker_main, this, artifact_root, incident_id);
    return true;
  } catch (...) {
    running_ = false;
    return false;
  }
}

void BurstManager::request_stop() noexcept {
  {
    std::lock_guard lock(mutex_);
    stop_requested_ = true;
  }
  stop_condition_.notify_all();
}

void BurstManager::worker_main(std::filesystem::path artifact_root,
                               std::string incident_id) noexcept {
  std::error_code error;
  std::filesystem::create_directories(artifact_root, error);
  std::vector<std::thread> starters;
  starters.reserve(collectors_.size());
  for (auto &collector : collectors_) {
    auto *instance = collector.get();
    starters.emplace_back([instance, &artifact_root, &incident_id] {
      try {
        instance->start(artifact_root, incident_id);
      } catch (...) {}
    });
  }
  for (auto &thread : starters) thread.join();

  {
    std::unique_lock lock(mutex_);
    stop_condition_.wait(lock, [this] { return stop_requested_; });
  }
  for (auto iterator = collectors_.rbegin(); iterator != collectors_.rend(); ++iterator) {
    (*iterator)->stop();
  }
  write_status(artifact_root);
  {
    std::lock_guard lock(mutex_);
    running_ = false;
  }
  const std::uint64_t completed = 1;
  const auto bytes_written = ::write(completion_fd_, &completed, sizeof(completed));
  if (bytes_written != sizeof(completed)) {
    // The eventfd is nonblocking. A saturated counter is harmless because one
    // pending completion is enough to wake the epoll loop.
  }
}

bool BurstManager::consume_completion() noexcept {
  std::uint64_t completed = 0;
  if (::read(completion_fd_, &completed, sizeof(completed)) != sizeof(completed)) return false;
  if (worker_.joinable()) worker_.join();
  return true;
}

void BurstManager::wait_for_completion() noexcept {
  request_stop();
  if (worker_.joinable()) worker_.join();
  std::uint64_t completed = 0;
  const auto bytes_read = ::read(completion_fd_, &completed, sizeof(completed));
  if (bytes_read < 0 && errno != EAGAIN) {
    // Shutdown is already committed; there is no recovery action here.
  }
}

void BurstManager::write_status(const std::filesystem::path &artifact_root) const noexcept {
  try {
    std::filesystem::create_directories(artifact_root);
    std::ofstream output(artifact_root / "status.json", std::ios::trunc);
    output << "{\n  \"collectors\": [\n";
    for (std::size_t index = 0; index < collectors_.size(); ++index) {
      const auto report = collectors_[index]->report();
      output << "    {\"name\":\"" << json_escape(report.name)
             << "\",\"start_attempted\":" << std::boolalpha << report.start_attempted
             << ",\"started\":" << report.started
             << ",\"stopped\":" << report.stopped
             << ",\"exit_code\":" << report.exit_code
             << ",\"error\":\"" << json_escape(report.error) << "\"}";
      if (index + 1 != collectors_.size()) output << ',';
      output << '\n';
    }
    output << "  ]\n}\n";
  } catch (...) {}
}

std::unique_ptr<IBurstCollector> make_lttng_burst_collector(const Config &config) {
  return std::make_unique<LttngBurstCollector>(config);
}

std::unique_ptr<IBurstCollector> make_ebpf_burst_collector(const Config &config) {
  return std::make_unique<EbpfBurstCollector>(config);
}

}  // namespace perf_robot
