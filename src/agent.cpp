#include "perf_robot/agent.hpp"
#include "perf_robot/control_server.hpp"

#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

namespace perf_robot {
namespace {

class FileDescriptor {
 public:
  explicit FileDescriptor(int fd = -1) : fd_(fd) {}
  ~FileDescriptor() { if (fd_ >= 0) ::close(fd_); }
  FileDescriptor(const FileDescriptor &) = delete;
  FileDescriptor &operator=(const FileDescriptor &) = delete;
  int get() const noexcept { return fd_; }
 private:
  int fd_;
};

std::runtime_error system_error(const char *operation) {
  return std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
}

std::int64_t steady_ns() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::int64_t realtime_ns() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string make_incident_id() {
  const auto ns = realtime_ns();
  return std::to_string(ns) + "-" + std::to_string(::getpid());
}

void add_epoll_fd(int epoll_fd, int watched_fd) {
  epoll_event event{};
  event.events = EPOLLIN;
  event.data.fd = watched_fd;
  if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, watched_fd, &event) != 0) {
    throw system_error("epoll_ctl");
  }
}

}  // namespace

Agent::Agent(Config config)
    : config_(std::move(config)),
      recorder_(config_.recorder_capacity()),
      repository_(config_.incident_root),
      incident_writer_(repository_),
      resource_guard_(config_.incident_root, config_.min_free_disk_mb),
      trigger_policy_(config_) {}

Agent::~Agent() { remove_pid_file(); }

void Agent::add_collector(std::unique_ptr<ICollector> collector) {
  if (!collector) throw std::invalid_argument("collector is null");
  collectors_.push_back(std::move(collector));
}

void Agent::add_burst_collector(std::unique_ptr<IBurstCollector> collector) {
  burst_manager_.add(std::move(collector));
}

void Agent::create_runtime_files() {
  if (!config_.pid_file.parent_path().empty()) {
    std::filesystem::create_directories(config_.pid_file.parent_path());
  }
  std::ofstream pid(config_.pid_file, std::ios::trunc);
  if (!pid) throw std::runtime_error("cannot write pid file: " + config_.pid_file.string());
  pid << ::getpid() << '\n';
}

void Agent::remove_pid_file() noexcept {
  std::error_code ignored;
  std::filesystem::remove(config_.pid_file, ignored);
}

void Agent::collect_once() {
  Sample sample;
  sample.sequence = ++sequence_;
  sample.monotonic_ns = steady_ns();
  sample.realtime_ns = realtime_ns();

  for (auto &collector : collectors_) {
    const auto started = std::chrono::steady_clock::now();
    try {
      collector->collect(sample);
    } catch (const std::exception &error) {
      std::cerr << "collector " << collector->name() << " failed: " << error.what() << '\n';
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count();
    sample.values["agent.collector." + std::string(collector->name()) + ".duration_us"] =
        static_cast<double>(elapsed);
  }

  sample.values["agent.missed_deadlines"] = static_cast<double>(missed_deadlines_);
  sample.values["agent.rejected_captures"] = static_cast<double>(rejected_captures_);
  if (state_machine_.state() == CaptureState::Normal) {
    if (const auto reason = trigger_policy_.evaluate(sample)) trigger_capture(reason->c_str());
  }
  if (state_machine_.state() == CaptureState::Capturing) post_trigger_.push_back(sample);
  recorder_.push(std::move(sample));

  const auto now = std::chrono::steady_clock::now();
  if (state_machine_.capture_expired(now)) seal_capture();
  state_machine_.update_cooldown(now);
}

void Agent::trigger_capture(const char *reason) {
  const auto now = std::chrono::steady_clock::now();
  std::string rejection_reason;
  if (!resource_guard_.allow_capture(rejection_reason)) {
    ++rejected_captures_;
    std::cerr << "capture rejected: " << rejection_reason << '\n';
    return;
  }
  if (!state_machine_.begin_capture(now, std::chrono::seconds(config_.capture_seconds))) {
    std::cerr << "capture trigger ignored in state " << to_string(state_machine_.state()) << '\n';
    return;
  }
  trigger_reason_ = reason;
  trigger_monotonic_ns_ = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count());
  trigger_realtime_ns_ = static_cast<std::uint64_t>(realtime_ns());
  trigger_policy_.reset();
  incident_id_ = make_incident_id();
  burst_artifact_root_ = config_.incident_root / (".burst-" + incident_id_);
  pre_trigger_ = recorder_.snapshot();
  post_trigger_.clear();
  post_trigger_.reserve(static_cast<std::size_t>(config_.sample_hz) * config_.capture_seconds);
  burst_worker_active_ = burst_manager_.start_async(burst_artifact_root_, incident_id_);
  if (!burst_worker_active_) {
    std::cerr << "burst worker could not start; baseline capture remains active\n";
  }
  std::cerr << "capture started: " << reason << ", pre-trigger samples=" << pre_trigger_.size() << '\n';
}

std::string Agent::status_json() const {
  std::ostringstream output;
  output << "{\"ok\":true"
         << ",\"pid\":" << ::getpid()
         << ",\"state\":\"" << to_string(state_machine_.state()) << '"'
         << ",\"sample_hz\":" << config_.sample_hz
         << ",\"sequence\":" << sequence_
         << ",\"flight_recorder_samples\":" << recorder_.size()
         << ",\"flight_recorder_capacity\":" << recorder_.capacity()
         << ",\"missed_deadlines\":" << missed_deadlines_
         << ",\"rejected_captures\":" << rejected_captures_
         << ",\"incident_write_active\":" << (incident_writer_.active() ? "true" : "false")
         << '}';
  return output.str();
}

// Sealing has two asynchronous phases, neither of which blocks the epoll loop:
//   1. stop the Burst collectors (BurstManager worker, completion eventfd);
//   2. persist the incident (AsyncIncidentWriter worker, completion eventfd).
// Cooldown starts only after the incident write has finished.
void Agent::seal_capture() {
  state_machine_.begin_sealing();
  if (burst_worker_active_) {
    burst_manager_.request_stop();
  } else {
    start_incident_write();
  }
}

void Agent::start_incident_write() {
  burst_worker_active_ = false;
  Incident incident;
  incident.id = incident_id_.empty() ? make_incident_id() : incident_id_;
  incident.trigger = trigger_reason_;
  incident.trigger_monotonic_ns = trigger_monotonic_ns_;
  incident.trigger_realtime_ns = trigger_realtime_ns_;
  incident.overwritten_samples = recorder_.overwritten();
  incident.pre_trigger = std::move(pre_trigger_);
  incident.post_trigger = std::move(post_trigger_);
  incident.artifact_root = burst_artifact_root_;
  pre_trigger_.clear();
  post_trigger_.clear();
  if (!incident_writer_.start(std::move(incident))) {
    // Unreachable while the state machine admits one capture at a time.
    std::cerr << "incident writer busy; incident dropped\n";
    finish_seal();
  }
}

void Agent::finish_seal() {
  state_machine_.begin_cooldown(std::chrono::steady_clock::now(),
                                std::chrono::seconds(config_.cooldown_seconds));
}

int Agent::run() {
  config_.validate();
  create_runtime_files();

  sigset_t signals;
  sigemptyset(&signals);
  sigaddset(&signals, SIGINT);
  sigaddset(&signals, SIGTERM);
  sigaddset(&signals, SIGUSR1);
  if (::sigprocmask(SIG_BLOCK, &signals, nullptr) != 0) throw system_error("sigprocmask");

  FileDescriptor signal_fd(::signalfd(-1, &signals, SFD_NONBLOCK | SFD_CLOEXEC));
  if (signal_fd.get() < 0) throw system_error("signalfd");
  FileDescriptor timer_fd(::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC));
  if (timer_fd.get() < 0) throw system_error("timerfd_create");
  FileDescriptor epoll_fd(::epoll_create1(EPOLL_CLOEXEC));
  if (epoll_fd.get() < 0) throw system_error("epoll_create1");

  const auto interval_ns = 1'000'000'000ULL / config_.sample_hz;
  itimerspec timer{};
  timer.it_interval.tv_sec = static_cast<time_t>(interval_ns / 1'000'000'000ULL);
  timer.it_interval.tv_nsec = static_cast<long>(interval_ns % 1'000'000'000ULL);
  timer.it_value = timer.it_interval;
  if (::timerfd_settime(timer_fd.get(), 0, &timer, nullptr) != 0) throw system_error("timerfd_settime");
  add_epoll_fd(epoll_fd.get(), timer_fd.get());
  add_epoll_fd(epoll_fd.get(), signal_fd.get());
  ControlServer control_server(config_.control_socket);
  add_epoll_fd(epoll_fd.get(), control_server.fd());
  add_epoll_fd(epoll_fd.get(), burst_manager_.completion_fd());
  add_epoll_fd(epoll_fd.get(), incident_writer_.completion_fd());

  std::cerr << "perf_robot running at " << config_.sample_hz
            << " Hz, pid=" << ::getpid() << ", trigger with SIGUSR1\n";

  while (!stop_requested_) {
    epoll_event events[8]{};
    const int count = ::epoll_wait(epoll_fd.get(), events, 8, -1);
    if (count < 0) {
      if (errno == EINTR) continue;
      throw system_error("epoll_wait");
    }
    for (int index = 0; index < count; ++index) {
      if (events[index].data.fd == timer_fd.get()) {
        std::uint64_t expirations = 0;
        if (::read(timer_fd.get(), &expirations, sizeof(expirations)) != sizeof(expirations)) continue;
        // If delayed, take one current sample and record missed deadlines instead of
        // causing a catch-up storm that could disturb the robot workload.
        collect_once();
        control_server.expire_idle_clients();
        if (expirations > 1) {
          missed_deadlines_ += expirations - 1;
          std::cerr << "sampling deadline misses: " << (expirations - 1) << '\n';
        }
      } else if (events[index].data.fd == signal_fd.get()) {
        signalfd_siginfo info{};
        while (::read(signal_fd.get(), &info, sizeof(info)) == sizeof(info)) {
          if (info.ssi_signo == SIGUSR1) trigger_capture("manual-sigusr1");
          else if (info.ssi_signo == SIGINT || info.ssi_signo == SIGTERM) stop_requested_ = true;
        }
      } else if (events[index].data.fd == control_server.fd()) {
        control_server.drain([this](const std::string &command) {
          if (command == "status") return status_json();
          if (command == "capture") {
            trigger_capture("manual-control-socket");
            return std::string("{\"ok\":true,\"state\":\"") +
                   to_string(state_machine_.state()) + "\"}";
          }
          if (command == "stop") {
            stop_requested_ = true;
            return std::string("{\"ok\":true,\"stopping\":true}");
          }
          return std::string("{\"ok\":false,\"error\":\"unknown command\"}");
        });
      } else if (events[index].data.fd == burst_manager_.completion_fd()) {
        if (burst_manager_.consume_completion() && burst_worker_active_ &&
            state_machine_.state() == CaptureState::Sealing) {
          start_incident_write();
        }
      } else if (events[index].data.fd == incident_writer_.completion_fd()) {
        if (incident_writer_.consume_completion() &&
            state_machine_.state() == CaptureState::Sealing) {
          finish_seal();
        }
      }
    }
  }

  if (state_machine_.state() == CaptureState::Capturing) seal_capture();
  if (state_machine_.state() == CaptureState::Sealing) {
    if (burst_worker_active_) {
      burst_manager_.wait_for_completion();
      start_incident_write();
    }
    incident_writer_.wait();
    finish_seal();
  }
  return 0;
}

}  // namespace perf_robot
