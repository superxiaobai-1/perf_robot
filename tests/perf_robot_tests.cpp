#include "perf_robot/burst_collector.hpp"
#include "perf_robot/config.hpp"
#include "perf_robot/control_server.hpp"
#include "perf_robot/ebpf_options.hpp"
#include "perf_robot/flight_recorder.hpp"
#include "perf_robot/incident_repository.hpp"
#include "perf_robot/incident_writer.hpp"
#include "perf_robot/json.hpp"
#include "perf_robot/state_machine.hpp"
#include "perf_robot/trigger_policy.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace {

struct FakeBurstState {
  std::atomic<bool> started{false};
  std::atomic<bool> stopped{false};
};

class FakeBurstCollector final : public perf_robot::IBurstCollector {
 public:
  explicit FakeBurstCollector(FakeBurstState &state) : state_(state) {}
  std::string name() const override { return "fake"; }
  void start(const std::filesystem::path &, const std::string &) override {
    state_.started = true;
  }
  void stop() noexcept override { state_.stopped = true; }
  perf_robot::BurstReport report() const override {
    perf_robot::BurstReport report;
    report.name = "fake";
    report.start_attempted = true;
    report.started = state_.started;
    report.stopped = state_.stopped;
    return report;
  }

 private:
  FakeBurstState &state_;
};

void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

void test_default_rate_and_capacity() {
  perf_robot::Config config;
  require(config.sample_hz == 10, "default sample rate must be 10 Hz");
  require(config.recorder_capacity() == 600, "60 seconds at 10 Hz must hold 600 samples");
  require(config.ebpf.runqueue_threshold_us == 1000,
          "default eBPF runqueue threshold must be 1 ms");
  require(config.ebpf.offcpu_min_us == 200000 &&
              config.ebpf.offcpu_max_us == 5000000,
          "default eBPF off-CPU window must match the low-overhead profile");
  require(!config.ebpf.user_stack_enabled && !config.ebpf.kernel_stack_enabled,
          "L2 must keep off-CPU stack capture disabled by default");
  require(config.ebpf.stack_sample_rate == 16,
          "deep stack capture must default to 1/16 sampling");
  require(!config.ebpf.irq_enabled,
          "system-wide IRQ probes must be disabled by default");
  require(config.ebpf.auto_deep_enabled &&
              config.ebpf.auto_deep_seconds == 2 &&
              config.ebpf.auto_deep_max_tids == 2,
          "automatic L3 must use a bounded two-second window by default");
  require(config.ebpf.auto_deep_user_stack &&
              !config.ebpf.auto_deep_kernel_stack,
          "automatic L3 must start with sampled user stacks only");
  require(!config.lttng_events.empty() &&
              std::find(config.lttng_events.begin(), config.lttng_events.end(),
                        "ros2:callback_start") != config.lttng_events.end(),
          "LTTng must use an explicit ROS event allowlist");
  require(config.lttng_subbuf_size_kb == 256 && config.lttng_num_subbuf == 4,
          "LTTng must default to a bounded discard channel");
  require(config.ebpf.target_pids.empty(),
          "default eBPF PID whitelist must be empty and fail closed");
  require(config.ebpf.target_tids.empty(),
          "default eBPF TID whitelist must be empty and fail closed");
}

void test_legacy_ebpf_threshold_config() {
  const auto path = std::filesystem::temp_directory_path() /
                    ("perf_robot_config_test_" + std::to_string(::getpid()));
  {
    std::ofstream output(path);
    output << "ebpf_threshold_us=2345\n";
    output << "ebpf_target_pids=123, 456\n";
    output << "ebpf_target_tids=789, 790\n";
    output << "ebpf_offcpu_stack_enabled=true\n";
  }
  const auto config = perf_robot::Config::load(path);
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
  require(config.ebpf.runqueue_threshold_us == 2345,
          "legacy eBPF threshold key must remain compatible");
  require(config.ebpf.target_pids.size() == 2 &&
              config.ebpf.target_pids[0] == 123 &&
              config.ebpf.target_pids[1] == 456,
          "eBPF target PID whitelist must be parsed");
  require(config.ebpf.target_tids.size() == 2 &&
              config.ebpf.target_tids[0] == 789 &&
              config.ebpf.target_tids[1] == 790,
          "eBPF target TID whitelist must be parsed");
  require(config.ebpf.user_stack_enabled && config.ebpf.kernel_stack_enabled,
          "legacy stack switch must enable both stack types");
}

void test_bounded_flight_recorder() {
  perf_robot::FlightRecorder recorder(2);
  recorder.push(perf_robot::Sample{1});
  recorder.push(perf_robot::Sample{2});
  recorder.push(perf_robot::Sample{3});
  const auto snapshot = recorder.snapshot();
  require(snapshot.size() == 2, "recorder must stay bounded");
  require(snapshot.front().sequence == 2, "recorder must overwrite oldest sample");
  require(recorder.overwritten() == 1, "overwrite count must be reported");
}

void test_state_machine() {
  using namespace std::chrono_literals;
  perf_robot::CaptureStateMachine machine;
  const auto now = std::chrono::steady_clock::now();
  require(machine.begin_capture(now, 1s), "normal must enter capturing");
  require(!machine.begin_capture(now, 1s), "capture must not re-enter");
  require(machine.capture_expired(now + 1s), "capture deadline must expire");
  machine.begin_sealing();
  machine.begin_cooldown(now + 1s, 1s);
  require(machine.update_cooldown(now + 2s), "cooldown must return to normal");
}

void test_trigger_policy_requires_consecutive_hits() {
  perf_robot::Config config;
  config.cpu_trigger_percent = 80.0;
  config.trigger_consecutive_samples = 3;
  perf_robot::TriggerPolicy policy(config);
  perf_robot::Sample sample;
  sample.values["cpu.busy_percent"] = 90.0;
  require(!policy.evaluate(sample), "first threshold hit must not trigger");
  require(!policy.evaluate(sample), "second threshold hit must not trigger");
  const auto reason = policy.evaluate(sample);
  require(reason && *reason == "auto-high-cpu", "third threshold hit must trigger");

  sample.values["cpu.busy_percent"] = 10.0;
  require(!policy.evaluate(sample), "normal sample must reset trigger counter");
}

void test_async_burst_manager() {
  FakeBurstState state;
  perf_robot::BurstManager manager;
  manager.add(std::make_unique<FakeBurstCollector>(state));
  const auto root = std::filesystem::temp_directory_path() /
                    ("perf_robot_burst_test_" + std::to_string(::getpid()));
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  require(manager.start_async(root, "test-incident"), "burst worker must start");
  for (int attempt = 0; attempt < 100 && !state.started; ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  require(state.started, "burst collector start must run on worker");
  manager.request_stop();
  pollfd descriptor{manager.completion_fd(), POLLIN, 0};
  require(::poll(&descriptor, 1, 2000) == 1, "burst completion must signal eventfd");
  require(manager.consume_completion(), "burst completion must be consumable");
  require(state.stopped, "burst collector stop must run on worker");
  require(std::filesystem::exists(root / "status.json"), "burst status must be written");
  std::filesystem::remove_all(root, ignored);
}

void test_incident_manifest_has_exact_trigger_time() {
  const auto root = std::filesystem::temp_directory_path() /
                    ("perf_robot_incident_test_" + std::to_string(::getpid()));
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  perf_robot::Incident incident;
  incident.id = "test-incident";
  incident.trigger = "unit-test";
  incident.trigger_monotonic_ns = 123456789;
  incident.trigger_realtime_ns = 987654321;
  perf_robot::IncidentRepository repository(root);
  const auto path = repository.save(incident);
  std::ifstream input(path / "manifest.json");
  const std::string manifest((std::istreambuf_iterator<char>(input)),
                             std::istreambuf_iterator<char>());
  require(manifest.find("\"schema_version\": 2") != std::string::npos,
          "incident manifest schema must be version 2");
  require(manifest.find("\"trigger_monotonic_ns\": 123456789") != std::string::npos,
          "incident manifest must contain exact monotonic trigger time");
  require(manifest.find("\"trigger_realtime_ns\": 987654321") != std::string::npos,
          "incident manifest must contain exact realtime trigger time");
  std::filesystem::remove_all(root, ignored);
}

void test_burst_child_resets_inherited_signal_mask() {
  perf_robot::Config config;
  config.l2_ebpf_enabled = true;
  config.ebpf_runner_path = PERF_ROBOT_SIGNAL_PROBE_PATH;
  config.ebpf_object_path = PERF_ROBOT_SIGNAL_PROBE_PATH;
  auto collector = perf_robot::make_ebpf_burst_collector(config);
  const auto root = std::filesystem::temp_directory_path() /
                    ("perf_robot_signal_test_" + std::to_string(::getpid()));
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);

  sigset_t blocked;
  sigset_t previous;
  ::sigemptyset(&blocked);
  ::sigaddset(&blocked, SIGINT);
  ::sigaddset(&blocked, SIGTERM);
  require(::sigprocmask(SIG_BLOCK, &blocked, &previous) == 0,
          "test must block shutdown signals before fork");
  collector->start(root, "signal-test");
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  collector->stop();
  const auto report = collector->report();
  require(::sigprocmask(SIG_SETMASK, &previous, nullptr) == 0,
          "test must restore its signal mask");

  require(report.started, "signal probe must start through eBPF adapter");
  require(report.stopped, "signal probe must stop through eBPF adapter");
  require(report.exit_code == 0,
          "fork/exec child must receive SIGINT instead of escalating to SIGKILL");
  require(std::filesystem::exists(root / "ebpf" / "runner.conf"),
          "eBPF adapter must hand options to the runner through runner.conf");
  std::filesystem::remove_all(root, ignored);
}


std::string read_file(const std::filesystem::path &path) {
  std::ifstream input(path);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void test_ebpf_options_round_trip() {
  perf_robot::EbpfOptions options;
  options.runqueue_threshold_us = 4321;
  options.offcpu_min_us = 1000;
  options.offcpu_max_us = 2000;
  options.user_stack_enabled = true;
  options.stack_sample_rate = 4;
  options.irq_enabled = true;
  options.auto_deep_enabled = false;
  options.target_pids = {11, 22};
  options.target_tids = {33};
  const auto path = std::filesystem::temp_directory_path() /
                    ("perf_robot_runner_conf_" + std::to_string(::getpid()));
  {
    std::ofstream output(path);
    options.write(output);
  }
  const auto loaded = perf_robot::EbpfOptions::load(path);
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
  require(loaded.runqueue_threshold_us == 4321 && loaded.offcpu_min_us == 1000 &&
              loaded.offcpu_max_us == 2000 && loaded.user_stack_enabled &&
              !loaded.kernel_stack_enabled && loaded.stack_sample_rate == 4 &&
              loaded.irq_enabled && !loaded.auto_deep_enabled,
          "runner.conf must round-trip every scalar eBPF option");
  require(loaded.target_pids == std::vector<int>({11, 22}) &&
              loaded.target_tids == std::vector<int>({33}),
          "runner.conf must round-trip eBPF target lists");

  {
    std::ofstream output(path);
    output << "sample_hz=10\n";
  }
  bool rejected = false;
  try {
    (void)perf_robot::EbpfOptions::load(path);
  } catch (const std::exception &) {
    rejected = true;
  }
  std::filesystem::remove(path, ignored);
  require(rejected, "runner.conf must reject non-eBPF keys");

  perf_robot::EbpfOptions invalid;
  invalid.stack_sample_rate = 3;
  rejected = false;
  try {
    invalid.validate();
  } catch (const std::exception &) {
    rejected = true;
  }
  require(rejected, "eBPF validation must reject a non power-of-two sample rate");
}

void test_json_escape_control_characters() {
  require(perf_robot::json_escape(std::string("a\"b\\\n\x01", 6)) == "a\\\"b\\\\\\n\\u0001",
          "json_escape must escape quotes, backslashes and all control characters");
}

void test_incident_moves_burst_artifacts() {
  const auto root = std::filesystem::temp_directory_path() /
                    ("perf_robot_move_test_" + std::to_string(::getpid()));
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  const auto staging = root / ".burst-move";
  std::filesystem::create_directories(staging / "ebpf");
  std::ofstream(staging / "ebpf" / "kernel_events.jsonl") << "{}\n";

  perf_robot::Incident incident;
  incident.id = "move-incident";
  incident.artifact_root = staging;
  const auto path = perf_robot::IncidentRepository(root).save(incident);
  const auto manifest = read_file(path / "manifest.json");
  require(std::filesystem::exists(path / "burst" / "ebpf" / "kernel_events.jsonl"),
          "burst artifacts must be attached to the incident");
  require(!std::filesystem::exists(staging), "burst staging directory must be moved, not copied");
  require(manifest.find("\"burst_artifacts\": true") != std::string::npos &&
              manifest.find("\"burst_error\": \"\"") != std::string::npos,
          "manifest must report attached burst artifacts without error");
  std::filesystem::remove_all(root, ignored);
}

void test_async_incident_writer() {
  const auto root = std::filesystem::temp_directory_path() /
                    ("perf_robot_writer_test_" + std::to_string(::getpid()));
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  perf_robot::IncidentRepository repository(root);
  perf_robot::AsyncIncidentWriter writer(repository);
  perf_robot::Incident incident;
  incident.id = "async-incident";
  incident.pre_trigger.push_back(perf_robot::Sample{1});
  require(writer.start(std::move(incident)), "writer must accept an incident when idle");
  require(writer.active(), "writer must report an active write");
  require(!writer.start(perf_robot::Incident{}), "writer must refuse a second concurrent write");
  pollfd descriptor{writer.completion_fd(), POLLIN, 0};
  require(::poll(&descriptor, 1, 2000) == 1, "incident write completion must signal eventfd");
  require(writer.consume_completion(), "incident write completion must be consumable");
  require(!writer.active(), "writer must be idle after completion");
  require(std::filesystem::exists(root / "async-incident" / "COMPLETE"),
          "async writer must produce a complete incident");
  std::filesystem::remove_all(root, ignored);
}

int connect_control(const std::string &address) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  require(fd >= 0, "test client socket must open");
  sockaddr_un endpoint{};
  endpoint.sun_family = AF_UNIX;
  std::memcpy(endpoint.sun_path + 1, address.data() + 1, address.size() - 1);
  const auto length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + address.size());
  require(::connect(fd, reinterpret_cast<const sockaddr *>(&endpoint), length) == 0,
          "test client must connect to the control socket");
  timeval timeout{2, 0};
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  return fd;
}

std::string read_response(int fd) {
  std::string response;
  char buffer[256];
  for (;;) {
    const auto bytes = ::recv(fd, buffer, sizeof(buffer), 0);
    if (bytes <= 0) break;
    response.append(buffer, static_cast<std::size_t>(bytes));
  }
  ::close(fd);
  return response;
}

void test_control_server_waits_for_late_command() {
  const std::string address = "@perf_robot_test_" + std::to_string(::getpid());
  perf_robot::ControlServer server(address);
  std::vector<std::string> received;
  const auto handler = [&received](const std::string &command) {
    received.push_back(command);
    return std::string("{\"ok\":true}");
  };

  // Connection accepted before any byte arrives: must stay pending instead of
  // being answered with "empty command" (the former EAGAIN race).
  const int client = connect_control(address);
  server.drain(handler);
  require(received.empty(), "server must not dispatch before a command arrives");
  require(::send(client, "sta", 3, 0) == 3, "test client must send first fragment");
  server.drain(handler);
  require(received.empty(), "server must buffer a partial command");
  require(::send(client, "tus\n", 4, 0) == 4, "test client must send second fragment");
  server.drain(handler);
  require(received.size() == 1 && received.front() == "status",
          "server must reassemble a fragmented command");
  require(read_response(client) == "{\"ok\":true}\n", "client must receive the response");

  // A client that never sends anything is answered and closed on timeout.
  const int idle = connect_control(address);
  server.drain(handler);
  std::this_thread::sleep_for(perf_robot::ControlServer::kClientTimeout +
                              std::chrono::milliseconds(50));
  server.expire_idle_clients();
  require(read_response(idle).find("timeout") != std::string::npos,
          "idle control client must be closed with a timeout error");
  require(received.size() == 1, "timed-out client must not dispatch a command");
}
}  // namespace

int main() {
  try {
    test_default_rate_and_capacity();
    test_legacy_ebpf_threshold_config();
    test_bounded_flight_recorder();
    test_state_machine();
    test_trigger_policy_requires_consecutive_hits();
    test_async_burst_manager();
    test_incident_manifest_has_exact_trigger_time();
    test_burst_child_resets_inherited_signal_mask();
    test_ebpf_options_round_trip();
    test_json_escape_control_characters();
    test_incident_moves_burst_artifacts();
    test_async_incident_writer();
    test_control_server_waits_for_late_command();
    std::cout << "all perf_robot tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "test failed: " << error.what() << '\n';
    return 1;
  }
}
