#pragma once

#include "perf_robot/config.hpp"

#include <filesystem>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace perf_robot {

struct BurstReport {
  std::string name;
  bool start_attempted{false};
  bool started{false};
  bool stopped{false};
  int exit_code{0};
  std::string error;
};

class IBurstCollector {
 public:
  virtual ~IBurstCollector() = default;
  virtual std::string name() const = 0;
  virtual void start(const std::filesystem::path &artifact_root,
                     const std::string &incident_id) = 0;
  virtual void stop() noexcept = 0;
  virtual BurstReport report() const = 0;
};

class BurstManager {
 public:
  BurstManager();
  ~BurstManager();

  BurstManager(const BurstManager &) = delete;
  BurstManager &operator=(const BurstManager &) = delete;

  void add(std::unique_ptr<IBurstCollector> collector);
  bool start_async(const std::filesystem::path &artifact_root,
                   const std::string &incident_id) noexcept;
  void request_stop() noexcept;
  int completion_fd() const noexcept { return completion_fd_; }
  bool consume_completion() noexcept;
  void wait_for_completion() noexcept;

 private:
  void worker_main(std::filesystem::path artifact_root,
                   std::string incident_id) noexcept;
  void write_status(const std::filesystem::path &artifact_root) const noexcept;

  std::vector<std::unique_ptr<IBurstCollector>> collectors_;
  int completion_fd_{-1};
  std::thread worker_;
  std::mutex mutex_;
  std::condition_variable stop_condition_;
  bool running_{false};
  bool stop_requested_{false};
};

std::unique_ptr<IBurstCollector> make_lttng_burst_collector(const Config &config);
std::unique_ptr<IBurstCollector> make_ebpf_burst_collector(const Config &config);

}  // namespace perf_robot
