#include "perf_robot/incident_writer.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <sys/eventfd.h>
#include <unistd.h>

namespace perf_robot {

AsyncIncidentWriter::AsyncIncidentWriter(const IncidentRepository &repository)
    : repository_(repository),
      completion_fd_(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)) {
  if (completion_fd_ < 0) throw std::runtime_error("cannot create incident writer eventfd");
}

AsyncIncidentWriter::~AsyncIncidentWriter() {
  wait();
  if (completion_fd_ >= 0) ::close(completion_fd_);
}

void AsyncIncidentWriter::write(const Incident &incident) noexcept {
  try {
    const auto path = repository_.save(incident);
    std::cerr << "incident saved: " << path << '\n';
  } catch (const std::exception &error) {
    std::cerr << "incident save failed: " << error.what() << '\n';
  } catch (...) {
    std::cerr << "incident save failed: unknown error\n";
  }
}

void AsyncIncidentWriter::signal_completion() noexcept {
  const std::uint64_t completed = 1;
  // A saturated nonblocking counter is harmless: one pending completion is
  // enough to wake the epoll loop.
  (void)!::write(completion_fd_, &completed, sizeof(completed));
}

bool AsyncIncidentWriter::start(Incident incident) noexcept {
  if (active_) return false;
  active_ = true;
  // Owned by the writer, not the thread closure, so the data survives a
  // failed thread creation. Only the worker touches it until completion.
  pending_ = std::move(incident);
  try {
    worker_ = std::thread([this]() noexcept {
      write(pending_);
      signal_completion();
    });
  } catch (...) {
    std::cerr << "incident writer thread could not start; saving synchronously\n";
    write(pending_);
    signal_completion();
  }
  return true;
}

bool AsyncIncidentWriter::consume_completion() noexcept {
  std::uint64_t completed = 0;
  if (::read(completion_fd_, &completed, sizeof(completed)) != sizeof(completed)) return false;
  if (worker_.joinable()) worker_.join();
  pending_ = Incident{};
  active_ = false;
  return true;
}

void AsyncIncidentWriter::wait() noexcept {
  if (worker_.joinable()) worker_.join();
  std::uint64_t completed = 0;
  (void)!::read(completion_fd_, &completed, sizeof(completed));
  pending_ = Incident{};
  active_ = false;
}

}  // namespace perf_robot
