#pragma once

#include <chrono>
#include <functional>
#include <string>
#include <unordered_map>

namespace perf_robot {

// Line-oriented control endpoint on a Linux abstract Unix socket.
//
// fd() is an internal epoll descriptor that watches the listening socket and
// every pending client. The Agent adds it to its own epoll set, so neither
// accepting nor reading ever blocks the 10 Hz loop: a client whose command has
// not arrived yet simply stays pending until its data (or a timeout) arrives.
class ControlServer {
 public:
  explicit ControlServer(const std::string &address);
  ~ControlServer();

  ControlServer(const ControlServer &) = delete;
  ControlServer &operator=(const ControlServer &) = delete;

  int fd() const noexcept { return epoll_fd_; }
  // Handles everything currently ready. Call when fd() is readable.
  void drain(const std::function<std::string(const std::string &)> &handler);
  // Answers and closes clients that never completed a command. Cheap when no
  // client is pending; call periodically.
  void expire_idle_clients();

  static constexpr std::size_t kMaxPendingClients = 16;
  static constexpr std::size_t kMaxCommandBytes = 255;
  static constexpr std::chrono::milliseconds kClientTimeout{1000};

 private:
  struct Client {
    std::string buffer;
    std::chrono::steady_clock::time_point deadline;
  };

  void accept_clients();
  void read_client(int client_fd,
                   const std::function<std::string(const std::string &)> &handler);
  void respond_and_close(int client_fd, std::string response) noexcept;

  int listen_fd_{-1};
  int epoll_fd_{-1};
  std::unordered_map<int, Client> clients_;
};

}  // namespace perf_robot
