#include "perf_robot/control_server.hpp"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

namespace perf_robot {
namespace {

std::runtime_error socket_error(const char *operation) {
  return std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
}

void send_and_close(int fd, const std::string &response) noexcept {
  (void)::send(fd, response.data(), response.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
  ::close(fd);
}

bool add_to_epoll(int epoll_fd, int fd) noexcept {
  epoll_event event{};
  event.events = EPOLLIN | EPOLLRDHUP;
  event.data.fd = fd;
  return ::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == 0;
}

std::string strip_command(std::string command) {
  while (!command.empty() &&
         (command.back() == '\n' || command.back() == '\r' || command.back() == ' ')) {
    command.pop_back();
  }
  return command;
}

}  // namespace

ControlServer::ControlServer(const std::string &address) {
  if (address.size() < 2 || address.front() != '@') {
    throw std::invalid_argument("control address must begin with @");
  }
  if (address.size() > sizeof(sockaddr_un::sun_path)) {
    throw std::invalid_argument("control address is too long");
  }

  listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (listen_fd_ < 0) throw socket_error("socket");

  sockaddr_un endpoint{};
  endpoint.sun_family = AF_UNIX;
  endpoint.sun_path[0] = '\0';
  std::memcpy(endpoint.sun_path + 1, address.data() + 1, address.size() - 1);
  const auto length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + address.size());
  try {
    if (::bind(listen_fd_, reinterpret_cast<const sockaddr *>(&endpoint), length) != 0) {
      throw socket_error("bind control socket");
    }
    if (::listen(listen_fd_, 16) != 0) throw socket_error("listen control socket");
    epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) throw socket_error("control epoll_create1");
    if (!add_to_epoll(epoll_fd_, listen_fd_)) throw socket_error("control epoll_ctl");
  } catch (...) {
    if (epoll_fd_ >= 0) ::close(epoll_fd_);
    ::close(listen_fd_);
    epoll_fd_ = -1;
    listen_fd_ = -1;
    throw;
  }
}

ControlServer::~ControlServer() {
  for (const auto &entry : clients_) ::close(entry.first);
  if (epoll_fd_ >= 0) ::close(epoll_fd_);
  if (listen_fd_ >= 0) ::close(listen_fd_);
}

void ControlServer::drain(const std::function<std::string(const std::string &)> &handler) {
  // Bounded so a flood of connections cannot monopolize the Agent loop; any
  // remaining readiness keeps fd() readable for the next epoll iteration.
  for (int round = 0; round < 64; ++round) {
    epoll_event events[16]{};
    const int count = ::epoll_wait(epoll_fd_, events, 16, 0);
    if (count < 0) {
      if (errno == EINTR) continue;
      throw socket_error("control epoll_wait");
    }
    if (count == 0) return;
    for (int index = 0; index < count; ++index) {
      if (events[index].data.fd == listen_fd_) accept_clients();
      else read_client(events[index].data.fd, handler);
    }
  }
}

void ControlServer::accept_clients() {
  for (;;) {
    const int client = ::accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (client < 0) {
      if (errno == EINTR) continue;
      // EAGAIN: drained. Anything else (ECONNABORTED, EMFILE, ...) only
      // affects this connection attempt and must not stop the Agent.
      return;
    }

    ucred credentials{};
    socklen_t credentials_size = sizeof(credentials);
    if (::getsockopt(client, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_size) != 0 ||
        credentials.uid != ::geteuid()) {
      send_and_close(client, "{\"ok\":false,\"error\":\"permission denied\"}\n");
      continue;
    }
    if (clients_.size() >= kMaxPendingClients) {
      send_and_close(client, "{\"ok\":false,\"error\":\"busy\"}\n");
      continue;
    }
    if (!add_to_epoll(epoll_fd_, client)) {
      send_and_close(client, "{\"ok\":false,\"error\":\"internal error\"}\n");
      continue;
    }
    clients_.emplace(client,
                     Client{{}, std::chrono::steady_clock::now() + kClientTimeout});
  }
}

void ControlServer::read_client(
    int client_fd, const std::function<std::string(const std::string &)> &handler) {
  const auto found = clients_.find(client_fd);
  if (found == clients_.end()) return;
  auto &buffer = found->second.buffer;

  bool complete = false;
  for (;;) {
    char chunk[256];
    const auto bytes = ::recv(client_fd, chunk, sizeof(chunk), 0);
    if (bytes > 0) {
      buffer.append(chunk, static_cast<std::size_t>(bytes));
      const auto newline = buffer.find('\n');
      if (newline != std::string::npos) {
        buffer.resize(newline);
        complete = true;
        break;
      }
      if (buffer.size() > kMaxCommandBytes) {
        respond_and_close(client_fd, "{\"ok\":false,\"error\":\"command too long\"}");
        return;
      }
      continue;
    }
    if (bytes == 0) {  // Peer finished sending without a trailing newline.
      if (buffer.empty()) {
        respond_and_close(client_fd, "{\"ok\":false,\"error\":\"empty command\"}");
        return;
      }
      complete = true;
      break;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return;  // Wait for the rest.
    respond_and_close(client_fd, {});
    return;
  }

  if (!complete) return;
  const auto command = strip_command(std::move(buffer));
  std::string response;
  try {
    response = handler(command);
  } catch (...) {
    respond_and_close(client_fd, "{\"ok\":false,\"error\":\"internal error\"}");
    throw;
  }
  respond_and_close(client_fd, std::move(response));
}

void ControlServer::respond_and_close(int client_fd, std::string response) noexcept {
  (void)::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, client_fd, nullptr);
  if (!response.empty() && response.back() != '\n') response.push_back('\n');
  send_and_close(client_fd, response);
  clients_.erase(client_fd);
}

void ControlServer::expire_idle_clients() {
  if (clients_.empty()) return;
  const auto now = std::chrono::steady_clock::now();
  std::vector<int> expired;
  for (const auto &[fd, client] : clients_) {
    if (now >= client.deadline) expired.push_back(fd);
  }
  for (const int fd : expired) {
    respond_and_close(fd, "{\"ok\":false,\"error\":\"timeout waiting for command\"}");
  }
}

}  // namespace perf_robot
