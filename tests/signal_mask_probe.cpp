#include <csignal>
#include <unistd.h>

namespace {

volatile std::sig_atomic_t stop_requested = 0;

void handle_signal(int) { stop_requested = 1; }

}  // namespace

int main() {
  sigset_t current;
  if (::sigprocmask(SIG_SETMASK, nullptr, &current) != 0) return 41;
  if (::sigismember(&current, SIGINT) == 1 ||
      ::sigismember(&current, SIGTERM) == 1) {
    return 42;
  }
  if (std::signal(SIGINT, handle_signal) == SIG_ERR ||
      std::signal(SIGTERM, handle_signal) == SIG_ERR) {
    return 43;
  }
  while (!stop_requested) ::pause();
  return 0;
}
