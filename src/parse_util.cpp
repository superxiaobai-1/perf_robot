#include "perf_robot/parse_util.hpp"

#include <algorithm>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace perf_robot {

std::string trim(std::string value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return {};
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

unsigned parse_unsigned(const std::string &key, const std::string &value) {
  std::size_t parsed = 0;
  unsigned long number = 0;
  try {
    number = std::stoul(value, &parsed);
  } catch (const std::exception &) {
    throw std::runtime_error("invalid unsigned value for " + key);
  }
  if (parsed != value.size() || value.front() == '-' ||
      number > std::numeric_limits<unsigned>::max()) {
    throw std::runtime_error("invalid unsigned value for " + key);
  }
  return static_cast<unsigned>(number);
}

double parse_double(const std::string &key, const std::string &value) {
  std::size_t parsed = 0;
  double number = 0.0;
  try {
    number = std::stod(value, &parsed);
  } catch (const std::exception &) {
    throw std::runtime_error("invalid number for " + key);
  }
  if (parsed != value.size()) throw std::runtime_error("invalid number for " + key);
  return number;
}

bool parse_bool(const std::string &key, const std::string &value) {
  if (value == "true" || value == "1") return true;
  if (value == "false" || value == "0") return false;
  throw std::runtime_error("invalid boolean for " + key);
}

std::vector<int> parse_pids(const std::string &key, const std::string &value,
                            bool allow_zero) {
  std::vector<int> pids;
  std::istringstream input(value);
  std::string item;
  while (std::getline(input, item, ',')) {
    item = trim(item);
    if (item.empty()) continue;
    std::size_t parsed = 0;
    long pid = 0;
    try {
      pid = std::stol(item, &parsed);
    } catch (const std::exception &) {
      throw std::runtime_error("invalid PID in " + key);
    }
    if (parsed != item.size() || pid < (allow_zero ? 0 : 1) ||
        pid > std::numeric_limits<int>::max()) {
      throw std::runtime_error("invalid PID in " + key);
    }
    const auto id = static_cast<int>(pid);
    if (std::find(pids.begin(), pids.end(), id) == pids.end()) pids.push_back(id);
  }
  return pids;
}

std::vector<std::string> parse_strings(const std::string &value) {
  std::vector<std::string> items;
  std::istringstream input(value);
  std::string item;
  while (std::getline(input, item, ',')) {
    item = trim(item);
    if (!item.empty()) items.push_back(std::move(item));
  }
  return items;
}

void for_each_config_entry(
    const std::filesystem::path &path,
    const std::function<void(const std::string &, const std::string &)> &handler) {
  std::ifstream input(path);
  if (!input) throw std::runtime_error("cannot open config: " + path.string());
  std::string line;
  unsigned line_number = 0;
  while (std::getline(input, line)) {
    ++line_number;
    line = trim(line);
    if (line.empty() || line.front() == '#') continue;
    const auto separator = line.find('=');
    if (separator == std::string::npos) {
      throw std::runtime_error("invalid config line " + std::to_string(line_number) +
                               " in " + path.string());
    }
    handler(trim(line.substr(0, separator)), trim(line.substr(separator + 1)));
  }
}

}  // namespace perf_robot
