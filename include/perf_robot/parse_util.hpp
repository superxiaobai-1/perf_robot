#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

// Shared key=value parsing helpers. Used by the Agent's Config loader and by
// the eBPF runner, so both sides accept exactly the same syntax.
namespace perf_robot {

std::string trim(std::string value);
unsigned parse_unsigned(const std::string &key, const std::string &value);
double parse_double(const std::string &key, const std::string &value);
bool parse_bool(const std::string &key, const std::string &value);
// Comma-separated numeric IDs; empty items are ignored and duplicates dropped
// while preserving first-seen order.
std::vector<int> parse_pids(const std::string &key, const std::string &value,
                            bool allow_zero);
std::vector<std::string> parse_strings(const std::string &value);

// Reads "key=value" lines, skipping blanks and '#' comments. Throws on a
// malformed line or an unreadable file.
void for_each_config_entry(
    const std::filesystem::path &path,
    const std::function<void(const std::string &key, const std::string &value)> &handler);

}  // namespace perf_robot
