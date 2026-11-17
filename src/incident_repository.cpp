#include "perf_robot/incident_repository.hpp"

#include "perf_robot/json.hpp"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace perf_robot {
namespace {

void write_samples(const std::filesystem::path &path, const std::vector<Sample> &samples) {
  std::ofstream output(path, std::ios::trunc);
  if (!output) throw std::runtime_error("cannot write " + path.string());
  output << std::setprecision(15);
  for (const auto &sample : samples) {
    output << "{\"sequence\":" << sample.sequence
           << ",\"monotonic_ns\":" << sample.monotonic_ns
           << ",\"realtime_ns\":" << sample.realtime_ns
           << ",\"values\":{";
    bool first = true;
    for (const auto &[key, value] : sample.values) {
      if (!first) output << ',';
      first = false;
      output << '"' << json_escape(key) << "\":" << value;
    }
    output << "}}\n";
  }
  output.flush();
  if (!output) throw std::runtime_error("failed writing " + path.string());
}

// Moves the burst staging directory into the incident. The staging directory
// lives under the incident root, so a rename is the normal path and costs no
// data copy. A failure is recorded and never discards the baseline samples;
// if the data cannot be attached, the staging directory is left in place.
bool attach_burst_artifacts(const std::filesystem::path &staging,
                            const std::filesystem::path &destination,
                            std::string &error_message) {
  std::error_code error;
  if (staging.empty() || !std::filesystem::exists(staging, error)) return false;
  std::filesystem::rename(staging, destination, error);
  if (!error) return true;

  // Fallback for EXDEV and similar: copy, then remove the source.
  const auto rename_error = error.message();
  error.clear();
  std::filesystem::copy(staging, destination, std::filesystem::copy_options::recursive, error);
  if (error) {
    error_message = "cannot attach burst artifacts (rename: " + rename_error +
                    ", copy: " + error.message() + "); left at " + staging.string();
    std::error_code ignored;
    std::filesystem::remove_all(destination, ignored);
    return false;
  }
  std::error_code ignored;
  std::filesystem::remove_all(staging, ignored);
  return true;
}

}  // namespace

IncidentRepository::IncidentRepository(std::filesystem::path root) : root_(std::move(root)) {}

std::filesystem::path IncidentRepository::save(const Incident &incident) const {
  std::filesystem::create_directories(root_);
  const auto temporary = root_ / ("." + incident.id + ".tmp");
  const auto complete = root_ / incident.id;
  std::filesystem::create_directory(temporary);

  bool have_artifacts = false;
  try {
    write_samples(temporary / "pre_trigger.jsonl", incident.pre_trigger);
    write_samples(temporary / "post_trigger.jsonl", incident.post_trigger);
    std::string burst_error;
    have_artifacts =
        attach_burst_artifacts(incident.artifact_root, temporary / "burst", burst_error);

    std::ofstream manifest(temporary / "manifest.json.tmp", std::ios::trunc);
    if (!manifest) throw std::runtime_error("cannot write incident manifest");
    manifest << "{\n"
             << "  \"schema_version\": 2,\n"
             << "  \"incident_id\": \"" << json_escape(incident.id) << "\",\n"
             << "  \"trigger\": \"" << json_escape(incident.trigger) << "\",\n"
             << "  \"trigger_monotonic_ns\": " << incident.trigger_monotonic_ns << ",\n"
             << "  \"trigger_realtime_ns\": " << incident.trigger_realtime_ns << ",\n"
             << "  \"pre_trigger_samples\": " << incident.pre_trigger.size() << ",\n"
             << "  \"post_trigger_samples\": " << incident.post_trigger.size() << ",\n"
             << "  \"burst_artifacts\": " << (have_artifacts ? "true" : "false") << ",\n"
             << "  \"burst_error\": \"" << json_escape(burst_error) << "\",\n"
             << "  \"overwritten_samples\": " << incident.overwritten_samples << "\n"
             << "}\n";
    manifest.close();
    if (!manifest) throw std::runtime_error("failed writing incident manifest");
    std::filesystem::rename(temporary / "manifest.json.tmp", temporary / "manifest.json");
    std::ofstream(temporary / "COMPLETE") << "complete\n";
    std::filesystem::rename(temporary, complete);
  } catch (...) {
    std::error_code ignored;
    // Never delete burst data that was already moved in: put it back.
    if (have_artifacts) {
      std::filesystem::rename(temporary / "burst", incident.artifact_root, ignored);
    }
    std::filesystem::remove_all(temporary, ignored);
    throw;
  }
  return complete;
}

}  // namespace perf_robot
