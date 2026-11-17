#!/usr/bin/env python3

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "perf_robot_report.py"


class PerfRobotReportTest(unittest.TestCase):
    def test_converts_metrics_trigger_and_ebpf(self):
        with tempfile.TemporaryDirectory() as directory:
            incident = Path(directory) / "incident-1"
            ebpf = incident / "burst" / "ebpf"
            ebpf.mkdir(parents=True)
            lttng = incident / "burst" / "lttng"
            lttng.mkdir()
            (lttng / "control.log").write_text(
                "    Statistics:\n      Discarded events: 3\n", encoding="utf-8"
            )
            (incident / "manifest.json").write_text(
                json.dumps({"schema_version": 1, "incident_id": "incident-1", "trigger": "test"}),
                encoding="utf-8",
            )
            (incident / "burst" / "status.json").write_text(
                json.dumps({"collectors": [{"name": "libbpf_kernel_events",
                                              "start_attempted": True, "started": True,
                                              "stopped": True, "exit_code": 0, "error": ""}]}),
                encoding="utf-8",
            )
            pre = {
                "sequence": 1,
                "monotonic_ns": 1_000_000_000,
                "realtime_ns": 5_000_000_000,
                "values": {"cpu.busy_percent": 10.0, "memory.available_bytes": 1000},
            }
            post = {
                "sequence": 2,
                "monotonic_ns": 1_100_000_000,
                "realtime_ns": 5_100_000_000,
                "values": {"cpu.busy_percent": 90.0, "memory.available_bytes": 900},
            }
            (incident / "pre_trigger.jsonl").write_text(json.dumps(pre) + "\n", encoding="utf-8")
            (incident / "post_trigger.jsonl").write_text(json.dumps(post) + "\n", encoding="utf-8")
            events = [
                {"type": "off_cpu", "monotonic_ns": 1_150_000_000,
                 "duration_ns": 50_000_000, "tid": 42, "tgid": 40, "cpu": 2,
                 "task_state": 1, "comm": "camera", "user_stack_id": 7,
                 "kernel_stack_id": 8, "waker_pid": 40, "waker_tid": 43,
                 "waker_comm": "dds-worker"},
                {"type": "stack_trace", "stack_id": 7, "frames": ["0x1100"]},
                {"type": "stack_trace", "stack_id": 8, "frames": ["0x2200"]},
                {"type": "process_maps", "tgid": 40,
                 "maps": ["1000-2000 r-xp 00000000 00:00 0 /missing/libcamera.so"]},
                {"type": "summary", "wakeups": 3, "offcpu_emitted": 1,
                 "ringbuf_drops": 0, "target_filter_enabled": True,
                 "target_pid_count": 1, "target_pids": [40],
                 "offcpu_stack_enabled": True, "stack_records": 2},
            ]
            (ebpf / "kernel_events.jsonl").write_text(
                "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
            )

            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(incident), "--skip-lttng"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            derived = incident / "derived"
            summary = json.loads((derived / "summary.json").read_text(encoding="utf-8"))
            trace = json.loads((derived / "incident.perfetto.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["samples"]["count"], 2)
            self.assertEqual(summary["ebpf"]["counts"], {"off_cpu": 1})
            self.assertEqual(summary["ebpf"]["ringbuf_drops"], 0)
            self.assertTrue(summary["ebpf"]["summary_present"])
            self.assertTrue(summary["ebpf"]["target_filter_enabled"])
            self.assertEqual(summary["ebpf"]["target_pids"], [40])
            self.assertEqual(summary["ebpf"]["stack_records"], 2)
            self.assertEqual(summary["ebpf"]["symbolized_offcpu_events"], 1)
            self.assertEqual(summary["ros2"]["discarded_events"], 3)
            self.assertIn("白名单进程：40", (derived / "report.html").read_text(encoding="utf-8"))
            off_cpu = next(event for event in trace["traceEvents"]
                           if event.get("name") == "off_cpu")
            self.assertEqual(off_cpu["args"]["waker_tid"], 43)
            self.assertEqual(
                off_cpu["args"]["user_stack_leaf_first"], ["libcamera.so+0x100"]
            )
            phases = {event["ph"] for event in trace["traceEvents"]}
            self.assertIn("C", phases)
            self.assertIn("X", phases)
            self.assertIn("i", phases)
            self.assertTrue((derived / "report.html").is_file())

    def test_rejects_non_incident_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), directory, "--skip-lttng"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("not a perf_robot incident", result.stderr)


if __name__ == "__main__":
    unittest.main()
