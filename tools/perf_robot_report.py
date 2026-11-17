#!/usr/bin/env python3
"""Convert a perf_robot incident package into an offline Perfetto report.

The generated trace uses the Chrome Trace Event JSON format, which Perfetto UI
can open directly. LTTng CTF ingestion is optional and uses Babeltrace 2's bt2
Python bindings when they are installed.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import html
import json
import math
import os
import statistics
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


METRICS_PID = 2_000_000_001
KERNEL_PID = 2_000_000_002
IRQ_PID = 2_000_000_003
INCIDENT_PID = 2_000_000_004


def read_json(path: Path, default: Any, warnings: list[str]) -> Any:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except FileNotFoundError:
        warnings.append(f"missing file: {path.relative_to(path.parent.parent) if path.parent.parent else path}")
    except (OSError, json.JSONDecodeError) as error:
        warnings.append(f"cannot read {path}: {error}")
    return default


def read_jsonl(path: Path, warnings: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        records.append(value)
                    else:
                        warnings.append(f"{path}:{line_number}: JSON value is not an object")
                except json.JSONDecodeError as error:
                    warnings.append(f"{path}:{line_number}: {error.msg}")
    except FileNotFoundError:
        return records
    except OSError as error:
        warnings.append(f"cannot read {path}: {error}")
    return records


def finite_number(value: Any) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def ns_to_us(value: int | float) -> float:
    return float(value) / 1000.0


def metadata_event(name: str, pid: int, tid: int, args: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "ph": "M", "pid": pid, "tid": tid, "args": args}


class TraceBuilder:
    def __init__(self) -> None:
        self.metadata: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self._processes: set[int] = set()
        self._threads: set[tuple[int, int]] = set()

    def process_name(self, pid: int, name: str) -> None:
        if pid in self._processes:
            return
        self._processes.add(pid)
        self.metadata.append(metadata_event("process_name", pid, 0, {"name": name}))

    def thread_name(self, pid: int, tid: int, name: str) -> None:
        key = (pid, tid)
        if key in self._threads:
            return
        self._threads.add(key)
        self.metadata.append(metadata_event("thread_name", pid, tid, {"name": name}))

    def add(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def payload(self) -> dict[str, Any]:
        self.events.sort(key=lambda event: (float(event.get("ts", 0)), event.get("ph", "")))
        return {
            "displayTimeUnit": "ns",
            "traceEvents": self.metadata + self.events,
            "otherData": {"generator": "perf_robot_report", "schema_version": 1},
        }


def load_samples(incident: Path, warnings: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pre = read_jsonl(incident / "pre_trigger.jsonl", warnings)
    post = read_jsonl(incident / "post_trigger.jsonl", warnings)
    by_sequence: dict[int, dict[str, Any]] = {}
    without_sequence: list[dict[str, Any]] = []
    for sample in pre + post:
        sequence = sample.get("sequence")
        if isinstance(sequence, int):
            by_sequence[sequence] = sample
        else:
            without_sequence.append(sample)
    all_samples = list(by_sequence.values()) + without_sequence
    all_samples.sort(key=lambda sample: int(sample.get("monotonic_ns", 0)))
    post.sort(key=lambda sample: int(sample.get("monotonic_ns", 0)))
    return all_samples, post


def clock_model(samples: list[dict[str, Any]]) -> dict[str, int]:
    offsets = []
    for sample in samples:
        monotonic = sample.get("monotonic_ns")
        realtime = sample.get("realtime_ns")
        if isinstance(monotonic, int) and isinstance(realtime, int):
            offsets.append(realtime - monotonic)
    offset = int(statistics.median(offsets)) if offsets else 0
    reference = samples[len(samples) // 2] if samples else {}
    return {
        "realtime_minus_monotonic_ns": offset,
        "reference_monotonic_ns": int(reference.get("monotonic_ns", 0)),
        "reference_realtime_ns": int(reference.get("realtime_ns", 0)),
    }


def normalize_external_clock(timestamp_ns: int, clock: dict[str, int]) -> int:
    reference_monotonic = clock["reference_monotonic_ns"]
    reference_realtime = clock["reference_realtime_ns"]
    if reference_monotonic == 0 or reference_realtime == 0:
        return timestamp_ns
    if abs(timestamp_ns - reference_realtime) < abs(timestamp_ns - reference_monotonic):
        return timestamp_ns - clock["realtime_minus_monotonic_ns"]
    return timestamp_ns


def add_metric_events(
    builder: TraceBuilder,
    samples: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, float | int]], dict[str, list[float]]]:
    builder.process_name(METRICS_PID, "System metrics (10 Hz)")
    values_by_metric: dict[str, list[float]] = collections.defaultdict(list)
    for sample in samples:
        timestamp = sample.get("monotonic_ns")
        values = sample.get("values")
        if not isinstance(timestamp, int) or not isinstance(values, dict):
            continue
        for name, raw_value in values.items():
            value = finite_number(raw_value)
            if value is None:
                continue
            numeric = float(value)
            values_by_metric[str(name)].append(numeric)
            builder.add({
                "name": str(name),
                "cat": "perf_robot.metrics",
                "ph": "C",
                "ts": ns_to_us(timestamp),
                "pid": METRICS_PID,
                "tid": 0,
                "args": {"value": value},
            })
    summaries: dict[str, dict[str, float | int]] = {}
    for name, values in values_by_metric.items():
        summaries[name] = {
            "samples": len(values),
            "min": min(values),
            "max": max(values),
            "average": sum(values) / len(values),
            "last": values[-1],
        }
    return summaries, values_by_metric


def add_trigger_event(
    builder: TraceBuilder,
    manifest: dict[str, Any],
    post_samples: list[dict[str, Any]],
    samples: list[dict[str, Any]],
    warnings: list[str],
) -> int:
    trigger_ns = manifest.get("trigger_monotonic_ns")
    if not isinstance(trigger_ns, int):
        source = post_samples[0] if post_samples else (samples[-1] if samples else {})
        trigger_ns = int(source.get("monotonic_ns", 0))
        if trigger_ns:
            warnings.append("trigger timestamp inferred from first post-trigger sample (up to one sample period error)")
    if trigger_ns:
        builder.process_name(INCIDENT_PID, "Incident")
        builder.add({
            "name": "TRIGGER",
            "cat": "perf_robot.incident",
            "ph": "i",
            "s": "g",
            "ts": ns_to_us(trigger_ns),
            "pid": INCIDENT_PID,
            "tid": 0,
            "args": {"reason": manifest.get("trigger", "unknown")},
        })
    return trigger_ns


def find_ebpf_path(incident: Path) -> Path | None:
    directory = incident / "burst" / "ebpf"
    for name in ("kernel_events.jsonl", "sched_latency.jsonl"):
        path = directory / name
        if path.exists():
            return path
    return None


def parse_stack_frames(record: dict[str, Any]) -> list[int]:
    result: list[int] = []
    for value in record.get("frames", []):
        try:
            result.append(int(value, 0) if isinstance(value, str) else int(value))
        except (TypeError, ValueError):
            continue
    return result


def parse_process_maps(lines: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if not isinstance(lines, list):
        return result
    for line in lines:
        if not isinstance(line, str):
            continue
        fields = line.split(None, 5)
        if len(fields) < 5 or "-" not in fields[0]:
            continue
        try:
            start_text, end_text = fields[0].split("-", 1)
            result.append({
                "start": int(start_text, 16),
                "end": int(end_text, 16),
                "perms": fields[1],
                "offset": int(fields[2], 16),
                "path": fields[5] if len(fields) > 5 else "",
            })
        except ValueError:
            continue
    return result


class OfflineSymbolizer:
    def __init__(self) -> None:
        self.addr2line = "addr2line"
        self.user_cache: dict[tuple[int, int], str] = {}
        self.elf_dyn_cache: dict[str, bool] = {}
        self.kernel_addresses: list[int] = []
        self.kernel_names: list[str] = []
        try:
            with open("/proc/kallsyms", "r", encoding="utf-8", errors="replace") as stream:
                pairs: list[tuple[int, str]] = []
                for line in stream:
                    fields = line.split()
                    if len(fields) >= 3:
                        try:
                            address = int(fields[0], 16)
                        except ValueError:
                            continue
                        if address:
                            pairs.append((address, fields[2]))
                pairs.sort()
                self.kernel_addresses = [item[0] for item in pairs]
                self.kernel_names = [item[1] for item in pairs]
        except OSError:
            pass

    def elf_is_dynamic(self, path: str) -> bool:
        if path in self.elf_dyn_cache:
            return self.elf_dyn_cache[path]
        dynamic = True
        try:
            with open(path, "rb") as stream:
                header = stream.read(18)
            if len(header) >= 18 and header[:4] == b"\x7fELF":
                endian = "<" if header[5] == 1 else ">"
                dynamic = struct.unpack(endian + "H", header[16:18])[0] == 3
        except OSError:
            pass
        self.elf_dyn_cache[path] = dynamic
        return dynamic

    def user_symbol(self, tgid: int, address: int,
                    mappings: dict[int, list[dict[str, Any]]]) -> str:
        cache_key = (tgid, address)
        if cache_key in self.user_cache:
            return self.user_cache[cache_key]
        for mapping in mappings.get(tgid, []):
            if not (mapping["start"] <= address < mapping["end"]):
                continue
            path = str(mapping["path"])
            if path.endswith(" (deleted)"):
                path = path[:-10]
            relative = address - mapping["start"] + mapping["offset"]
            fallback = f"{Path(path).name or '[anonymous]'}+0x{relative:x}"
            if not path.startswith("/") or not Path(path).is_file():
                self.user_cache[cache_key] = fallback
                return fallback
            query = relative if self.elf_is_dynamic(path) else address
            try:
                completed = subprocess.run(
                    [self.addr2line, "-f", "-C", "-e", path, hex(query)],
                    text=True, capture_output=True, timeout=2, check=False,
                )
                lines = completed.stdout.splitlines()
                function = lines[0].strip() if lines else "??"
                location = lines[1].strip() if len(lines) > 1 else "??:0"
                if completed.returncode == 0 and function not in ("", "??"):
                    result = f"{Path(path).name}!{function} ({location})"
                    self.user_cache[cache_key] = result
                    return result
            except (OSError, subprocess.SubprocessError):
                pass
            self.user_cache[cache_key] = fallback
            return fallback
        result = f"0x{address:x}"
        self.user_cache[cache_key] = result
        return result

    def kernel_symbol(self, address: int) -> str:
        if not self.kernel_addresses:
            return f"0x{address:x}"
        index = bisect.bisect_right(self.kernel_addresses, address) - 1
        if index < 0:
            return f"0x{address:x}"
        offset = address - self.kernel_addresses[index]
        return f"{self.kernel_names[index]}+0x{offset:x}"


def add_ebpf_events(
    builder: TraceBuilder,
    incident: Path,
    warnings: list[str],
) -> dict[str, Any]:
    path = find_ebpf_path(incident)
    result: dict[str, Any] = {
        "source": str(path.relative_to(incident)) if path else None,
        "events": 0,
        "counts": {},
        "max_duration_ns": {},
        "ringbuf_drops": None,
        "summary_present": False,
        "target_filter_enabled": None,
        "scheduler_enabled": None,
        "irq_enabled": None,
        "target_pids": [],
        "target_tids": [],
        "stack_records": 0,
        "process_map_snapshots": 0,
        "symbolized_offcpu_events": 0,
    }
    if path is None:
        warnings.append("eBPF event file is missing")
        return result

    counts: collections.Counter[str] = collections.Counter()
    maxima: dict[str, int] = {}
    records = read_jsonl(path, warnings)
    stack_traces: dict[int, list[int]] = {}
    process_mappings: dict[int, list[dict[str, Any]]] = {}
    for record in records:
        if record.get("type") == "stack_trace":
            try:
                stack_traces[int(record["stack_id"])] = parse_stack_frames(record)
            except (KeyError, TypeError, ValueError):
                continue
        elif record.get("type") == "process_maps":
            try:
                process_mappings[int(record["tgid"])] = parse_process_maps(record.get("maps"))
            except (KeyError, TypeError, ValueError):
                continue
    result["stack_records"] = len(stack_traces)
    result["process_map_snapshots"] = len(process_mappings)
    symbolizer = OfflineSymbolizer()
    missing_stack_ids: set[int] = set()
    builder.process_name(KERNEL_PID, "Kernel scheduler")
    builder.process_name(IRQ_PID, "Kernel IRQ")
    for record in records:
        event_type = str(record.get("type", "unknown"))
        if event_type in ("stack_trace", "process_maps"):
            continue
        if event_type == "summary":
            result["summary_present"] = True
            result["ringbuf_drops"] = record.get("ringbuf_drops")
            result["target_filter_enabled"] = record.get("target_filter_enabled")
            result["scheduler_enabled"] = record.get("scheduler_enabled")
            result["irq_enabled"] = record.get("irq_enabled")
            target_pids = record.get("target_pids", [])
            if isinstance(target_pids, list):
                result["target_pids"] = target_pids
            target_tids = record.get("target_tids", [])
            if isinstance(target_tids, list):
                result["target_tids"] = target_tids
            result["runner_summary"] = record
            continue
        timestamp = record.get("monotonic_ns")
        duration = record.get("duration_ns", record.get("latency_ns"))
        if not isinstance(timestamp, int) or not isinstance(duration, int) or duration < 0:
            warnings.append(f"invalid eBPF timestamp/duration in {path.name}")
            continue
        tid = int(record.get("tid", 0))
        tgid = int(record.get("tgid", 0))
        cpu = int(record.get("cpu", 0))
        comm = str(record.get("comm", ""))
        if event_type in ("softirq", "hardirq"):
            pid = IRQ_PID
            track_tid = cpu * 2 + (1 if event_type == "hardirq" else 0)
            builder.thread_name(pid, track_tid, f"CPU {cpu} {event_type}")
        else:
            pid = tgid if tgid > 0 else KERNEL_PID
            track_tid = tid
            builder.process_name(pid, comm or f"process {pid}")
            builder.thread_name(pid, track_tid, f"{comm or 'thread'} [{tid}]")
        arguments = {
            key: value for key, value in record.items()
            if key not in {"type", "monotonic_ns", "realtime_ns", "duration_ns", "latency_ns"}
        }
        if event_type == "off_cpu":
            user_stack_id = int(record.get("user_stack_id", -1))
            kernel_stack_id = int(record.get("kernel_stack_id", -1))
            user_frames = stack_traces.get(user_stack_id)
            kernel_frames = stack_traces.get(kernel_stack_id)
            if user_stack_id >= 0 and user_frames is None:
                missing_stack_ids.add(user_stack_id)
            if kernel_stack_id >= 0 and kernel_frames is None:
                missing_stack_ids.add(kernel_stack_id)
            if user_frames is not None:
                arguments["user_stack_leaf_first"] = [
                    symbolizer.user_symbol(tgid, address, process_mappings)
                    for address in user_frames
                ]
            if kernel_frames is not None:
                arguments["kernel_stack_leaf_first"] = [
                    symbolizer.kernel_symbol(address) for address in kernel_frames
                ]
            if user_frames is not None or kernel_frames is not None:
                result["symbolized_offcpu_events"] += 1
        arguments["duration_ns"] = duration
        builder.add({
            "name": event_type,
            "cat": "kernel.irq" if event_type in ("softirq", "hardirq") else "kernel.scheduler",
            "ph": "X",
            "ts": ns_to_us(timestamp - duration),
            "dur": ns_to_us(duration),
            "pid": pid,
            "tid": track_tid,
            "args": arguments,
        })
        counts[event_type] += 1
        maxima[event_type] = max(maxima.get(event_type, 0), duration)
    result["events"] = sum(counts.values())
    result["counts"] = dict(counts)
    result["max_duration_ns"] = maxima
    if missing_stack_ids:
        warnings.append(
            f"{len(missing_stack_ids)} referenced eBPF Stack IDs were unavailable at sealing"
        )
    return result


def bt_field_to_python(field: Any, depth: int = 0) -> Any:
    if field is None or depth > 5:
        return None
    if isinstance(field, (bool, int, float, str)):
        return field
    if isinstance(field, bytes):
        return field.hex()
    if hasattr(field, "items"):
        try:
            return {str(key): bt_field_to_python(value, depth + 1) for key, value in field.items()}
        except Exception:
            pass
    if not isinstance(field, (str, bytes)) and hasattr(field, "__iter__"):
        try:
            return [bt_field_to_python(value, depth + 1) for value in field]
        except Exception:
            pass
    for conversion in (int, float, str):
        try:
            return conversion(field)
        except (TypeError, ValueError):
            continue
    return repr(field)


def event_fields(event: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for attribute in (
        "common_context_field",
        "specific_context_field",
        "payload_field",
    ):
        converted = bt_field_to_python(getattr(event, attribute, None))
        if isinstance(converted, dict):
            result.update(converted)
    return result


def context_int(fields: dict[str, Any], *names: str) -> int:
    for name in names:
        value = fields.get(name)
        if isinstance(value, int):
            return value
        try:
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            pass
    return 0


def add_lttng_events(
    builder: TraceBuilder,
    incident: Path,
    clock: dict[str, int],
    warnings: list[str],
    skip_lttng: bool,
    require_lttng: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "events": 0,
        "callbacks": 0,
        "counts": {},
        "available": False,
        "discarded_events": 0,
        "channel_discarded_events": 0,
        "discarded_packets": 0,
    }
    control_log = incident / "burst" / "lttng" / "control.log"
    if control_log.is_file():
        try:
            for line in control_log.read_text(encoding="utf-8", errors="replace").splitlines():
                label, separator, value = line.strip().partition(":")
                if separator and label == "Discarded events":
                    result["channel_discarded_events"] = max(
                        result["channel_discarded_events"], int(value.strip())
                    )
        except (OSError, ValueError):
            pass
    trace_path = incident / "burst" / "lttng"
    if skip_lttng or not trace_path.exists():
        result["discarded_events"] = result["channel_discarded_events"]
        return result
    try:
        import bt2  # type: ignore
    except ImportError as error:
        message = "LTTng CTF skipped: install babeltrace2 and python3-bt2"
        if require_lttng:
            raise RuntimeError(message) from error
        warnings.append(message)
        result["discarded_events"] = result["channel_discarded_events"]
        return result

    try:
        iterator: Iterable[Any] = bt2.TraceCollectionMessageIterator(str(trace_path))
    except Exception as error:
        message = f"cannot open LTTng CTF at {trace_path}: {error}"
        if require_lttng:
            raise RuntimeError(message) from error
        warnings.append(message)
        return result

    counts: collections.Counter[str] = collections.Counter()
    callback_stacks: dict[tuple[int, int], list[tuple[int, dict[str, Any]]]] = collections.defaultdict(list)
    unmatched_starts: list[tuple[int, int, int, dict[str, Any]]] = []
    result["available"] = True
    try:
        for message in iterator:
            if isinstance(message, bt2._DiscardedEventsMessageConst):
                result["discarded_events"] += int(message.count or 0)
                continue
            if isinstance(message, bt2._DiscardedPacketsMessageConst):
                result["discarded_packets"] += int(message.count or 0)
                continue
            event = getattr(message, "event", None)
            snapshot = getattr(message, "default_clock_snapshot", None)
            timestamp = getattr(snapshot, "ns_from_origin", None)
            if event is None or not isinstance(timestamp, int):
                continue
            timestamp = normalize_external_clock(timestamp, clock)
            name = str(getattr(event, "name", "lttng:event"))
            fields = event_fields(event)
            pid = context_int(fields, "vpid", "_vpid", "pid")
            tid = context_int(fields, "vtid", "_vtid", "tid")
            if pid <= 0:
                pid = 1_900_000_000
            if tid <= 0:
                tid = pid
            process_name = str(fields.get("procname", fields.get("_procname", f"process {pid}")))
            builder.process_name(pid, process_name)
            builder.thread_name(pid, tid, f"{process_name} [{tid}]")
            counts[name] += 1

            if name.endswith("callback_start"):
                callback_stacks[(pid, tid)].append((timestamp, fields))
                continue
            if name.endswith("callback_end") and callback_stacks[(pid, tid)]:
                start, start_fields = callback_stacks[(pid, tid)].pop()
                duration = max(0, timestamp - start)
                args = dict(start_fields)
                args.update({f"end.{key}": value for key, value in fields.items() if key not in args})
                args["duration_ns"] = duration
                builder.add({
                    "name": "ros2:callback",
                    "cat": "ros2.callback",
                    "ph": "X",
                    "ts": ns_to_us(start),
                    "dur": ns_to_us(duration),
                    "pid": pid,
                    "tid": tid,
                    "args": args,
                })
                result["callbacks"] += 1
                continue

            builder.add({
                "name": name,
                "cat": "ros2" if name.startswith("ros2:") else "lttng",
                "ph": "i",
                "s": "t",
                "ts": ns_to_us(timestamp),
                "pid": pid,
                "tid": tid,
                "args": fields,
            })
    except PermissionError as error:
        message = f"permission denied reading LTTng CTF: {error}; run converter with sudo"
        if require_lttng:
            raise RuntimeError(message) from error
        warnings.append(message)
    except Exception as error:
        message = f"LTTng conversion stopped early: {error}"
        if require_lttng:
            raise RuntimeError(message) from error
        warnings.append(message)

    for (pid, tid), stack in callback_stacks.items():
        for timestamp, fields in stack:
            unmatched_starts.append((pid, tid, timestamp, fields))
    for pid, tid, timestamp, fields in unmatched_starts:
        incomplete = dict(fields)
        incomplete["incomplete"] = True
        builder.add({
            "name": "ros2:callback_start",
            "cat": "ros2.callback",
            "ph": "i",
            "s": "t",
            "ts": ns_to_us(timestamp),
            "pid": pid,
            "tid": tid,
            "args": incomplete,
        })
    result["events"] = sum(counts.values())
    result["counts"] = dict(counts.most_common())
    result["unmatched_callback_starts"] = len(unmatched_starts)
    result["discarded_events"] = max(
        result["discarded_events"], result["channel_discarded_events"]
    )
    if result["discarded_events"] or result["discarded_packets"]:
        warnings.append(
            "LTTng discard channel lost "
            f"{result['discarded_events']} events and "
            f"{result['discarded_packets']} packets"
        )
    return result


def sparkline_svg(values: list[float], width: int = 720, height: int = 110) -> str:
    if not values:
        return ""
    low, high = min(values), max(values)
    span = high - low
    points = []
    for index, value in enumerate(values):
        x = 8 + index * (width - 16) / max(1, len(values) - 1)
        y = height / 2 if span == 0 else 8 + (high - value) * (height - 16) / span
        points.append(f"{x:.1f},{y:.1f}")
    return (
        f'<svg viewBox="0 0 {width} {height}" role="img">'
        f'<polyline points="{" ".join(points)}" fill="none" stroke="#5b8cff" '
        'stroke-width="2" vector-effect="non-scaling-stroke"/></svg>'
    )


def selected_charts(values_by_metric: dict[str, list[float]]) -> list[tuple[str, list[float]]]:
    preferred = [
        "cpu.busy_percent",
        "memory.available_bytes",
        "agent.missed_deadlines",
    ]
    result: list[tuple[str, list[float]]] = []
    selected: set[str] = set()
    for name in preferred:
        if name in values_by_metric:
            result.append((name, values_by_metric[name]))
            selected.add(name)
    for name, values in values_by_metric.items():
        lowered = name.lower()
        if name not in selected and ("thermal" in lowered or ("gpu" in lowered and "duration" not in lowered)):
            result.append((name, values))
            selected.add(name)
        if len(result) >= 8:
            break
    return result


def render_html(
    summary: dict[str, Any],
    values_by_metric: dict[str, list[float]],
    trace_filename: str,
) -> str:
    ebpf_summary = summary.get("ebpf", {})
    filter_enabled = ebpf_summary.get("target_filter_enabled")
    scheduler_enabled = ebpf_summary.get("scheduler_enabled")
    target_pids = ebpf_summary.get("target_pids", [])
    target_tids = ebpf_summary.get("target_tids", [])
    runner_summary = ebpf_summary.get("runner_summary", {})
    deep_tids = runner_summary.get("auto_deep_tids", [])
    deep_scope = (
        "自动L3 TID：" + ", ".join(str(tid) for tid in deep_tids)
        if deep_tids else "本次未触发自动L3"
    )
    if scheduler_enabled is False:
        ebpf_scope = "调度探针未挂载（空白名单，fail-closed）"
    elif filter_enabled is True:
        scopes = []
        if target_pids:
            scopes.append("进程：" + ", ".join(str(pid) for pid in target_pids))
        if target_tids:
            scopes.append("线程：" + ", ".join(str(tid) for tid in target_tids))
        ebpf_scope = "白名单" + ("；".join(scopes) if scopes else "（动态TID）")
    elif filter_enabled is False:
        ebpf_scope = "全系统（未启用进程白名单）"
    else:
        ebpf_scope = "旧事故包，未记录监控范围"
    collector_rows = []
    for collector in summary.get("collectors", {}).get("collectors", []):
        healthy = collector.get("started") and collector.get("stopped") and collector.get("exit_code") == 0
        collector_rows.append(
            "<tr>"
            f"<td>{html.escape(str(collector.get('name', 'unknown')))}</td>"
            f"<td class=\"{'ok' if healthy else 'bad'}\">{'OK' if healthy else 'FAILED'}</td>"
            f"<td>{html.escape(str(collector.get('exit_code', '')))}</td>"
            f"<td>{html.escape(str(collector.get('error', '')))}</td>"
            "</tr>"
        )
    ebpf_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{count}</td>"
        f"<td>{summary['ebpf']['max_duration_ns'].get(name, 0) / 1e6:.3f} ms</td></tr>"
        for name, count in summary.get("ebpf", {}).get("counts", {}).items()
    )
    ros_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{count}</td></tr>"
        for name, count in list(summary.get("ros2", {}).get("counts", {}).items())[:30]
    )
    charts = "".join(
        "<section class=\"chart\">"
        f"<h3>{html.escape(name)}</h3>"
        f"<div class=\"range\">min {min(values):.3f} · max {max(values):.3f}</div>"
        f"{sparkline_svg(values)}</section>"
        for name, values in selected_charts(values_by_metric)
    )
    warnings = "".join(f"<li>{html.escape(item)}</li>" for item in summary.get("warnings", []))
    manifest = summary.get("manifest", {})
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>perf_robot incident {html.escape(str(manifest.get('incident_id', '')))}</title>
<style>
body{{font:14px/1.5 system-ui,sans-serif;background:#0d1117;color:#dce3ed;margin:0;padding:28px}}
main{{max-width:1180px;margin:auto}} h1,h2,h3{{color:#f4f7fb}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}}
.card,.chart{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin:14px 0}}
.value{{font-size:25px;font-weight:650}} table{{width:100%;border-collapse:collapse}} td,th{{padding:8px;border-bottom:1px solid #30363d;text-align:left}}
.ok{{color:#45d483}} .bad{{color:#ff6b6b}} .warn{{color:#ffca5c}} a{{color:#7db4ff}} svg{{width:100%;height:110px;background:#0d1117;border-radius:6px}}
.range{{color:#9aa7b8;margin-bottom:5px}} code{{background:#21262d;padding:2px 5px;border-radius:4px}}
</style></head><body><main>
<h1>Robot Performance Incident</h1>
<div class="grid">
 <div class="card"><div>Incident</div><div class="value">{html.escape(str(manifest.get('incident_id', 'unknown')))}</div></div>
 <div class="card"><div>Trigger</div><div class="value">{html.escape(str(manifest.get('trigger', 'unknown')))}</div></div>
 <div class="card"><div>Samples</div><div class="value">{summary.get('samples', {}).get('count', 0)}</div></div>
 <div class="card"><div>ROS / eBPF events</div><div class="value">{summary.get('ros2', {}).get('events', 0)} / {summary.get('ebpf', {}).get('events', 0)}</div></div>
</div>
<section class="card"><h2>Perfetto timeline</h2>
<p>下载或选择 <a href="{html.escape(trace_filename)}">{html.escape(trace_filename)}</a>，在
<a href="https://ui.perfetto.dev" target="_blank" rel="noreferrer">ui.perfetto.dev</a> 中使用 Open trace file 打开。</p></section>
<h2>System metrics</h2>{charts or '<div class="card">No metric data</div>'}
<section class="card"><h2>Collector health</h2><table><tr><th>Collector</th><th>Status</th><th>Exit</th><th>Error</th></tr>{''.join(collector_rows)}</table></section>
<div class="grid">
<section class="card"><h2>eBPF</h2><p>{html.escape(ebpf_scope)}</p><p>{html.escape(deep_scope)}</p><table><tr><th>Type</th><th>Count</th><th>Max</th></tr>{ebpf_rows}</table></section>
<section class="card"><h2>ROS 2 events</h2>
<p>Discarded events: {summary.get('ros2', {}).get('discarded_events', 0)} · Discarded packets: {summary.get('ros2', {}).get('discarded_packets', 0)}</p>
<table><tr><th>Event</th><th>Count</th></tr>{ros_rows}</table></section>
</div>
<section class="card"><h2>Warnings</h2><ul>{warnings or '<li>None</li>'}</ul></section>
</main></body></html>"""


def atomic_write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, separators=(",", ":"))
        stream.write("\n")
    temporary.replace(path)


def atomic_write_text(path: Path, value: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        stream.write(value)
    temporary.replace(path)


def restore_invoking_user(paths: Iterable[Path]) -> None:
    if os.geteuid() != 0 or "SUDO_UID" not in os.environ or "SUDO_GID" not in os.environ:
        return
    uid = int(os.environ["SUDO_UID"])
    gid = int(os.environ["SUDO_GID"])
    for path in paths:
        os.chown(path, uid, gid)
        os.chmod(path, 0o750 if path.is_dir() else 0o640)


def convert(args: argparse.Namespace) -> dict[str, Any]:
    incident = args.incident.resolve()
    if not (incident / "manifest.json").is_file():
        raise RuntimeError(f"not a perf_robot incident: {incident}")
    output = (args.output_dir or incident / "derived").resolve()
    output.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    manifest = read_json(incident / "manifest.json", {}, warnings)
    collectors = read_json(incident / "burst" / "status.json", {"collectors": []}, warnings)
    for collector in collectors.get("collectors", []):
        if not isinstance(collector, dict) or not collector.get("start_attempted"):
            continue
        healthy = (collector.get("started") and collector.get("stopped") and
                   collector.get("exit_code") == 0)
        if not healthy:
            warnings.append(
                f"collector {collector.get('name', 'unknown')} is incomplete: "
                f"exit={collector.get('exit_code')} {collector.get('error', '')}".rstrip()
            )
    samples, post_samples = load_samples(incident, warnings)
    clock = clock_model(samples)

    builder = TraceBuilder()
    metric_summary, values_by_metric = add_metric_events(builder, samples)
    trigger_ns = add_trigger_event(builder, manifest, post_samples, samples, warnings)
    ebpf = add_ebpf_events(builder, incident, warnings)
    if ebpf["events"] and not ebpf["summary_present"]:
        warnings.append("eBPF events are present but the final runner summary is missing")
    ros2 = add_lttng_events(
        builder, incident, clock, warnings, args.skip_lttng, args.require_lttng
    )

    trace_name = "incident.perfetto.json"
    summary_name = "summary.json"
    report_name = "report.html"
    trace_path = output / trace_name
    summary_path = output / summary_name
    report_path = output / report_name
    sample_start = int(samples[0].get("monotonic_ns", 0)) if samples else 0
    sample_end = int(samples[-1].get("monotonic_ns", 0)) if samples else 0
    summary: dict[str, Any] = {
        "schema_version": 1,
        "manifest": manifest,
        "collectors": collectors,
        "samples": {
            "count": len(samples),
            "start_monotonic_ns": sample_start,
            "end_monotonic_ns": sample_end,
            "trigger_monotonic_ns": trigger_ns,
        },
        "clock": clock,
        "metrics": metric_summary,
        "ebpf": ebpf,
        "ros2": ros2,
        "warnings": warnings,
        "outputs": {"trace": trace_name, "summary": summary_name, "report": report_name},
    }
    atomic_write_json(trace_path, builder.payload())
    atomic_write_json(summary_path, summary)
    atomic_write_text(report_path, render_html(summary, values_by_metric, trace_name))
    restore_invoking_user((output, trace_path, summary_path, report_path))
    return summary


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a perf_robot incident to a Perfetto trace and HTML report"
    )
    parser.add_argument("incident", type=Path, help="incident package directory")
    parser.add_argument("--output-dir", type=Path, help="output directory (default: INCIDENT/derived)")
    parser.add_argument("--skip-lttng", action="store_true", help="do not parse LTTng CTF")
    parser.add_argument(
        "--require-lttng", action="store_true", help="fail instead of degrading when CTF cannot be parsed"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_arguments(argv if argv is not None else sys.argv[1:])
        summary = convert(args)
        output = (args.output_dir or args.incident / "derived").resolve()
        print(f"Perfetto trace: {output / summary['outputs']['trace']}")
        print(f"HTML report:   {output / summary['outputs']['report']}")
        for warning in summary["warnings"]:
            print(f"warning: {warning}", file=sys.stderr)
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
