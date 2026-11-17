# perf_robot

Low-overhead, three-level robot performance capture skeleton.

The first implementation runs all periodic baseline collection at **10 Hz**.
It uses `timerfd` + `epoll`, keeps the normal-path history in a bounded memory
flight recorder, and writes an incident package only after a trigger.

## Build and run

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/perf_robot_agent config/perf_robot.conf
```

In a second terminal:

```bash
python3 tools/perf_robotctl.py status
python3 tools/perf_robotctl.py capture
python3 tools/perf_robotctl.py stop
```

The commands use the Linux abstract Unix socket `@perf_robot.control`; the
server accepts only clients with the same effective UID. `status` returns JSON
with the capture state, sample sequence, ring occupancy, missed deadlines and
rejected captures. The control socket is handled by the Agent's existing epoll
loop and does not add a polling thread.

The default capture contains 60 seconds of pre-trigger samples and 10 seconds
of post-trigger samples under `/tmp/perf_robot/incidents`. `SIGTERM` stops the
agent cleanly; if a capture is active, the partial post-trigger data is sealed.

Sealing never blocks the 10 Hz loop: Burst collectors are stopped on the Burst
worker, then the incident is written by a separate writer thread; `status`
reports `incident_write_active` while it runs. Burst data is staged under the
incident root and moved into the incident with a rename. If it cannot be
attached, the baseline samples are still saved and `manifest.json` records the
reason in `burst_error`.

## L2 ROS 2 and kernel burst

The default L2 profile targets ROS 2 Jazzy under `/opt/ros/jazzy`:

- LTTng enables an explicit ROS 2 event allowlist on a 256 KiB × 4 per-CPU,
  per-user discard channel. A virtual-PID tracker admits only
  `lttng_target_pids` (falling back to `ebpf_target_pids`); empty target lists
  fail closed. The final channel statistics, including discarded events, are
  retained in `burst/lttng/control.log`, and the offline report also reads CTF
  discarded-event/packet messages.
- A C/libbpf CO-RE loader collects four kernel delay classes: wakeup/preemption
  to run (runqueue latency), blocking switch-out to resume (off-CPU), long
  softirq execution and long hardirq execution. The scheduler switch probe uses
  raw `sched_switch`'s captured `prev_state` to distinguish preemption from
  blocking, while CO-RE reads stable task identity fields from `task_struct`.
  Only events over their configured thresholds enter one bounded BPF ring
  buffer; JSONL is stored as `burst/ebpf/kernel_events.jsonl`.
- `runqueue_latency` records TID/TGID, CPU, task names and the thread switched
  out immediately before it. `off_cpu` additionally records the numeric Linux
  task-state bits. `softirq` uses `other_id` for the vector and `hardirq` uses
  it for the IRQ number. A final summary reports per-type emitted counts and
  ring-buffer drops.
- Scheduler collection is fail-closed. `ebpf_target_pids=PID1,PID2` is expanded
  from `/proc/PID/task` into a TID map and refreshed periodically;
  `ebpf_target_tids=TID1,TID2` provides a tighter explicit thread whitelist.
  When both are empty, the scheduler tracepoints are not attached. Every hot
  path checks the TID map before reading time, task metadata or configuration.
- The default L2 profile records runqueue latency, off-CPU duration, task state
  and waker PID/TID without walking stacks. The first emitted long off-CPU
  interval automatically inserts that TID into a dedicated L3 BPF map for a
  fixed two-second window; the TID is removed on expiry and cannot be rearmed
  during the same Burst. Only the first two anomalous TIDs are deep-captured by
  default. Automatic L3 uses sampled user stacks and keeps kernel stacks off.
  For a manually targeted L3 capture,
  `ebpf_user_stack_enabled` and `ebpf_kernel_stack_enabled` independently enable
  blocking-site stacks, while `ebpf_stack_sample_rate=16` samples approximately
  one in sixteen blocking switch-outs per CPU. Only intervals in the configured
  200 ms–5 s window are emitted. Referenced stack addresses and `/proc/PID/maps`
  snapshots are sealed into `kernel_events.jsonl`; the offline report resolves
  them with `addr2line` and `/proc/kallsyms`, keeping symbol work off the robot's
  real-time path.
  Stack IDs are never collision-reused. The runner copies each referenced stack
  out on its first event and writes JSON through a 1 MiB buffer flushed every
  250 ms, avoiding per-event write syscalls while bounding the crash-loss window.
- Softirq and hardirq hooks are system-wide and therefore default to detached.
  Set `ebpf_irq_enabled=true` only for a short IRQ-focused diagnosis.
- The Agent hands the eBPF options to the runner as `burst/ebpf/runner.conf`
  (the `ebpf_*` keys of `perf_robot.conf`, parsed and validated by the same
  code on both sides), which also archives the effective settings in each
  incident. Run it by hand with
  `perf_robot_ebpf_runner --object FILE --output FILE --config runner.conf`.
- LTTng and libbpf start concurrently on a dedicated Burst worker. External
  helpers run at nice level 10, while the 10 Hz epoll loop remains responsive.

The libbpf build requires `clang`, `bpftool`, kernel BTF and libbpf development
headers. On Ubuntu/JetPack install `libbpf-dev`; `/sys/kernel/btf/vmlinux` must
exist. CMake generates `vmlinux.h` and compiles a CO-RE object for the current
architecture, including ARM64 on AGX Orin.

`lttng_no_sessiond=true` prevents accidental blocking while LTTng tries to
spawn a daemon. Start `lttng-sessiond` before the Agent. The libbpf loader needs
root or the appropriate `CAP_BPF`, `CAP_PERFMON` and resource-limit setup.
Permission and setup failures are retained in `burst/status.json` and the
corresponding adapter log; they do not abort L0/L1 collection.

For example, monitor only a ROS 2 talker and listener:

```bash
pgrep -x talker
pgrep -x listener
# Then set: ebpf_target_pids=913638,913700
# lttng_target_pids may remain empty and will use the same PID list.
```

Restart the Agent after changing the configuration. A PID changes when its
process restarts, so a long-running deployment should update this list when
managed ROS processes are relaunched.

For a deep two-second investigation of one already identified thread, use a
short capture profile such as:

```ini
capture_seconds=2
ebpf_target_pids=
ebpf_target_tids=913638
lttng_target_pids=913600
ebpf_user_stack_enabled=true
ebpf_kernel_stack_enabled=false
ebpf_stack_sample_rate=16
ebpf_auto_deep_enabled=false
ebpf_irq_enabled=false
```

## Offline visualization

Convert a completed incident into a Perfetto-compatible trace, JSON summary,
and standalone HTML overview:

```bash
sudo apt install babeltrace2 python3-bt2
sudo -E /usr/bin/python3 tools/perf_robot_report.py \
  /tmp/perf_robot/incidents/INCIDENT_ID
```

The converter writes `derived/incident.perfetto.json`, `derived/summary.json`,
and `derived/report.html`. When invoked through sudo, it restores ownership of
the derived files to the invoking user. Open the JSON trace with
<https://ui.perfetto.dev>; it contains 10 Hz counters, the trigger marker,
eBPF scheduler/IRQ slices, ROS 2 LTTng instants, and paired callback slices.
Use `--skip-lttng` to generate a partial report without Babeltrace 2, or
`--require-lttng` to make missing/unreadable CTF data fatal.

## Current scope

- Implemented: 10 Hz scheduler, `/proc` CPU/memory/load/agent-RSS metrics,
  configured PID metrics, Jetson thermal/GPU sysfs metrics, bounded flight
  recorder, consecutive-hit automatic triggers, disk-space admission guard,
  capture state machine, atomic incident directory, signal/socket control,
  ROS 2 LTTng UST Burst, libbpf CO-RE scheduler/off-CPU/IRQ Burst, offline
  Perfetto/HTML incident conversion, and unit tests.
- Not yet implemented: cgroup CPU/memory enforcement and reliable ROS 2
  publish-to-take flow correlation across processes.
