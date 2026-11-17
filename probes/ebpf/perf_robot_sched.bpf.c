#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "perf_robot_ebpf.h"

struct offcpu_start {
  __u64 ktime_ns;
  __u64 task_state;
  __u32 tgid;
  __s32 user_stack_id;
  __s32 kernel_stack_id;
  __u32 waker_pid;
  __u32 waker_tid;
  char comm[PERF_ROBOT_TASK_COMM_LEN];
  char waker_comm[PERF_ROBOT_TASK_COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 16384);
  __type(key, __u32);
  __type(value, __u64);
} wakeup_ns SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 16384);
  __type(key, __u32);
  __type(value, struct offcpu_start);
} offcpu_starts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, __u64);
} softirq_starts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, __u64);
} hardirq_starts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, __u32);
  __type(value, __u32);
} target_tids SEC(".maps");

// Automatic L3 stack capture is armed only for TIDs inserted by userspace
// after an anomalous L2 off-CPU event.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32);
  __type(key, __u32);
  __type(value, __u32);
} deep_target_tids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(max_entries, 4096);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, PERF_ROBOT_MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct perf_robot_ebpf_config);
} ebpf_config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct perf_robot_ebpf_stats);
} ebpf_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} kernel_events SEC(".maps");

static __always_inline struct perf_robot_ebpf_stats *stats(void) {
  __u32 key = 0;
  return bpf_map_lookup_elem(&ebpf_stats, &key);
}

static __always_inline const struct perf_robot_ebpf_config *current_config(void) {
  __u32 key = 0;
  return bpf_map_lookup_elem(&ebpf_config, &key);
}

static __always_inline bool target_allowed(__u32 tid) {
  // An empty map deliberately rejects everything. This keeps an accidental
  // empty whitelist from turning into system-wide scheduler collection.
  return bpf_map_lookup_elem(&target_tids, &tid) != 0;
}

static __always_inline struct perf_robot_ebpf_event *reserve_event(
    __u32 type, __u64 now, __u64 duration) {
  struct perf_robot_ebpf_event *event =
      bpf_ringbuf_reserve(&kernel_events, sizeof(*event), 0);
  if (!event) {
    struct perf_robot_ebpf_stats *counter = stats();
    if (counter) counter->ringbuf_drops++;
    return 0;
  }
  __builtin_memset(event, 0, sizeof(*event));
  event->type = type;
  event->ktime_ns = now;
  event->duration_ns = duration;
  event->cpu = bpf_get_smp_processor_id();
  return event;
}

static __always_inline int record_wakeup(struct task_struct *task) {
  if (!task) return 0;
  const __s32 pid = BPF_CORE_READ(task, pid);
  if (pid <= 0) return 0;
  const __u32 tid = (__u32)pid;
  if (!target_allowed(tid)) return 0;
  const __u64 now = bpf_ktime_get_ns();
  bpf_map_update_elem(&wakeup_ns, &tid, &now, BPF_ANY);
  struct perf_robot_ebpf_stats *counter = stats();
  if (counter) counter->wakeups++;

  // Waker information is cheap enough for the stack-free L2 profile and is
  // useful for deciding which thread deserves a short L3 stack capture.
  const struct offcpu_start *existing =
      bpf_map_lookup_elem(&offcpu_starts, &tid);
  if (existing) {
    struct offcpu_start updated = *existing;
    const __u64 waker = bpf_get_current_pid_tgid();
    updated.waker_pid = (__u32)(waker >> 32);
    updated.waker_tid = (__u32)waker;
    bpf_get_current_comm(updated.waker_comm, sizeof(updated.waker_comm));
    bpf_map_update_elem(&offcpu_starts, &tid, &updated, BPF_ANY);
    if (counter) counter->waker_matches++;
  }
  return 0;
}

SEC("raw_tp/sched_waking")
int perf_robot_sched_waking(struct bpf_raw_tracepoint_args *ctx) {
  return record_wakeup((struct task_struct *)ctx->args[0]);
}

SEC("raw_tp/sched_wakeup_new")
int perf_robot_sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx) {
  return record_wakeup((struct task_struct *)ctx->args[0]);
}

static __always_inline void emit_runqueue(struct task_struct *next,
                                           struct task_struct *prev,
                                           __u32 tid, __u64 now) {
  const __u64 *start = bpf_map_lookup_elem(&wakeup_ns, &tid);
  if (!start) return;
  const __u64 duration = now - *start;
  bpf_map_delete_elem(&wakeup_ns, &tid);

  const struct perf_robot_ebpf_config *settings = current_config();
  if (!settings || duration < settings->runqueue_threshold_ns) return;
  struct perf_robot_ebpf_event *event =
      reserve_event(PERF_ROBOT_EVENT_RUNQUEUE, now, duration);
  if (!event) return;
  event->tid = tid;
  event->tgid = (__u32)BPF_CORE_READ(next, tgid);
  event->other_id = (__u32)BPF_CORE_READ(prev, pid);
  bpf_core_read(event->comm, sizeof(event->comm), &next->comm);
  bpf_core_read(event->other_comm, sizeof(event->other_comm), &prev->comm);
  bpf_ringbuf_submit(event, 0);
  struct perf_robot_ebpf_stats *counter = stats();
  if (counter) counter->runqueue_emitted++;
}

static __always_inline void emit_offcpu(__u32 tid, __u64 now) {
  const struct offcpu_start *start = bpf_map_lookup_elem(&offcpu_starts, &tid);
  if (!start) return;
  const struct offcpu_start snapshot = *start;
  bpf_map_delete_elem(&offcpu_starts, &tid);
  const __u64 duration = now - snapshot.ktime_ns;

  const struct perf_robot_ebpf_config *settings = current_config();
  if (!settings || duration < settings->offcpu_min_ns ||
      duration > settings->offcpu_max_ns) return;
  struct perf_robot_ebpf_event *event =
      reserve_event(PERF_ROBOT_EVENT_OFF_CPU, now, duration);
  if (!event) return;
  event->tid = tid;
  event->tgid = snapshot.tgid;
  event->task_state = snapshot.task_state;
  event->user_stack_id = snapshot.user_stack_id;
  event->kernel_stack_id = snapshot.kernel_stack_id;
  event->waker_pid = snapshot.waker_pid;
  event->waker_tid = snapshot.waker_tid;
  __builtin_memcpy(event->comm, snapshot.comm, sizeof(event->comm));
  __builtin_memcpy(event->waker_comm, snapshot.waker_comm,
                   sizeof(event->waker_comm));
  bpf_ringbuf_submit(event, 0);
  struct perf_robot_ebpf_stats *counter = stats();
  if (counter) counter->offcpu_emitted++;
}

// Raw sched_switch exposes task_struct plus the scheduler-captured prev_state.
// prev_state == TASK_RUNNING means preemption; non-zero means a blocking wait.
SEC("raw_tp/sched_switch")
int perf_robot_sched_switch(struct bpf_raw_tracepoint_args *ctx) {
  struct task_struct *prev = (struct task_struct *)ctx->args[1];
  struct task_struct *next = (struct task_struct *)ctx->args[2];
  if (!prev || !next) return 0;
  // Filter on TID before reading time, task metadata, configuration or stack.
  // Every system task reaches this raw tracepoint, so the early exit is the
  // most important normal-system overhead control.
  const __s32 next_pid = BPF_CORE_READ(next, pid);
  const __s32 prev_pid = BPF_CORE_READ(prev, pid);
  const bool next_is_target =
      next_pid > 0 && target_allowed((__u32)next_pid);
  const bool prev_is_target =
      prev_pid > 0 && target_allowed((__u32)prev_pid);
  if (!next_is_target && !prev_is_target) return 0;

  const __u64 now = bpf_ktime_get_ns();
  if (next_is_target) {
    emit_runqueue(next, prev, (__u32)next_pid, now);
    emit_offcpu((__u32)next_pid, now);
  }
  if (!prev_is_target) return 0;

  const __u32 tid = (__u32)prev_pid;
  const __u32 prev_tgid = (__u32)BPF_CORE_READ(prev, tgid);
  // The raw tracepoint exposes the state captured by the scheduler as arg 3.
  // It is more precise here than re-reading task_struct after trace emission.
  const __u64 state = (__u64)ctx->args[3];
  struct perf_robot_ebpf_stats *counter = stats();
  if (state == 0) {
    bpf_map_update_elem(&wakeup_ns, &tid, &now, BPF_ANY);
    if (counter) counter->preemptions++;
  } else {
    struct offcpu_start start = {};
    start.ktime_ns = now;
    start.task_state = state;
    start.tgid = prev_tgid;
    start.user_stack_id = -1;
    start.kernel_stack_id = -1;
    const struct perf_robot_ebpf_config *settings = current_config();
    const bool stack_type_enabled =
        settings &&
        (settings->user_stack_enabled || settings->kernel_stack_enabled);
    const bool deep_target_allowed =
        settings && (!settings->deep_filter_enabled ||
                     bpf_map_lookup_elem(&deep_target_tids, &tid) != 0);
    if (stack_type_enabled && deep_target_allowed) {
      __u32 sample_rate = settings->stack_sample_rate;
      if (sample_rate == 0) sample_rate = 1;
      __u64 sequence = 0;
      if (counter) {
        sequence = counter->stack_opportunities;
        counter->stack_opportunities++;
      }
      const bool sampled = sample_rate == 1 ||
                           (sequence & ((__u64)sample_rate - 1)) == 0;
      if (sampled) {
        if (settings->user_stack_enabled) {
          start.user_stack_id =
              (__s32)bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
          if (counter && start.user_stack_id < 0)
            counter->user_stack_failures++;
        }
        if (settings->kernel_stack_enabled) {
          start.kernel_stack_id =
              (__s32)bpf_get_stackid(ctx, &stack_traces, 0);
          if (counter && start.kernel_stack_id < 0)
            counter->kernel_stack_failures++;
        }
        if (counter) counter->stack_samples++;
      } else if (counter) {
        counter->stack_skipped++;
      }
    }
    bpf_core_read(start.comm, sizeof(start.comm), &prev->comm);
    bpf_map_update_elem(&offcpu_starts, &tid, &start, BPF_ANY);
    if (counter) counter->sleeps++;
  }
  return 0;
}

static __always_inline __u64 irq_key(__u32 id) {
  return ((__u64)bpf_get_smp_processor_id() << 32) | id;
}

SEC("tracepoint/irq/softirq_entry")
int perf_robot_softirq_entry(struct trace_event_raw_softirq *ctx) {
  const __u32 vec = BPF_CORE_READ(ctx, vec);
  const __u64 key = irq_key(vec);
  const __u64 now = bpf_ktime_get_ns();
  bpf_map_update_elem(&softirq_starts, &key, &now, BPF_ANY);
  return 0;
}

SEC("tracepoint/irq/softirq_exit")
int perf_robot_softirq_exit(struct trace_event_raw_softirq *ctx) {
  const __u32 vec = BPF_CORE_READ(ctx, vec);
  const __u64 key = irq_key(vec);
  const __u64 *start = bpf_map_lookup_elem(&softirq_starts, &key);
  if (!start) return 0;
  const __u64 now = bpf_ktime_get_ns();
  const __u64 duration = now - *start;
  bpf_map_delete_elem(&softirq_starts, &key);
  const struct perf_robot_ebpf_config *settings = current_config();
  if (!settings || duration < settings->softirq_threshold_ns) return 0;
  struct perf_robot_ebpf_event *event =
      reserve_event(PERF_ROBOT_EVENT_SOFTIRQ, now, duration);
  if (!event) return 0;
  event->other_id = vec;
  bpf_ringbuf_submit(event, 0);
  struct perf_robot_ebpf_stats *counter = stats();
  if (counter) counter->softirq_emitted++;
  return 0;
}

SEC("tracepoint/irq/irq_handler_entry")
int perf_robot_hardirq_entry(struct trace_event_raw_irq_handler_entry *ctx) {
  const __u32 irq = (__u32)BPF_CORE_READ(ctx, irq);
  const __u64 key = irq_key(irq);
  const __u64 now = bpf_ktime_get_ns();
  bpf_map_update_elem(&hardirq_starts, &key, &now, BPF_ANY);
  return 0;
}

SEC("tracepoint/irq/irq_handler_exit")
int perf_robot_hardirq_exit(struct trace_event_raw_irq_handler_exit *ctx) {
  const __u32 irq = (__u32)BPF_CORE_READ(ctx, irq);
  const __u64 key = irq_key(irq);
  const __u64 *start = bpf_map_lookup_elem(&hardirq_starts, &key);
  if (!start) return 0;
  const __u64 now = bpf_ktime_get_ns();
  const __u64 duration = now - *start;
  bpf_map_delete_elem(&hardirq_starts, &key);
  const struct perf_robot_ebpf_config *settings = current_config();
  if (!settings || duration < settings->hardirq_threshold_ns) return 0;
  struct perf_robot_ebpf_event *event =
      reserve_event(PERF_ROBOT_EVENT_HARDIRQ, now, duration);
  if (!event) return 0;
  event->other_id = irq;
  bpf_ringbuf_submit(event, 0);
  struct perf_robot_ebpf_stats *counter = stats();
  if (counter) counter->hardirq_emitted++;
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
