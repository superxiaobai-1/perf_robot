#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define PERF_ROBOT_TASK_COMM_LEN 16
#define PERF_ROBOT_MAX_STACK_DEPTH 127

enum perf_robot_event_type {
  PERF_ROBOT_EVENT_RUNQUEUE = 1,
  PERF_ROBOT_EVENT_OFF_CPU = 2,
  PERF_ROBOT_EVENT_SOFTIRQ = 3,
  PERF_ROBOT_EVENT_HARDIRQ = 4,
};

struct perf_robot_ebpf_config {
  __u64 runqueue_threshold_ns;
  __u64 offcpu_min_ns;
  __u64 offcpu_max_ns;
  __u64 softirq_threshold_ns;
  __u64 hardirq_threshold_ns;
  __u32 user_stack_enabled;
  __u32 kernel_stack_enabled;
  __u32 stack_sample_rate;
  __u32 deep_filter_enabled;
};

// One fixed-size ABI keeps the hot path and userspace ring-buffer callback
// simple. Fields that do not apply to an event type are zeroed.
struct perf_robot_ebpf_event {
  __u64 ktime_ns;
  __u64 duration_ns;
  __u64 task_state;
  __u32 type;
  __u32 tid;
  __u32 tgid;
  __u32 cpu;
  __u32 other_id;
  __s32 user_stack_id;
  __s32 kernel_stack_id;
  __u32 waker_pid;
  __u32 waker_tid;
  char comm[PERF_ROBOT_TASK_COMM_LEN];
  char other_comm[PERF_ROBOT_TASK_COMM_LEN];
  char waker_comm[PERF_ROBOT_TASK_COMM_LEN];
};

struct perf_robot_ebpf_stats {
  __u64 wakeups;
  __u64 preemptions;
  __u64 sleeps;
  __u64 runqueue_emitted;
  __u64 offcpu_emitted;
  __u64 softirq_emitted;
  __u64 hardirq_emitted;
  __u64 ringbuf_drops;
  __u64 user_stack_failures;
  __u64 kernel_stack_failures;
  __u64 waker_matches;
  __u64 stack_opportunities;
  __u64 stack_samples;
  __u64 stack_skipped;
};
