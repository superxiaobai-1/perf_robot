cmake_minimum_required(VERSION 3.16)

project(perf_robot VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PERF_ROBOT_BUILD_TESTS "Build perf_robot tests" ON)
option(PERF_ROBOT_BUILD_EBPF "Build the libbpf CO-RE L2 collector" ON)

# Option parsing shared by the Agent and the eBPF runner, so both accept and
# validate the same ebpf_* keys.
add_library(perf_robot_common
  src/ebpf_options.cpp
  src/parse_util.cpp
)
target_include_directories(perf_robot_common PUBLIC include)
target_compile_options(perf_robot_common PRIVATE -Wall -Wextra -Wpedantic)

add_library(perf_robot_core
  src/agent.cpp
  src/burst_collector.cpp
  src/config.cpp
  src/control_server.cpp
  src/flight_recorder.cpp
  src/incident_repository.cpp
  src/incident_writer.cpp
  src/json.cpp
  src/resource_guard.cpp
  src/state_machine.cpp
  src/trigger_policy.cpp
  src/collectors/jetson_collector.cpp
  src/collectors/proc_collector.cpp
  src/collectors/process_collector.cpp
)

target_include_directories(perf_robot_core PUBLIC include)
target_link_libraries(perf_robot_core PUBLIC perf_robot_common)
find_package(Threads REQUIRED)
target_link_libraries(perf_robot_core PUBLIC Threads::Threads)
target_compile_options(perf_robot_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(perf_robot_agent src/main.cpp)
target_link_libraries(perf_robot_agent PRIVATE perf_robot_core)

install(TARGETS perf_robot_agent RUNTIME DESTINATION bin)
install(FILES config/perf_robot.conf DESTINATION etc/perf_robot)
install(PROGRAMS tools/perf_robot_report.py DESTINATION bin)

if(PERF_ROBOT_BUILD_EBPF)
  find_program(PERF_ROBOT_CLANG clang REQUIRED)
  find_program(PERF_ROBOT_BPFTOOL bpftool REQUIRED)
  execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE PERF_ROBOT_KERNEL_RELEASE
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  find_path(PERF_ROBOT_LIBBPF_INCLUDE_DIR bpf/libbpf.h
    PATHS
      /usr/include
      /usr/local/include
      "/usr/src/linux-headers-${PERF_ROBOT_KERNEL_RELEASE}/tools/bpf/resolve_btfids/libbpf/include"
  )
  find_library(PERF_ROBOT_LIBBPF_LIBRARY NAMES bpf)
  if(NOT PERF_ROBOT_LIBBPF_LIBRARY)
    find_file(PERF_ROBOT_LIBBPF_LIBRARY
      NAMES libbpf.so.1
      PATHS /lib /usr/lib /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu
    )
  endif()
  if(NOT PERF_ROBOT_LIBBPF_INCLUDE_DIR)
    message(FATAL_ERROR "libbpf headers not found; install libbpf-dev on the target")
  endif()
  if(NOT PERF_ROBOT_LIBBPF_LIBRARY)
    message(FATAL_ERROR "libbpf library not found; install libbpf-dev on the target")
  endif()
  if(NOT EXISTS /sys/kernel/btf/vmlinux)
    message(FATAL_ERROR "kernel BTF /sys/kernel/btf/vmlinux is required for the CO-RE build")
  endif()

  set(PERF_ROBOT_EBPF_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/ebpf_generated")
  set(PERF_ROBOT_VMLINUX_HEADER "${PERF_ROBOT_EBPF_GENERATED_DIR}/vmlinux.h")
  set(PERF_ROBOT_EBPF_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/perf_robot_sched.bpf.o")

  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(PERF_ROBOT_BPF_ARCH arm64)
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$")
    set(PERF_ROBOT_BPF_ARCH x86)
  else()
    message(FATAL_ERROR "unsupported BPF target architecture: ${CMAKE_SYSTEM_PROCESSOR}")
  endif()

  add_custom_command(
    OUTPUT "${PERF_ROBOT_VMLINUX_HEADER}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${PERF_ROBOT_EBPF_GENERATED_DIR}"
    COMMAND "${CMAKE_COMMAND}"
      -DBPFTOOL=${PERF_ROBOT_BPFTOOL}
      -DBTF_FILE=/sys/kernel/btf/vmlinux
      -DOUTPUT_FILE=${PERF_ROBOT_VMLINUX_HEADER}
      -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/generate_vmlinux.cmake"
    VERBATIM
  )
  add_custom_command(
    OUTPUT "${PERF_ROBOT_EBPF_OBJECT}"
    COMMAND "${PERF_ROBOT_CLANG}" -g -O2 -target bpf
      -Wno-missing-declarations
      -D__TARGET_ARCH_${PERF_ROBOT_BPF_ARCH}
      "-I${PERF_ROBOT_EBPF_GENERATED_DIR}"
      "-I${PERF_ROBOT_LIBBPF_INCLUDE_DIR}"
      "-I${CMAKE_CURRENT_SOURCE_DIR}/probes/ebpf/include"
      -c "${CMAKE_CURRENT_SOURCE_DIR}/probes/ebpf/perf_robot_sched.bpf.c"
      -o "${PERF_ROBOT_EBPF_OBJECT}"
    DEPENDS
      "${PERF_ROBOT_VMLINUX_HEADER}"
      probes/ebpf/perf_robot_sched.bpf.c
      probes/ebpf/include/perf_robot_ebpf.h
    VERBATIM
  )
  add_custom_target(perf_robot_ebpf_bpf ALL DEPENDS "${PERF_ROBOT_EBPF_OBJECT}")

  add_executable(perf_robot_ebpf_runner tools/ebpf/perf_robot_ebpf_runner.cpp)
  target_include_directories(perf_robot_ebpf_runner PRIVATE
    "${PERF_ROBOT_LIBBPF_INCLUDE_DIR}"
    probes/ebpf/include
  )
  target_link_libraries(perf_robot_ebpf_runner PRIVATE
    perf_robot_common "${PERF_ROBOT_LIBBPF_LIBRARY}")
  target_compile_options(perf_robot_ebpf_runner PRIVATE -Wall -Wextra -Wpedantic)
  add_dependencies(perf_robot_ebpf_runner perf_robot_ebpf_bpf)

  install(TARGETS perf_robot_ebpf_runner RUNTIME DESTINATION bin)
  install(FILES "${PERF_ROBOT_EBPF_OBJECT}" DESTINATION share/perf_robot/ebpf)
endif()

if(PERF_ROBOT_BUILD_TESTS)
  enable_testing()
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_executable(perf_robot_signal_probe tests/signal_mask_probe.cpp)
  target_compile_options(perf_robot_signal_probe PRIVATE -Wall -Wextra -Wpedantic)
  add_executable(perf_robot_tests tests/perf_robot_tests.cpp)
  target_link_libraries(perf_robot_tests PRIVATE perf_robot_core)
  target_compile_definitions(perf_robot_tests PRIVATE
    PERF_ROBOT_SIGNAL_PROBE_PATH="$<TARGET_FILE:perf_robot_signal_probe>")
  add_dependencies(perf_robot_tests perf_robot_signal_probe)
  add_test(NAME perf_robot_tests COMMAND perf_robot_tests)
  add_test(NAME perf_robot_report_tests
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_perf_robot_report.py")
endif()
