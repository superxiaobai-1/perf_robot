# CMake generated Testfile for 
# Source directory: /home/liujie/work/perf_robot
# Build directory: /home/liujie/work/perf_robot/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(perf_robot_tests "/home/liujie/work/perf_robot/build/perf_robot_tests")
set_tests_properties(perf_robot_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/liujie/work/perf_robot/CMakeLists.txt;146;add_test;/home/liujie/work/perf_robot/CMakeLists.txt;0;")
add_test(perf_robot_report_tests "/home/liujie/miniconda3/bin/python3" "/home/liujie/work/perf_robot/tests/test_perf_robot_report.py")
set_tests_properties(perf_robot_report_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/liujie/work/perf_robot/CMakeLists.txt;147;add_test;/home/liujie/work/perf_robot/CMakeLists.txt;0;")
