execute_process(
  COMMAND "${BPFTOOL}" btf dump file "${BTF_FILE}" format c
  OUTPUT_FILE "${OUTPUT_FILE}"
  RESULT_VARIABLE result
  ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "bpftool failed to generate vmlinux.h: ${error}")
endif()
