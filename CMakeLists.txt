cmake_minimum_required(VERSION 2.8)

project(fw)

set(CMAKE_VERBOSE_MAKEFILE true)

set(CMAKE_INSTALL_PREFIX "/usr/local/fw")

execute_process(
    COMMAND sh -c "git rev-parse HEAD | cut -c 1-16"
    TIMEOUT 3
	OUTPUT_VARIABLE PROJECT_COMMIT
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
message("commit: " ${PROJECT_COMMIT})

execute_process(
    COMMAND sh -c "git describe  --tags --abbrev=0 | sed 's/[[:blank:]]//g' | sed 's/^v//g' | awk -F'.' '{printf \"%04x%04x%08x\", $1,$2,$3}'"
    TIMEOUT 3
	OUTPUT_VARIABLE PROJECT_TAG
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
message("tag: " ${PROJECT_TAG})


execute_process(
    COMMAND sh -c "cat ${CMAKE_CURRENT_SOURCE_DIR}/bpf/fw.bpf.c"
    TIMEOUT 3
)

