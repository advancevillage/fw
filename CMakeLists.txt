cmake_minimum_required(VERSION 2.8)

project(fw)
set(PROJECT_NAME "fw")

set(CMAKE_VERBOSE_MAKEFILE true)

set(CMAKE_INSTALL_PREFIX "/usr/local/fw")

set(CMAKE_BUILD_TYPE Release)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${CMAKE_CURRENT_SOURCE_DIR}/deploy/cmake")

add_custom_command(
    OUTPUT commit
    COMMAND sh -c "git rev-parse HEAD | cut -c 1-16"
	OUTPUT_VARIABLE PROJECT_COMMIT
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_custom_command(
    OUTPUT tag
    COMMAND sh -c "git describe  --tags --abbrev=0 | sed 's/[[:blank:]]//g' | sed 's/^v//g' | awk -F'.' '{printf \"%04x%04x%08x\", $1,$2,$3}'"
	OUTPUT_VARIABLE PROJECT_TAG
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_custom_command(
    OUTPUT  os
    COMMAND sh -c "uname -s"
	OUTPUT_VARIABLE PROJECT_OS
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_custom_command(
    OUTPUT  bpfTag
    COMMAND sh -c "sed -i '' 's/#define bpfTag      0x0000000000000000/#define bpfTag      0x${PROJECT_TAG}/' ${CMAKE_CURRENT_SOURCE_DIR}/bpf/fw.bpf.c"
)
add_custom_target(bpfTag DEPENDS tag)

add_custom_command(
    OUTPUT bpfCommit
    COMMAND sh -c "sed -i '' 's/#define bpfCommit   0x0000000000000000/#define bpfCommit   0x${PROJECT_COMMIT}/' ${CMAKE_CURRENT_SOURCE_DIR}/bpf/fw.bpf.c"
)
add_custom_target(bpfCommit DEPENDS commit)

add_custom_command(
    OUTOUT go
    COMMAND sh -c "mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/bin"
    COMMAND sh -c "CGO_ENABLED=0 GOOS=${PROJECT_OS} GOARCH=amd64 go build -a -ldflags '-X pkg/meta.tag=0x${PROJECT_TAG} -X pkg/meta.commit=0x${PROJECT_COMMIT} -extldflags \"-static\"' -o ${CMAKE_CURRENT_SOURCE_DIR}/bin/${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/cmd/cmd.go"
)
add_custom_target(build DEPENDS os bpfTag bpfCommit)


set(CPACK_PACKAGE_NAME                      "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION                   "${PROJECT_TAG}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY       "efficient firewall base of ebpf/xdp")
set(CPACK_PACKAGE_CONTACT                   "cugriver@163.com")
set(CPACK_PACKAGING_INSTALL_PREFIX          "${CMAKE_INSTALL_PREFIX}")

include(rpm)
include(CPack)
