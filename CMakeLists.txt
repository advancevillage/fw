cmake_minimum_required(VERSION 3.10)

project(fw)
set(PROJECT_NAME "fw")

set(CMAKE_VERBOSE_MAKEFILE true)

set(CMAKE_INSTALL_PREFIX "/usr/local/fw")

##获取基础数据-commit
execute_process(
    COMMAND sh -c "git rev-parse HEAD | cut -c 1-16"
	OUTPUT_VARIABLE PROJECT_COMMIT
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

##获取基础数据-tag
execute_process(
    COMMAND sh -c "git describe  --tags --abbrev=0 | sed 's/[[:blank:]]//g' | sed 's/^v//g' | awk -F'.' '{printf \"%04x%04x%08x\", $1,$2,$3}'"
	OUTPUT_VARIABLE PROJECT_TAG
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
    COMMAND sh -c "git describe  --tags --abbrev=0 | sed 's/[[:blank:]]//g'"
	OUTPUT_VARIABLE PROJECT_PKG_TAG OUTPUT_STRIP_TRAILING_WHITESPACE
)

##获取基础数据-os
execute_process(
    COMMAND sh -c "uname -s"
	OUTPUT_VARIABLE PROJECT_OS
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(TOLOWER ${PROJECT_OS} PROJECT_OS)

execute_process(
    COMMAND sh -c "uname -m"
	OUTPUT_VARIABLE PROJECT_ARCH
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

## 流程编排
execute_process(
    COMMAND sh -c "sed -i '' 's/#define bpfTag .*/#define bpfTag      0x${PROJECT_TAG}/' ${CMAKE_CURRENT_SOURCE_DIR}/bpf/fw.bpf.c"
)

execute_process(
    COMMAND sh -c "sed -i '' 's/#define bpfCommit .*/#define bpfCommit   0x${PROJECT_COMMIT}/' ${CMAKE_CURRENT_SOURCE_DIR}/bpf/fw.bpf.c"
)

execute_process(
    COMMAND sh -c "rm -rf ${CMAKE_CURRENT_SOURCE_DIR}/bin"
    COMMAND sh -c "mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/bin"
    COMMAND sh -c "CGO_ENABLED=0 GOOS=${PROJECT_OS} GOARCH=amd64 go build -a -ldflags '-X github.com/advancevillage/fw/pkg/meta.tag=0x${PROJECT_TAG} -X github.com/advancevillage/fw/pkg/meta.commit=0x${PROJECT_COMMIT}' -o ${CMAKE_CURRENT_SOURCE_DIR}/bin/${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/cmd/cmd.go"
)

include(${CMAKE_CURRENT_SOURCE_DIR}/deploy/${PROJECT_NAME}.cmake)

include(${CMAKE_CURRENT_SOURCE_DIR}/deploy/tgz/tgz.cmake)

include(CPack)
