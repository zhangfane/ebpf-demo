cmake_minimum_required(VERSION 3.25)
project(untitled1 C)

set(CMAKE_C_STANDARD 99)
add_definitions(-D__KERNEL__ -DMODULE)

# Find the kernel release
execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Find the headers
find_path(
        KERNELHEADERS_DIR
        include/linux/user.h
        PATHS /usr/src/linux-headers-${KERNEL_RELEASE}
)

message(STATUS "Kernel release: ${KERNEL_RELEASE}")
message(STATUS "Kernel headers: ${KERNELHEADERS_DIR}")

# Add header files
include_directories(
        ${KERNELHEADERS_DIR}/include
)

#list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
#LINK_DIRECTORIES("/usr/lib/modules/6.3.1-arch1-1/build/include")
#find_package(KernelHeaders REQUIRED)
#add_dependencies(/usr/lib/modules/6.3.1-arch1-1/build/include)
add_executable(untitled1 kprobe-demo/main.c tracepoint-demo/main.c fprobe-demo/main.c uprobe-demo/main.c kprobe-query-demo/main.c ebpf_raw_tracepoint/main.c)
