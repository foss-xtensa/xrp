SET(CMAKE_C_FLAGS "-W -Wall -DHAVE_ATOMIC -fPIC")

set(XRP_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src/xrp-host/xrp_threaded_queue.c
             ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src/xrp-host/xrp_host_common.c
             ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src/xrp-host/standalone/xrp_host.c
             ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src/xrp-host/standalone/xrp_linux.c
             ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src/xrp-kernel/xrp_alloc.c)

include_directories(${XTENSA_TOOLS_DIR}/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src/xrp-host
                    ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src/xrp-host/thread-pthread
                    ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src/xrp-host/standalone
                    ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src
                    ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src/xrp-common
                    ${CMAKE_CURRENT_SOURCE_DIR}/../xrp_standalone/xrp_src/xrp-kernel)

add_library(xrp-standalone ${XRP_SRCS})

install(TARGETS xrp-standalone
        ARCHIVE DESTINATION lib)

