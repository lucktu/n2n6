set(CMAKE_MC_COMPILER mc.exe)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/msg.h ${CMAKE_CURRENT_BINARY_DIR}/msg.rc ${CMAKE_CURRENT_BINARY_DIR}/MSG00000.bin
    COMMAND ${CMAKE_MC_COMPILER} -U ${CMAKE_CURRENT_SOURCE_DIR}/msg.mc -r ${CMAKE_CURRENT_BINARY_DIR} -h ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/msg.mc)

set(N2N_RESOURCE ${CMAKE_CURRENT_BINARY_DIR}/msg.rc)

add_library(n2n_win32 OBJECT
    getopt1.c
    getopt.c
    wintap.c
    scm_service.c
    windivert.c
    ${N2N_RESOURCE}
)
