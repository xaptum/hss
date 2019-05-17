cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

include(GNUInstallDirs)

add_executable(psock_test
	psock_test.c)

add_executable(xpt_ffs_setup
	xpt_ffs_setup.c)

install(
    TARGETS psock_test
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

install(
    TARGETS xpt_ffs_setup
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

target_link_libraries(xpt_ffs_setup 
PUBLIC config 
       usbgx
)
