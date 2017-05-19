### Description
# Communication modules for pkg-mgr client lib and server process
# By Youmin Ha <youmin.ha@samsung.com>

cmake_minimum_required(VERSION 2.6)
#set(CMAKE_SKIP_BUILD_RPATH true)
set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)

### Get required CFLAGS, LDFLAGS from pkg-config

include(FindPkgConfig)
pkg_check_modules(installer_pkgs REQUIRED glib-2.0 gio-2.0 dlog pkgmgr-info libtzplatform-config)
foreach(flag ${installer_pkgs_CFLAGS})
	set(installer_pkgs_CFLAGS_str "${installer_pkgs_CFLAGS_str} ${flag}")
endforeach()

PKG_CHECK_MODULES(AGENT_DEPS REQUIRED glib-2.0 gio-2.0 dlog libsystemd-daemon)
FOREACH(FLAG ${AGENT_DEPS_CFLAGS})
	SET(AGENT_CFLAGS "${AGENT_CFLAGS} ${FLAG}")
ENDFOREACH()

### Build modules

## pkgmgr_installer object (by youmin.ha)
# This library is for installer backend
add_library(pkgmgr_installer SHARED pkgmgr_installer.c)
set_target_properties(pkgmgr_installer PROPERTIES SOVERSION ${MAJORVER})
set_target_properties(pkgmgr_installer PROPERTIES VERSION ${FULLVER})
set_target_properties(pkgmgr_installer PROPERTIES COMPILE_FLAGS "${installer_pkgs_CFLAGS_str} -fPIC")
target_link_libraries(pkgmgr_installer ${installer_pkgs_LDFLAGS})

### Create pc file
configure_file(pkgmgr-installer.pc.in ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer.pc @ONLY)

## Install
INSTALL(TARGETS pkgmgr_installer DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)
INSTALL(FILES pkgmgr_installer.h DESTINATION include/pkgmgr)
INSTALL(FILES pkgmgr_installer_info.h DESTINATION include/pkgmgr)
INSTALL(FILES pkgmgr_installer_error.h DESTINATION include/pkgmgr)
INSTALL(FILES pkgmgr_installer_type.h DESTINATION include/pkgmgr)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)

## pkgmgr_installer_signal_agent
ADD_EXECUTABLE(pkgmgr-installer-signal-agent pkgmgr_installer_signal_agent.c)
SET_TARGET_PROPERTIES(pkgmgr-installer-signal-agent PROPERTIES COMPILE_FLAGS "${AGENT_CFLAGS} -fPIE")
TARGET_LINK_LIBRARIES(pkgmgr-installer-signal-agent ${AGENT_DEPS_LDFLAGS} "-pie")

INSTALL(TARGETS pkgmgr-installer-signal-agent DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
