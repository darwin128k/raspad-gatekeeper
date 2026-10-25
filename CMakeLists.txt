cmake_minimum_required(VERSION 3.16)
project(gatekeeper C)

# Authum client module (ABI 1.0), pure C11 / Linux i386 (-m32).
# SQL via Authum (`<authum/sql.h>`); IPHub via plain HTTP sockets.
# No HLSDK / metamod-p — same shape as qproto 2.x.

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

set(AUTHUM_DIR "${CMAKE_SOURCE_DIR}/lib/authum" CACHE PATH "Authum API source tree")
if (NOT EXISTS "${AUTHUM_DIR}/client/CMakeLists.txt")
	message(FATAL_ERROR
		"lib/authum missing — run: git submodule update --init --recursive lib/authum")
endif ()

add_subdirectory("${AUTHUM_DIR}/client" "${CMAKE_BINARY_DIR}/authum-client")

add_library(gatekeeper MODULE
	src/authum/info.c
	src/authum/module.c
	src/authum/bridge.c
	src/gatekeeper/config.c
	src/gatekeeper/sql.c
	src/gatekeeper/iphub.c
	src/gatekeeper/iphub/data.c
	src/gatekeeper/client/state.c
	src/gatekeeper/filter.c
	src/gatekeeper/steam/guard.c
	src/gatekeeper/resolve.c
)

set_target_properties(gatekeeper PROPERTIES
	PREFIX ""
	OUTPUT_NAME "gatekeeper"
	LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules/gatekeeper"
	RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules/gatekeeper"
)

target_include_directories(gatekeeper PRIVATE
	"${CMAKE_SOURCE_DIR}/include"
)

target_compile_definitions(gatekeeper PRIVATE linux LINUX)

if (NOT MSVC)
	target_compile_options(gatekeeper PRIVATE
		-m32
		-fvisibility=hidden
		-Wall
		-ffunction-sections
		-fdata-sections
	)
	target_link_options(gatekeeper PRIVATE
		-m32
		-static-libgcc
		"LINKER:--gc-sections"
	)
endif ()

target_link_libraries(gatekeeper PRIVATE authum_client pthread dl m)

option(GATEKEEPER_BUILD_TESTS "Build async gatekeeper integration tests" ON)
if (GATEKEEPER_BUILD_TESTS)
    enable_testing()
    add_executable(gatekeeper_test_async
        tests/async.c
        src/gatekeeper/config.c src/gatekeeper/sql.c src/gatekeeper/filter.c
        src/gatekeeper/iphub.c src/gatekeeper/iphub/data.c
        src/gatekeeper/client/state.c src/gatekeeper/steam/guard.c src/gatekeeper/resolve.c
        "${AUTHUM_DIR}/src/authum/host/tasks.c" "${AUTHUM_DIR}/src/authum/host/events.c")
    target_include_directories(gatekeeper_test_async PRIVATE include "${AUTHUM_DIR}/src")
    target_compile_options(gatekeeper_test_async PRIVATE -m32)
    target_link_options(gatekeeper_test_async PRIVATE -m32)
    target_link_libraries(gatekeeper_test_async PRIVATE authum_client pthread dl m)
    add_test(NAME gatekeeper_async COMMAND gatekeeper_test_async)
    set_tests_properties(gatekeeper_async PROPERTIES TIMEOUT 20)
endif ()

if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
	if (CMAKE_STRIP)
		add_custom_command(TARGET gatekeeper POST_BUILD
			COMMAND ${CMAKE_STRIP} --strip-unneeded "$<TARGET_FILE:gatekeeper>"
			COMMENT "strip gatekeeper.so")
	endif ()
endif ()
