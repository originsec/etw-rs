# CMakeLists.txt for ETW C++ Benchmarks

cmake_minimum_required(VERSION 3.15)
project(etw_cpp_benchmarks CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find krabsetw (optional): clone it into benches/krabsetw, or set both
# USE_KRABSETW=ON and KRABSETW_DIR
option(USE_KRABSETW "Enable krabsetw benchmarks" OFF)

# Auto-detect krabsetw cloned into benches/krabsetw/
if(NOT USE_KRABSETW AND EXISTS "${CMAKE_SOURCE_DIR}/krabsetw/krabs/krabs.hpp")
    set(USE_KRABSETW ON)
    set(KRABSETW_DIR "${CMAKE_SOURCE_DIR}/krabsetw" CACHE PATH "Auto-detected krabsetw path")
    message(STATUS "Auto-detected krabsetw at ${CMAKE_SOURCE_DIR}/krabsetw/krabs")
endif()

# Add executable
add_executable(cpp_benchmarks
    cpp_benchmarks.cpp
)

# Link TDH library (Windows only)
if(WIN32)
    target_link_libraries(cpp_benchmarks PRIVATE
        tdh
        advapi32
    )
else()
    message(FATAL_ERROR "This benchmark is Windows-only (requires TDH)")
endif()

# krabsetw support (optional)
if(USE_KRABSETW)
    find_path(KRABSETW_INCLUDE_DIR krabs.hpp
        HINTS
            ${KRABSETW_DIR}
            ${KRABSETW_DIR}/include
            ${KRABSETW_DIR}/krabs
            $ENV{KRABSETW_DIR}
            $ENV{KRABSETW_DIR}/include
            $ENV{KRABSETW_DIR}/krabs
    )

    if(KRABSETW_INCLUDE_DIR)
        message(STATUS "Found krabsetw: ${KRABSETW_INCLUDE_DIR}")
        target_include_directories(cpp_benchmarks PRIVATE ${KRABSETW_INCLUDE_DIR})
        target_compile_definitions(cpp_benchmarks PRIVATE HAVE_KRABSETW UNICODE _UNICODE)
    else()
        message(WARNING "krabsetw not found. Set KRABSETW_DIR or clone it into benches/krabsetw.")
    endif()
endif()

# Optimization flags
if(MSVC)
    target_compile_options(cpp_benchmarks PRIVATE /O2 /W4)
else()
    target_compile_options(cpp_benchmarks PRIVATE -O3 -Wall -Wextra)
endif()

# Install target
install(TARGETS cpp_benchmarks DESTINATION bin)

message(STATUS "")
message(STATUS "Build configuration:")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  krabsetw enabled: ${USE_KRABSETW}")
message(STATUS "")
