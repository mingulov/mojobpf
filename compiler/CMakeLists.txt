# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.20)
project(MojoBPFCompiler LANGUAGES C CXX)

# This reader/API combination is qualified against captured Mojo output.
# Changing the dependency requires a new producer compatibility check.
find_package(LLVM 21.1.8 EXACT REQUIRED CONFIG)

add_executable(mojobpf-lower tools/mojobpf-lower.cpp)
target_compile_features(mojobpf-lower PRIVATE cxx_std_17)
target_include_directories(mojobpf-lower SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
separate_arguments(MOJOBPF_LLVM_DEFINITIONS NATIVE_COMMAND "${LLVM_DEFINITIONS}")
target_compile_options(mojobpf-lower PRIVATE ${MOJOBPF_LLVM_DEFINITIONS})
target_link_libraries(mojobpf-lower PRIVATE LLVM)

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)
    add_test(NAME ir-roundtrip
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ir_roundtrip.py)
    set_tests_properties(ir-roundtrip PROPERTIES
        ENVIRONMENT "MOJOBPF_LOWER=$<TARGET_FILE:mojobpf-lower>;MOJOBPF_LLVM_CONFIG=${LLVM_TOOLS_BINARY_DIR}/llvm-config")
endif()
