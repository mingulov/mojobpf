# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.20)
project(MojoBPFCompiler LANGUAGES C CXX)

# This reader/API combination is qualified against captured Mojo output.
# Changing the dependency requires a new producer compatibility check.
find_package(LLVM 22.1.8 EXACT REQUIRED CONFIG)

add_library(mojobpf-compiler STATIC lib/TargetModel.cpp lib/Audit.cpp
    lib/HelperLowering.cpp lib/MapMetadata.cpp)
target_compile_features(mojobpf-compiler PUBLIC cxx_std_17)
target_include_directories(mojobpf-compiler PUBLIC include)
target_include_directories(mojobpf-compiler SYSTEM PUBLIC ${LLVM_INCLUDE_DIRS})
separate_arguments(MOJOBPF_LLVM_DEFINITIONS NATIVE_COMMAND "${LLVM_DEFINITIONS}")
target_compile_options(mojobpf-compiler PUBLIC ${MOJOBPF_LLVM_DEFINITIONS})
target_link_libraries(mojobpf-compiler PUBLIC LLVM)
add_executable(mojobpf-lower tools/mojobpf-lower.cpp)
target_link_libraries(mojobpf-lower PRIVATE mojobpf-compiler)
# Analysis-only executable: not an emission API or an installed product tool.
add_executable(mojobpf-audit-driver tests/audit_driver.cpp)
target_link_libraries(mojobpf-audit-driver PRIVATE mojobpf-compiler)

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)
    execute_process(COMMAND ${Python3_EXECUTABLE} -c "import pytest"
        RESULT_VARIABLE MOJOBPF_PYTEST_IMPORT)
    if(NOT MOJOBPF_PYTEST_IMPORT EQUAL 0)
        message(FATAL_ERROR "Compiler tests require pytest for the selected Python")
    endif()
    add_test(NAME ir-roundtrip
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ir_roundtrip.py)
    set_tests_properties(ir-roundtrip PROPERTIES
        ENVIRONMENT "MOJOBPF_LOWER=$<TARGET_FILE:mojobpf-lower>;MOJOBPF_LLVM_CONFIG=${LLVM_TOOLS_BINARY_DIR}/llvm-config")
    foreach(SUITE IN ITEMS target_model parsed_audit parsed_lowering parsed_elf)
        add_test(NAME ${SUITE}
            COMMAND ${Python3_EXECUTABLE} -m pytest ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_${SUITE}.py -q)
        set_tests_properties(${SUITE} PROPERTIES
            ENVIRONMENT "MOJOBPF_LOWER=$<TARGET_FILE:mojobpf-lower>;MOJOBPF_AUDIT_DRIVER=$<TARGET_FILE:mojobpf-audit-driver>;MOJOBPF_LLVM_CONFIG=${LLVM_TOOLS_BINARY_DIR}/llvm-config")
    endforeach()
endif()
