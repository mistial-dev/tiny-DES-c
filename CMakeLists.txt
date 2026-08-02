# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.10)
project(tiny-DES-c VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configuration Options
option(TINY_DES_ENABLE_ECB "Enable ECB mode" ON)
option(TINY_DES_ENABLE_CBC "Enable CBC mode" ON)
option(TINY_DES_ENABLE_CTR "Enable CTR mode" ON)
option(TINY_DES_ENABLE_TDES "Enable Triple-DES (3DES)" ON)
option(TINY_DES_BUILD_TESTS "Build unit test executable" ON)

# Static Library Target
add_library(tiny-des-c STATIC des.c)
target_include_directories(tiny-des-c PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

# Apply Compile Definitions
if(TINY_DES_ENABLE_ECB)
    target_compile_definitions(tiny-des-c PUBLIC DES_ENABLE_ECB=1)
else()
    target_compile_definitions(tiny-des-c PUBLIC DES_ENABLE_ECB=0)
endif()

if(TINY_DES_ENABLE_CBC)
    target_compile_definitions(tiny-des-c PUBLIC DES_ENABLE_CBC=1)
else()
    target_compile_definitions(tiny-des-c PUBLIC DES_ENABLE_CBC=0)
endif()

if(TINY_DES_ENABLE_CTR)
    target_compile_definitions(tiny-des-c PUBLIC DES_ENABLE_CTR=1)
else()
    target_compile_definitions(tiny-des-c PUBLIC DES_ENABLE_CTR=0)
endif()

if(TINY_DES_ENABLE_TDES)
    target_compile_definitions(tiny-des-c PUBLIC DES_ENABLE_TDES=1)
else()
    target_compile_definitions(tiny-des-c PUBLIC DES_ENABLE_TDES=0)
endif()

# Build Unit Tests
if(TINY_DES_BUILD_TESTS)
    enable_testing()

    add_executable(test_des test.c munit.c)
    target_link_libraries(test_des PRIVATE tiny-des-c)
    add_test(NAME test_des COMMAND test_des)
    
    # C++ Integration Test
    add_executable(test_cpp test_cpp.cpp)
    target_link_libraries(test_cpp PRIVATE tiny-des-c)
    add_test(NAME test_cpp COMMAND test_cpp)
endif()
