cmake_minimum_required(VERSION 3.10)
include(TestBigEndian)
# project name and version
project(disasm_test VERSION 1.0.0.0)

# C++ standards!
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)

add_executable(disasm_test driver.cpp disasm_scalar16.cpp disasm_scalar32.cpp disasm_scalar48.cpp)

target_include_directories(disasm_test PUBLIC "${PROJECT_BINARY_DIR}")

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
set(Boost_USE_RELEASE_LIBS ON)
find_package(Boost 1.67.0 REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})
target_link_libraries(VCIV_DIS ${Boost_LIBRARIES})


TEST_BIG_ENDIAN(IS_BE)
if(IS_BE)
  message(STATUS "Configuring instruction read for Big Endian systems")
else()
  message(STATUS "Configuring intruction read for Little Endian systems")
endif()

configure_file(disasm_config.h.in disasm_config.h)
