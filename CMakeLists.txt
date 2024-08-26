cmake_minimum_required(VERSION 3.10)

project(MyRSAProject)

set(CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/cmake
    ${CMAKE_MODULE_PATH}
)

# Find GMP library
find_package(GMP REQUIRED)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

# Add the executable
add_executable(my_program main.cpp rsa.cpp primes.cpp aes.cpp aes-modes.cpp)

# Link against GMP and GMPXX
target_link_libraries(my_program GMP)