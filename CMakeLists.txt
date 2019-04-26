#
# scrypt/CMakeLists.txt --
#

cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
project(scrypt VERSION 0.4.0 LANGUAGES C)

find_package(Threads)
find_package(PkgConfig)

if(CMAKE_COMPILER_IS_GNUCC)
    add_definitions(-Wall -Werror)
endif(CMAKE_COMPILER_IS_GNUCC)

add_subdirectory(src)
add_subdirectory(test)

enable_testing()
add_test(NAME misc COMMAND check-scrypt)

