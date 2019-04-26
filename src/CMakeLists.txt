#
# scrypt/src/CMakeLists.txt --
#

cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

include_directories(${PROJECT_BINARY_DIR}/src)

add_library(scrypt scrypt.c)

add_executable(main main.c)
target_link_libraries(main scrypt)
