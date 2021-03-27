cmake_minimum_required(VERSION 3.12)

project(heal VERSION 0.1.0)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

find_package(SEAL 3.6.2 EXACT REQUIRED)

include(GNUInstallDirs)

set(heal_src
  src/heal.c
  src/seal.cpp
)

add_library(heal SHARED ${heal_src})
target_include_directories(heal
  PUBLIC include
  PRIVATE src)
target_link_libraries(heal PUBLIC SEAL::seal_shared)

install(TARGETS heal
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(DIRECTORY include/
  DESTINATION include)
