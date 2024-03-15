project(dns_cache)

cmake_minimum_required(VERSION 3.24)

set (CMAKE_CXX_STANDARD 20)


##### debug flags
set(CMAKE_BUILD_TYPE "Debug")
add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)
add_compile_options(-Wall)
add_link_options(-Wall)


add_executable(dns_cache main.cpp dns_cache.cpp gateway.cpp)


##### libraries
add_library(base "")
add_subdirectory(base)
target_link_libraries(dns_cache base)

add_library(dns "")
add_subdirectory(dns)
target_link_libraries(dns_cache dns)
