
target_sources(dns
PRIVATE
    ./dns_packet.cpp
PUBLIC
    ./dns_packet.h
)

target_include_directories(dns PUBLIC ${CMAKE_SOURCE_DIR})
