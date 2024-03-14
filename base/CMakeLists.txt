
target_sources(base
PRIVATE
    ./threading/task.cpp
    ./threading/thread_pool.cpp
    ./threading/worker_thread.cpp
    ./net/udp_socket.cpp
PUBLIC
    ./threading/task.h
    ./threading/thread_pool.h
    ./threading/worker_thread.h
    ./mpsc.h
    ./net/udp_socket.h
)

target_include_directories(base PUBLIC ${CMAKE_SOURCE_DIR})
