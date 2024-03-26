
target_sources(base
PRIVATE
    ./threading/task.cpp
    ./threading/thread_pool.cpp
    ./threading/worker_thread.cpp
    ./threading/timer.cpp
    ./net/udp_socket.cpp
    ./logging.cpp
PUBLIC
    ./threading/task.h
    ./threading/thread_pool.h
    ./threading/worker_thread.h
    ./threading/timer.h
    ./mpsc.h
    ./net/udp_socket.h
    ./logging.h
)

target_include_directories(base PUBLIC ${CMAKE_SOURCE_DIR})
