#include "base/threading/thread_pool.h"
#include "base/threading/task.h"
#include <memory>
#include <mutex>
#include <thread>

namespace base {

// static
std::shared_ptr<ThreadPool> ThreadPool::MakeShared(int number_of_threads) {
  return std::shared_ptr<ThreadPool>(new ThreadPool());
}

// static
ThreadPool *ThreadPool::GetInstance() {
  static ThreadPool instance;
  return &instance;
}

void ThreadPool::Initialize(int number_of_threads) {
  initialized_ = true;

  round_robin_counter = 0;
  for (int i = 0; i < number_of_threads; i++) {
    handlers_.emplace_back();
  }
}

ThreadPool::ThreadPool() {}

void ThreadPool::PostTask(std::function<void()> &&func) {
  std::lock_guard<std::mutex> lg(mutex_);
  if (!initialized_) {
    fprintf(stderr, "[ERROR] thread pool is not initialized\n");
    return;
  }
  handlers_[round_robin_counter].PostTask(std::move(func));
  round_robin_counter = (round_robin_counter + 1) % handlers_.size();
}

int ThreadPool::GetNumberOfThreads() {
  int rv = -1;
  {
    std::lock_guard<std::mutex> lg(mutex_);
    rv = handlers_.size();
  }
  return rv;
}

void ThreadPool::Shutdown() {
  std::lock_guard<std::mutex> lg(mutex_);
  if (!initialized_) {
    fprintf(stderr, "[ERROR] thread pool is not initialized\n");
    return;
  }
  for (auto &handler : handlers_) {
    handler.Shutdown();
  }
}

ThreadPool::~ThreadPool() { Shutdown(); }

void thread_pool_test() {

  using namespace std::chrono_literals;
  auto pool = ThreadPool::MakeShared(10);

  pool->PostTask([]() {
    std::this_thread::sleep_for(500ms);
    printf("1\n");
  });
  pool->PostTask([]() {
    std::this_thread::sleep_for(400ms);
    printf("2\n");
  });
  pool->PostTask([]() {
    std::this_thread::sleep_for(300ms);
    printf("3\n");
  });
  pool->PostTask([]() {
    std::this_thread::sleep_for(200ms);
    printf("4\n");
  });
  pool->PostTask([]() {
    std::this_thread::sleep_for(100ms);
    printf("5\n");
  });
  std::this_thread::sleep_for(1000ms);
}

} // namespace base