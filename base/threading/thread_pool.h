#ifndef BASE_THREADING_THREAD_POOL_H_
#define BASE_THREADING_THREAD_POOL_H_

#include "base/threading/worker_thread.h"
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace base {

class ThreadPool {
private:
  ThreadPool();

public:
  [[deprecated("use GetInstance")]] static std::shared_ptr<ThreadPool>
  MakeShared(int number_of_threads);

  static ThreadPool *GetInstance();

  void Initialize(int number_of_threads);

  void PostTask(std::function<void()> &&func);

  template <typename T>
  void PostSequencedTask(std::function<T()> &&func1,
                         std::function<void(T t)> &&func2) {
    auto func3 = [func1 = std::move(func1), func2 = std::move(func2)]() {
      T rv = func1();
      auto func2_wrapped = [t = std::move(rv), func2 = std::move(func2)]() {
        func2(std::move(t));
      };
      GetInstance()->PostTask(func2_wrapped);
    };
    PostTask(func3);
  }

  int GetNumberOfThreads();

  void Shutdown();

  ~ThreadPool();

private:
  bool initialized_ = false;
  std::vector<WorkerHandler> handlers_;
  int round_robin_counter = 0;
  std::mutex mutex_;
};

void thread_pool_test();

} // namespace base

#endif