#ifndef BASE_THREADING_THREAD_POOL_H_
#define BASE_THREADING_THREAD_POOL_H_

#include "base/threading/worker_thread.h"
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace base {

class ThreadPool : public std::enable_shared_from_this<ThreadPool> {
private:
  ThreadPool(int number_of_threads);

public:
  static std::shared_ptr<ThreadPool> MakeShared(int number_of_threads);

  void PostTask(std::function<void()> &&func);

  template <typename T>
  void PostSequencedTask(std::function<T()> &&func1,
                         std::function<void(T t)> &&func2) {
    auto func3 =
        [func1 = std::move(func1), func2 = std::move(func2),
         pool =
             weak_from_this()]() { // TODO(lingsong.feng): use weak or shared?
          T rv = func1();
          auto func2_wrapped = [t = std::move(rv), func2 = std::move(func2)]() {
            func2(std::move(t));
          };
          if (auto pool_sp = pool.lock()) {
            pool_sp->PostTask(func2_wrapped);
          }
        };
    PostTask(func3);
  }

  int GetNumberOfThreads();

  void Shutdown();

  ~ThreadPool();

private:
  std::vector<WorkerHandler> handlers_;
  int round_robin_counter;
  std::mutex mutex_;
};

void thread_pool_test();

} // namespace base

#endif