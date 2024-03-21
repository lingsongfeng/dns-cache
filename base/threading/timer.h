#ifndef BASE_THREADING_TIMER_H_
#define BASE_THREADING_TIMER_H_

#include "base/mpsc.h"
#include "base/threading/task.h"
#include "base/threading/thread_pool.h"
#include "base/threading/worker_thread.h"
#include <chrono>
#include <cstdint>
#include <thread>

namespace base {

class Timer {
public:
  template <class Rep, class Period>
  Timer(std::function<void()> repeating_task,
        const std::chrono::duration<Rep, Period> &interval) {

    auto [tx, rx] = base::Channel<base::Task>();
    tx_ = tx;
    auto closure = [rx = std::move(rx), func = repeating_task, interval]() {
      std::optional<Task> task = rx.recv();
      while (!task || !task->shutdown) {
        auto func_copied = func;
        base::ThreadPool::GetInstance()->PostTask(std::move(func_copied));
        std::this_thread::sleep_for(interval);
        task = rx.recv_no_block();
      }
    };

    std::thread t(std::move(closure));
    t_ = std::move(t);
  }

  void Start() {
    tx_->send(base::Task());
  }

private:
  std::optional<std::thread> t_;
  std::optional<base::SenderHandler<Task>> tx_;
};

} // namespace base

#endif