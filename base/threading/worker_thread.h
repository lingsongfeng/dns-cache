#ifndef BASE_THREADING_WORKER_THREAD_H_
#define BASE_THREADING_WORKER_THREAD_H_

#include "base/mpsc.h"
#include "base/threading/task.h"
#include <functional>

namespace base {

/*
  `WorkerHandler` is the handler for a specific worker thread.
  The thread is created when creating the handler. The thread
  will be notified to be destroyed when the handler is destructuring.

  example:

    auto handler = WorkerHandler();
    handler.PostTask([]() {
      for (int i = 0; i < 10000; i++) {
        printf("%d\n", i);
      }
    });

*/
class WorkerHandler {
public:
  WorkerHandler();

  WorkerHandler(WorkerHandler &&other);
  WorkerHandler &operator=(WorkerHandler &&other);

  void PostTask(std::function<void()> func);

  void Shutdown();

  ~WorkerHandler();

  WorkerHandler(const WorkerHandler &) = delete;
  WorkerHandler &operator=(const WorkerHandler &) = delete;

private:
  void CreateWorker();

private:
  std::optional<SenderHandler<Task>> tx_;
};

} // namespace base

#endif