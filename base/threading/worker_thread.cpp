#include "base/threading/worker_thread.h"
#include "base/mpsc.h"
#include <thread>

namespace base {

WorkerHandler::WorkerHandler() : tx_(std::nullopt) { CreateWorker(); }

// std::optional does not reset moved optionals,
// so we need to reset manually.
WorkerHandler::WorkerHandler(WorkerHandler &&other) {
  tx_ = std::move(other.tx_);
  other.tx_.reset();
}

WorkerHandler &WorkerHandler::operator=(WorkerHandler &&other) {
  tx_ = std::move(other.tx_);
  other.tx_.reset();
  return *this;
}

void WorkerHandler::CreateWorker() {
  auto [tx, rx] = base::Channel<Task>();
  std::thread t([rx = std::move(rx)]() {
    Task task = rx.recv();
    while (!task.shutdown) {
      if (task.func_opt != std::nullopt) {
        (*task.func_opt)();
      }
      task = rx.recv();
    }
  });
  t.detach();

  tx_ = std::move(tx);
}

void WorkerHandler::PostTask(std::function<void()> func) {
  if (tx_ != std::nullopt) {
    tx_->send(Task(std::move(func)));
  }
}

void WorkerHandler::Shutdown() {
  if (tx_ != std::nullopt) {
    tx_->send(Task::MakeShutdownTask());
    tx_.reset();
  }
}

WorkerHandler::~WorkerHandler() { Shutdown(); }

} // namespace base