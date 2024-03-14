#include "base/threading/task.h"

namespace base {

Task::Task() : shutdown(false), func_opt(std::nullopt) {}
Task::Task(std::function<void()> &&func)
    : shutdown(false), func_opt(std::move(func)) {}

// static
Task Task::MakeShutdownTask() {
  Task task;
  task.shutdown = true;
  return task;
}

} // namespace base