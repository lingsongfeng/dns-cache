#ifndef BASE_THREADING_TASK_H_
#define BASE_THREADING_TASK_H_

#include <functional>
#include <optional>

namespace base {

struct Task {
  bool shutdown = false;
  std::optional<std::function<void()>> func_opt;

  Task();
  Task(std::function<void()> &&func);

  static Task MakeShutdownTask();
};

} // namespace base

#endif