#ifndef BASE_LOGGING_H_
#define BASE_LOGGING_H_

#include <iostream>
#include <string>
#include <string_view>
#include <vector>

/*

Example:
  using namespace base::log_level;
  base::log(INFO, "str:{} int:{} double:{} noval:{}", std::string("Hello"), 123,
            123.0);

*/
namespace base {

namespace log_level {
enum LogLevel : int { DEBUG = 0, INFO, WARN, ERROR, FATAL };
}

const char *to_cstr(int level);

std::vector<std::string_view> tokenize(const char *s);

void build_args_v_impl(std::vector<std::string> &v);

template <typename T, typename... Args>
void build_args_v_impl(std::vector<std::string> &v, T arg0, Args... res) {
  if constexpr (std::is_same_v<T, std::string>) {
    v.push_back(arg0);
  } else {
    v.push_back(std::to_string(arg0));
  }
  build_args_v_impl(v, res...);
}

template <typename... Args>
std::vector<std::string> build_args_v(Args... args) {
  std::vector<std::string> rv;
  build_args_v_impl(rv, args...);
  return rv;
}

void log_inner(int level, const char *s,
               const std::vector<std::string> &args_v);

template <typename... Args> void log(int level, const char *s, Args... args) {
  auto args_v = build_args_v(args...);
  log_inner(level, s, args_v);
}

} // namespace base

#endif