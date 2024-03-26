#include "base/logging.h"
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace base {

std::vector<std::string_view> tokenize(const char *s) {
  std::vector<std::string_view> tokens;
  int len = strlen(s);
  const char *curr = nullptr;
  int curr_len = 0;
  for (int i = 0; i < len; i++) {
    if (s[i] != '{') {
      if (!curr) {
        curr = &s[i];
      }
      curr_len++;
    } else {
      if (i + 1 >= len)
        return {};
      if (curr) {
        tokens.emplace_back(curr, curr_len);
      }
      tokens.emplace_back(&s[i], 2);
      curr = nullptr;
      curr_len = 0;
      i++;
    }
  }
  if (curr) {
    tokens.emplace_back(curr, curr_len);
  }
  return tokens;
}

const char *to_cstr(int level) {
  if (level == log_level::DEBUG) {
    return "DEBUG";
  } else if (level == log_level::INFO) {
    return "INFO";
  } else if (level == log_level::WARN) {
    return "WARN";
  } else if (level == log_level::ERROR) {
    return "ERROR";
  } else {
    return "FATAL";
  }
}

void build_args_v_impl(std::vector<std::string> &v) { return; };

void log_inner(int level, const char *s,
               const std::vector<std::string> &args_v) {
  auto tokens = tokenize(s);
  int cnt = 0;
  // FIXME: use thread safe print functions
  std::cout << '[' << to_cstr(level) << "] ";
  for (auto token : tokens) {
    if (token == "{}") {
      if (cnt < args_v.size()) {
        std::cout << args_v[cnt++];
      } else {
        std::cout << "N/A";
      }
    } else {
      std::cout << token;
    }
  }
  std::cout << std::endl;
}

} // namespace base

int TestLogging() {
  using namespace base::log_level;
  base::log(INFO, "str:{} int:{} double:{} noval:{}", std::string("Hello"), 123,
            123.0);
  return 0;
}