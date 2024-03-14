#ifndef BASE_LOGGING_H_
#define BASE_LOGGING_H_

#include <cstdio>

constexpr const int FATAL = 0;
constexpr const int ERROR = 1;
constexpr const int WARN = 2;
constexpr const int INFO = 3;
constexpr const int DEBUG = 4;

// TODO
inline void log(int level, const char* content) {

}

#endif