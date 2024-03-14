#ifndef BASE_MPSC_H_
#define BASE_MPSC_H_

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <type_traits>

namespace base {

template <typename T> class Receiver;
template <typename T> class ReceiverHandler;
template <typename T> class SenderHandler;

/*
 mpsc stands for multiple-producer-single-consumer.

 example:

    auto [tx, rx] = base::Channel<int>();

    // `tx` can be copied and passed to different threads, and
    // it ensures thread safety.
    tx.send(123);
    auto t = std::thread([tx]() {
      tx.send(456);
    });
    t.detach();


    // receive a number from the other end of the channel
    int val1 = rx.recv();
    // receive a number from the other end of the channel
    int val2 = rx.recv();

    // because we sent only 2 numbers, so this `recv()` will block
    // until `tx` sends the third number
    int val3 = rx.recv();

*/
template <typename T>
std::pair<SenderHandler<T>, ReceiverHandler<T>> Channel() {

  auto receiver = Receiver<T>::Create();
  SenderHandler<T> tx(receiver);
  ReceiverHandler<T> rx(receiver);

  return {std::move(tx), std::move(rx)};
}

// SenderHandler is copyable
template <typename T> class SenderHandler {
public:
  SenderHandler(std::shared_ptr<Receiver<T>> receiver) : receiver_(receiver) {}
  SenderHandler(SenderHandler &&) = default;
  SenderHandler &operator=(SenderHandler &&) = default;
  SenderHandler(const SenderHandler &) = default;
  SenderHandler &operator=(const SenderHandler &) = default;

  template <typename U> void send(U &&u) {
    if constexpr (std::is_convertible_v<U, T>) {
      receiver_->push(std::forward<U>(u));
    }
  }

  SenderHandler() = delete;

private:
  std::shared_ptr<Receiver<T>> receiver_;
};

// move only
template <typename T> class ReceiverHandler {
public:
  ReceiverHandler(std::shared_ptr<Receiver<T>> receiver) : inner_(receiver) {}
  ReceiverHandler(ReceiverHandler &&) = default;
  ReceiverHandler &operator=(ReceiverHandler &&) = default;

  T recv() const { return inner_->recv(); }

  template <class Rep, class Period>
  std::optional<T>
  recv_timeout(const std::chrono::duration<Rep, Period> &rel_time) const {
    return inner_->recv_timeout(rel_time);
  }

  ReceiverHandler(const ReceiverHandler &) = delete;
  ReceiverHandler &operator=(const ReceiverHandler &) = delete;

private:
  std::shared_ptr<Receiver<T>> inner_;
};

template <typename T> class Receiver {
private:
  // disallow being created on stack,
  // therefore it is set to private member
  Receiver() = default;

public:
  static std::shared_ptr<Receiver> Create() {
    return std::shared_ptr<Receiver>(new Receiver());
  }
  Receiver(Receiver &&) = default;
  Receiver &operator=(Receiver &&) = default;
  T recv() {
    std::unique_lock<std::mutex> lk(mutex_);
    condvar_.wait(lk, [this]() { return !queue_.empty(); });
    T ret = std::move(queue_.front());
    queue_.pop();
    lk.unlock();
    return ret;
  }

  template <class Rep, class Period>
  std::optional<T>
  recv_timeout(const std::chrono::duration<Rep, Period> &rel_time) {
    std::unique_lock<std::mutex> lk(mutex_);
    if (condvar_.wait_for(lk, rel_time, [this]() { return !queue_.empty(); })) {
      T ret = std::move(queue_.front());
      queue_.pop();
      lk.unlock();
      return ret;
    } else {
      return {};
    }
  }

  template <typename U> void push(U &&u) {
    if constexpr (std::is_convertible_v<U, T>) {
      mutex_.lock();
      queue_.push(std::forward<U>(u));
      mutex_.unlock();
      condvar_.notify_one();
    }
  }

  Receiver(const Receiver &) = delete;
  Receiver &operator=(const Receiver &) = delete;

private:
  std::queue<T> queue_;
  std::mutex mutex_;
  std::condition_variable condvar_;
};

} // namespace base

#endif