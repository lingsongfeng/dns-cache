
#include <memory>
#include <mutex>
#include <thread>

using namespace std::chrono_literals;

// TODO(lingsong.feng): use atomic instead of mutex
class TokenBucket : public std::enable_shared_from_this<TokenBucket> {
public:
    TokenBucket(int limit, int rate) : limit_(limit), rate_(rate), counter_(0), t_{} {
    }

    ~TokenBucket() {
        t_.join();
    }

    void start() {
        // TODO(lingsong.feng): use weak ptr
        std::thread add([](std::shared_ptr<TokenBucket> ptr) {
            while (true) {
                ptr->try_add();
                std::this_thread::sleep_for(500ms);
            }
        }, shared_from_this());
        t_ = std::move(add);
    }
    void try_add() {
        mutex_.lock();
        if (counter_ + 1 <= limit_) {
            counter_++;
        }
        mutex_.unlock();
    }

    bool try_sub() {
        std::lock_guard<std::mutex> lg(mutex_);
        if (counter_ - 1 >= 0) {
            counter_--;
            return true;
        }
        return false;
    }
private:
    std::mutex mutex_;
    int counter_;
    int limit_;
    int rate_;
    std::thread t_;
};