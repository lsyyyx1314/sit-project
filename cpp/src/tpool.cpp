#include "tpool.h"

#include <pthread.h>

namespace mpv {

ThreadPool::ThreadPool(size_t threads, size_t stack_kb) {
  if (threads == 0) threads = 1;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, stack_kb * 1024);
  workers_.reserve(threads);
  for (size_t i = 0; i < threads; ++i) {
    pthread_t t;
    if (pthread_create(&t, &attr, &ThreadPool::trampoline, this) != 0)
      break;  // 线程资源耗尽：至少保住已创建的部分
    workers_.push_back(t);
  }
  pthread_attr_destroy(&attr);
}

void* ThreadPool::trampoline(void* self) {
  static_cast<ThreadPool*>(self)->worker_loop();
  return nullptr;
}

ThreadPool::~ThreadPool() {
  {
    std::lock_guard<std::mutex> lk(mu_);
    stop_ = true;
  }
  has_job_.notify_all();
  for (pthread_t w : workers_)
    pthread_join(w, nullptr);
}

void ThreadPool::worker_loop() {
  while (true) {
    std::function<void()> job;
    {
      std::unique_lock<std::mutex> lk(mu_);
      has_job_.wait(lk, [this] { return stop_ || !jobs_.empty(); });
      if (stop_ && jobs_.empty()) return;
      job = std::move(jobs_.front());
      jobs_.pop();
    }
    job();
    std::lock_guard<std::mutex> lk(mu_);
    ++completed_;
    if (jobs_.empty() && completed_ == submitted_) all_done_.notify_all();
  }
}

void ThreadPool::submit(std::function<void()> job) {
  {
    std::lock_guard<std::mutex> lk(mu_);
    jobs_.push(std::move(job));
    ++submitted_;
  }
  has_job_.notify_one();
}

void ThreadPool::wait_idle() {
  std::unique_lock<std::mutex> lk(mu_);
  all_done_.wait(lk, [this] { return submitted_ == completed_ && jobs_.empty(); });
}

}  // namespace mpv
