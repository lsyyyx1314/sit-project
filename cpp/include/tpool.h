// 极简固定大小线程池（M5.16）。
//
// 设计取舍：
//   * 线程数固定、构造即起——exp 各实验节与 dashboard 的连接处理复用同一个
//     池，消除"每节/每连接临时起线程"的创建开销与栈分配；
//   * 工作线程栈默认收紧到 512KB（pthread_attr_setstacksize）——glibc 默认
//     8MB/线程，32 个连接线程仅虚拟内存就 256MB，实际用到远小于此；
//   * wait_idle() 阻塞至"队列空且在跑任务全部结束"，供分段提交后归并结果；
//   * 非线程安全入口：submit/wait_idle/析构应自同一线程（或外部串行化）调用，
//     任务体自身并发安全由调用方保证（exp 的 worker 各写各的槽位）。
#pragma once

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <pthread.h>
#include <queue>
#include <vector>

namespace mpv {

class ThreadPool {
 public:
  explicit ThreadPool(size_t threads, size_t stack_kb = 512);
  ~ThreadPool();
  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;

  void submit(std::function<void()> job);
  void wait_idle();                  // 队列空且在跑任务全部结束
  size_t threads() const { return workers_.size(); }

 private:
  static void* trampoline(void* self);
  void worker_loop();

  std::vector<pthread_t> workers_;
  std::queue<std::function<void()>> jobs_;
  std::mutex mu_;
  std::condition_variable has_job_;   // 有新任务 / 停止
  std::condition_variable all_done_;  // 队列排干
  bool stop_ = false;
  uint64_t submitted_ = 0;
  uint64_t completed_ = 0;
};

}  // namespace mpv
