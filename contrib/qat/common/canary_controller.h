#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "envoy/thread/thread.h"

#include "source/common/common/lock_guard.h"
#include "source/common/common/logger.h"
#include "source/common/common/thread.h"

namespace Envoy {
namespace Extensions {
namespace Qat {

struct CanaryControllerConfig {
  uint32_t startup_samples;
  std::chrono::milliseconds startup_sample_interval;
  std::chrono::milliseconds poll_interval;
  double probability_decrease;
  double probability_increase;
};

class CanaryController : public Logger::Loggable<Logger::Id::connection> {
public:
  static constexpr uint32_t ProbabilityScale = 10000;

  using MeasureCallback = std::function<std::optional<double>()>;

  CanaryController(std::string engine_name, CanaryControllerConfig config);
  ~CanaryController();

  void start(Thread::ThreadFactory& thread_factory, MeasureCallback measure_callback);
  bool shouldUseQat();

  double probabilityForTest() const;
  void setProbabilityForTest(double probability);
  void updateProbabilityForTest(bool busy) { updateProbability(busy, 0); }
  double criticalLatencyForTest() const { return critical_latency_ms_; }
  static double calculateCriticalLatencyForTest(const std::vector<double>& latencies_ms);

private:
  void run();
  bool waitFor(std::chrono::milliseconds duration);
  void updateProbability(bool busy, double latency_ms);
  static double calculateCriticalLatency(const std::vector<double>& latencies_ms);

  const std::string engine_name_;
  const CanaryControllerConfig config_;
  const uint32_t probability_decrease_units_;
  const uint32_t probability_increase_units_;

  std::atomic<uint32_t> probability_units_{0};
  std::atomic<uint32_t> routing_accumulator_{0};
  std::atomic<bool> stopping_{false};
  Thread::MutexBasicLockable sleep_lock_;
  Thread::CondVar sleep_condition_;
  Thread::ThreadPtr thread_;
  MeasureCallback measure_callback_;
  double critical_latency_ms_{0};
};

using CanaryControllerSharedPtr = std::shared_ptr<CanaryController>;

} // namespace Qat
} // namespace Extensions
} // namespace Envoy
