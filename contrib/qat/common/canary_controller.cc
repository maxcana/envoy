#include "contrib/qat/common/canary_controller.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <utility>

#include "source/common/common/assert.h"
#include "source/common/common/fmt.h"

namespace Envoy {
namespace Extensions {
namespace Qat {

namespace {

uint32_t probabilityUnits(double probability) {
  return static_cast<uint32_t>(std::lround(probability * CanaryController::ProbabilityScale));
}

std::string formatLatencies(const std::vector<double>& latencies_ms) {
  std::string result;
  for (const double latency_ms : latencies_ms) {
    if (!result.empty()) {
      result.append(", ");
    }
    result.append(fmt::format("{:.3f}", latency_ms));
  }
  return result;
}

} // namespace

CanaryController::CanaryController(std::string engine_name, CanaryControllerConfig config)
    : engine_name_(std::move(engine_name)), config_(config),
      probability_decrease_units_(probabilityUnits(config.probability_decrease)),
      probability_increase_units_(probabilityUnits(config.probability_increase)) {}

CanaryController::~CanaryController() {
  stopping_.store(true, std::memory_order_release);
  sleep_condition_.notifyAll();
  if (thread_ != nullptr) {
    thread_->join();
  }
}

void CanaryController::start(Thread::ThreadFactory& thread_factory,
                             MeasureCallback measure_callback) {
  ASSERT(thread_ == nullptr);
  measure_callback_ = std::move(measure_callback);
  thread_ =
      thread_factory.createThread([this] { run(); }, Thread::Options{std::string("QatCanary")});
}

bool CanaryController::shouldUseQat() {
  const uint32_t probability = probability_units_.load(std::memory_order_relaxed);
  uint32_t current = routing_accumulator_.load(std::memory_order_relaxed);
  uint32_t updated;
  bool use_qat;
  do {
    const uint32_t sum = current + probability;
    use_qat = sum >= ProbabilityScale;
    updated = use_qat ? sum - ProbabilityScale : sum;
  } while (!routing_accumulator_.compare_exchange_weak(current, updated,
                                                       std::memory_order_relaxed));
  return use_qat;
}

double CanaryController::probabilityForTest() const {
  return static_cast<double>(probability_units_.load(std::memory_order_relaxed)) /
         ProbabilityScale;
}

void CanaryController::setProbabilityForTest(double probability) {
  probability_units_.store(probabilityUnits(probability), std::memory_order_relaxed);
  routing_accumulator_.store(0, std::memory_order_relaxed);
}

double CanaryController::calculateCriticalLatencyForTest(
    const std::vector<double>& latencies_ms) {
  return calculateCriticalLatency(latencies_ms);
}

double CanaryController::calculateCriticalLatency(const std::vector<double>& latencies_ms) {
  ASSERT(!latencies_ms.empty());

  std::vector<double> sorted = latencies_ms;
  std::sort(sorted.begin(), sorted.end());
  const size_t middle = sorted.size() / 2;
  const double median = sorted.size() % 2 == 0 ? (sorted[middle - 1] + sorted[middle]) / 2.0
                                               : sorted[middle];
  const double mean =
      std::accumulate(sorted.begin(), sorted.end(), 0.0) / static_cast<double>(sorted.size());

  double variance = 0;
  if (sorted.size() > 1) {
    for (const double latency_ms : sorted) {
      const double difference = latency_ms - mean;
      variance += difference * difference;
    }
    variance /= static_cast<double>(sorted.size() - 1);
  }

  // Thirty samples cannot establish an empirical p99 reliably. Combine a three-sigma estimate
  // with a conservative two-times-median floor.
  return std::max(2.0 * median, mean + 3.0 * std::sqrt(variance));
}

bool CanaryController::waitFor(std::chrono::milliseconds duration) {
  Thread::LockGuard lock(sleep_lock_);
  if (stopping_.load(std::memory_order_acquire)) {
    return false;
  }
  sleep_condition_.waitFor(sleep_lock_, duration);
  return !stopping_.load(std::memory_order_acquire);
}

void CanaryController::updateProbability(bool busy, double latency_ms) {
  uint32_t current = probability_units_.load(std::memory_order_relaxed);
  uint32_t updated;
  do {
    updated = busy ? (current > probability_decrease_units_
                          ? current - probability_decrease_units_
                          : 0)
                   : std::min(ProbabilityScale, current + probability_increase_units_);
  } while (!probability_units_.compare_exchange_weak(current, updated, std::memory_order_relaxed));

  ENVOY_LOG(info,
            "{} QAT canary latency_ms={:.3f} critical_ms={:.3f} busy={} qat_probability={:.4f}",
            engine_name_, latency_ms, critical_latency_ms_, busy,
            static_cast<double>(updated) / ProbabilityScale);
}

void CanaryController::run() {
  for (uint32_t sample = 0;
       sample < config_.startup_warmup_samples && !stopping_.load(std::memory_order_acquire);
       ++sample) {
    if (!measure_callback_().has_value()) {
      ENVOY_LOG(warn, "{} QAT startup warmup failed", engine_name_);
    }
    if (!waitFor(config_.startup_sample_interval)) {
      return;
    }
  }

  std::vector<double> startup_latencies;
  startup_latencies.reserve(config_.startup_samples);

  for (uint32_t sample = 0;
       sample < config_.startup_samples && !stopping_.load(std::memory_order_acquire); ++sample) {
    const std::optional<double> latency_ms = measure_callback_();
    if (latency_ms.has_value()) {
      startup_latencies.push_back(*latency_ms);
    } else {
      ENVOY_LOG(warn, "{} QAT startup canary failed", engine_name_);
    }

    if (sample + 1 < config_.startup_samples && !waitFor(config_.startup_sample_interval)) {
      return;
    }
  }

  if (startup_latencies.empty()) {
    probability_units_.store(0, std::memory_order_relaxed);
    ENVOY_LOG(error, "{} QAT startup canaries all failed; qat_probability=0", engine_name_);
  } else {
    critical_latency_ms_ =
        std::max(calculateCriticalLatency(startup_latencies), config_.min_critical_latency_ms);
    probability_units_.store(ProbabilityScale, std::memory_order_relaxed);
    ENVOY_LOG(info, "{} QAT startup canary latencies_ms={} critical_ms={:.3f}", engine_name_,
              formatLatencies(startup_latencies), critical_latency_ms_);
  }

  while (waitFor(config_.poll_interval)) {
    const std::optional<double> latency_ms = measure_callback_();
    if (!latency_ms.has_value()) {
      ENVOY_LOG(warn, "{} QAT runtime canary failed", engine_name_);
      updateProbability(true, std::numeric_limits<double>::quiet_NaN());
      continue;
    }
    if (critical_latency_ms_ == 0) {
      critical_latency_ms_ =
          std::max(2.0 * *latency_ms, config_.min_critical_latency_ms);
    }
    updateProbability(*latency_ms > critical_latency_ms_, *latency_ms);
  }
}

} // namespace Qat
} // namespace Extensions
} // namespace Envoy
