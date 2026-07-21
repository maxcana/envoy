#include "contrib/qat/common/canary_controller.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Qat {

namespace {

CanaryControllerConfig testConfig() {
  return {30, std::chrono::milliseconds(10), std::chrono::seconds(1), 0.1, 0.1};
}

TEST(CanaryControllerTest, CalculatesConservativeCriticalLatency) {
  const std::vector<double> latencies{3.79, 4.12, 4.32, 3.80, 3.97};
  EXPECT_DOUBLE_EQ(7.94, CanaryController::calculateCriticalLatencyForTest(latencies));
}

TEST(CanaryControllerTest, RoutesDeterministicShareToQat) {
  CanaryController controller("test", testConfig());
  controller.setProbabilityForTest(0.9);

  uint32_t qat_operations = 0;
  for (uint32_t operation = 0; operation < 100; ++operation) {
    qat_operations += controller.shouldUseQat() ? 1 : 0;
  }
  EXPECT_EQ(90, qat_operations);
}

TEST(CanaryControllerTest, HandlesProbabilityEndpoints) {
  CanaryController controller("test", testConfig());
  controller.setProbabilityForTest(0);
  EXPECT_FALSE(controller.shouldUseQat());
  controller.setProbabilityForTest(1);
  EXPECT_TRUE(controller.shouldUseQat());
}

TEST(CanaryControllerTest, AdjustsProbabilityGradually) {
  CanaryController controller("test", testConfig());
  controller.setProbabilityForTest(1);
  controller.updateProbabilityForTest(true);
  EXPECT_DOUBLE_EQ(0.9, controller.probabilityForTest());
  controller.updateProbabilityForTest(false);
  EXPECT_DOUBLE_EQ(1, controller.probabilityForTest());
}

} // namespace
} // namespace Qat
} // namespace Extensions
} // namespace Envoy
