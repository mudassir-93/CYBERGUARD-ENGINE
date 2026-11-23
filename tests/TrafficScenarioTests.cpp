#include "core/TrafficScenarioGenerator.hpp"
#include <gtest/gtest.h>
#include <stdexcept>
namespace cyberguard {
TEST(TrafficScenarioTests, RejectsInvalidPortRange) {
    Network n;
    EXPECT_THROW(TrafficScenarioGenerator::runPortScan(n,"10.0.0.1","10.0.0.2",20,10,1,1),std::invalid_argument);
}
} // namespace cyberguard
