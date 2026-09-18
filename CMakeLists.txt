cmake_minimum_required(VERSION 3.20)

project(CyberGuard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CYBERGUARD_BUILD_TESTS "Build CyberGuard tests" ON)

add_library(CyberGuardCore
    src/core/Network.cpp
    src/core/Packet.cpp
    src/devices/Firewall.cpp
    src/devices/Router.cpp
    src/devices/Server.cpp
    src/devices/Workstation.cpp
)

target_include_directories(CyberGuardCore
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(CyberGuardCore PUBLIC cxx_std_20)

add_executable(CyberGuard
    src/main.cpp
)

target_link_libraries(CyberGuard PRIVATE CyberGuardCore)

include(CTest)

if(CYBERGUARD_BUILD_TESTS)
    include(FetchContent)

    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    )
    FetchContent_MakeAvailable(googletest)

    add_executable(CyberGuardSmokeTest
        tests/SmokeTest.cpp
    )

    target_link_libraries(CyberGuardSmokeTest PRIVATE CyberGuardCore)

    add_test(NAME CyberGuardSmokeTest COMMAND CyberGuardSmokeTest)

    add_executable(CyberGuardTests
        tests/PacketTests.cpp
        tests/RouterTests.cpp
        tests/FirewallTests.cpp
        tests/ServerTests.cpp
        tests/NetworkTests.cpp
    )

    target_link_libraries(CyberGuardTests
        PRIVATE
            CyberGuardCore
            GTest::gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(CyberGuardTests)
endif()