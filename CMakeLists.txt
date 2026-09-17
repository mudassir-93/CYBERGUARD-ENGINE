cmake_minimum_required(VERSION 3.20)

project(CyberGuard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CYBERGUARD_BUILD_TESTS "Build CyberGuard tests" ON)

add_library(CyberGuardCore
    src/core/Network.cpp
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
    add_executable(CyberGuardSmokeTest
        tests/SmokeTest.cpp
    )

    target_link_libraries(CyberGuardSmokeTest PRIVATE CyberGuardCore)

    add_test(NAME CyberGuardSmokeTest COMMAND CyberGuardSmokeTest)
endif()