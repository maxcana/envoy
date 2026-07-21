load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_library(
    name = "canary_controller_lib",
    srcs = ["canary_controller.cc"],
    hdrs = ["canary_controller.h"],
    deps = [
        "//envoy/thread:thread_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:fmt_lib",
        "//source/common/common:lock_guard_lib",
        "//source/common/common:logger_lib",
        "//source/common/common:thread_lib",
    ],
)

envoy_cc_test(
    name = "canary_controller_test",
    srcs = ["canary_controller_test.cc"],
    deps = [":canary_controller_lib"],
)
