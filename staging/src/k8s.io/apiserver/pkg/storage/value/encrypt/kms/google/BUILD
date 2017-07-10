package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_library",
)

go_library(
    name = "go_default_library",
    srcs = ["google.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor/google.golang.org/api/cloudkms/v1:go_default_library",
        "//vendor/google.golang.org/api/googleapi:go_default_library",
    ],
)
