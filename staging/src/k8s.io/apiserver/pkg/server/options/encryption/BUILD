package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_library",
)

go_library(
    name = "go_default_library",
    srcs = [
        "encryption.go",
        "types.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor/k8s.io/apiserver/pkg/storage/value:go_default_library",
        "//vendor/k8s.io/apiserver/pkg/storage/value/encrypt/aes:go_default_library",
        "//vendor/k8s.io/apiserver/pkg/storage/value/encrypt/envelope:go_default_library",
        "//vendor/k8s.io/apiserver/pkg/storage/value/encrypt/identity:go_default_library",
        "//vendor/k8s.io/apiserver/pkg/storage/value/encrypt/secretbox:go_default_library",
    ],
)
