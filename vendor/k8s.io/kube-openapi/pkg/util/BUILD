load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "trie.go",
        "util.go",
    ],
    importmap = "k8s.io/kubernetes/vendor/k8s.io/kube-openapi/pkg/util",
    importpath = "k8s.io/kube-openapi/pkg/util",
    visibility = ["//visibility:public"],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [
        ":package-srcs",
        "//vendor/k8s.io/kube-openapi/pkg/util/proto:all-srcs",
        "//vendor/k8s.io/kube-openapi/pkg/util/sets:all-srcs",
    ],
    tags = ["automanaged"],
    visibility = ["//visibility:public"],
)
