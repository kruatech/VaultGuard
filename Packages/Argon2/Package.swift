// swift-tools-version:5.9
//
// The Argon2 reference implementation, vendored.
//
// Replaces the `Argon2Swift` package, which the app used for a single function and which
// pulled the same C library in twice: once as a SwiftPM dependency on a floating `master`
// branch, and once as a git submodule that is never compiled but that SwiftPM still tries to
// clone — and that clone is what broke builds from a fresh checkout.
//
// The source set below is exactly the one upstream's own Package.swift compiles, and exactly
// what `Argon2Swift` was building: the portable reference core, not the SSE-only `opt.c`.
// See PROVENANCE.md for the pinned commit and file hashes.

import PackageDescription

let package = Package(
    name: "Argon2",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "CArgon2", targets: ["CArgon2"]),
    ],
    targets: [
        .target(
            name: "CArgon2",
            path: "Sources/CArgon2",
            sources: [
                "argon2.c",
                "core.c",
                "encoding.c",
                "ref.c",
                "thread.c",
                "blake2/blake2b.c",
            ],
            publicHeadersPath: "include"
        ),
    ]
)
