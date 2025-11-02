const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Check if building for mobile platforms
    const is_ios = target.result.os.tag == .ios;
    const is_android = target.result.os.tag == .linux and
        (target.result.abi == .android or target.result.abi == .androideabi);

    // Determine iOS SDK path if needed
    const ios_sdk_path = if (is_ios) blk: {
        if (target.result.cpu.arch == .aarch64 and target.result.abi == .simulator) {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk";
        } else if (target.result.cpu.arch == .x86_64) {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk";
        } else {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk";
        }
    } else null;

    // Export module (works with both Zig 0.13 and 0.15)
    // TapTun now only provides platform device abstraction - no protocol logic
    const taptun_module = b.addModule("taptun", .{
        .root_source_file = b.path("src/taptun.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add iOS SDK include paths for @cImport
    if (ios_sdk_path) |sdk| {
        const ios_include = b.fmt("{s}/usr/include", .{sdk});
        taptun_module.addSystemIncludePath(.{ .cwd_relative = ios_include });
    }

    // Create libraries using Zig 0.15 API (compatible with module system)
    // Note: This uses Step.Compile.create which works with main_module
    const lib = std.Build.Step.Compile.create(b, .{
        .name = "taptun",
        .root_module = taptun_module,
        .kind = .lib,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const shared_lib = std.Build.Step.Compile.create(b, .{
        .name = "taptun",
        .root_module = taptun_module,
        .kind = .lib,
        .linkage = .dynamic,
    });
    b.installArtifact(shared_lib);

    // Unit tests
    const unit_tests = b.addTest(.{
        .root_module = taptun_module,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Documentation
    const docs = std.Build.Step.Compile.create(b, .{
        .name = "taptun",
        .root_module = taptun_module,
        .kind = .lib,
        .linkage = .static,
    });

    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&install_docs.step);

    // Benchmark executables
    const throughput_module = b.createModule(.{
        .root_source_file = b.path("bench/throughput.zig"),
        .target = target,
        .optimize = optimize,
    });
    throughput_module.addImport("taptun", taptun_module);

    const throughput_exe = std.Build.Step.Compile.create(b, .{
        .name = "throughput",
        .root_module = throughput_module,
        .kind = .exe,
        .linkage = null,
    });

    const latency_module = b.createModule(.{
        .root_source_file = b.path("bench/latency.zig"),
        .target = target,
        .optimize = optimize,
    });
    latency_module.addImport("taptun", taptun_module);

    const latency_exe = std.Build.Step.Compile.create(b, .{
        .name = "latency",
        .root_module = latency_module,
        .kind = .exe,
        .linkage = null,
    });

    const install_throughput = b.addInstallArtifact(throughput_exe, .{});
    const install_latency = b.addInstallArtifact(latency_exe, .{});

    const bench_step = b.step("bench", "Build benchmarks");
    bench_step.dependOn(&install_throughput.step);
    bench_step.dependOn(&install_latency.step);

    const run_throughput = b.addRunArtifact(throughput_exe);
    const run_latency = b.addRunArtifact(latency_exe);

    const run_bench_step = b.step("run-bench", "Run all benchmarks");
    run_bench_step.dependOn(&run_throughput.step);
    run_bench_step.dependOn(&run_latency.step);

    // ═══════════════════════════════════════════════════════════════════════════
    // iOS Cross-Compilation Steps
    // ═══════════════════════════════════════════════════════════════════════════

    // iOS Device (ARM64)
    const ios_device_step = b.step("ios-device", "Build for iOS device (arm64)");
    buildForTarget(b, ios_device_step, "aarch64-ios", optimize);

    // iOS Simulator (ARM64 - Apple Silicon Macs)
    const ios_sim_arm_step = b.step("ios-sim-arm", "Build for iOS Simulator (arm64, Apple Silicon)");
    buildForTarget(b, ios_sim_arm_step, "aarch64-ios-simulator", optimize);

    // iOS Simulator (x86_64 - Intel Macs)
    const ios_sim_x86_step = b.step("ios-sim-x86", "Build for iOS Simulator (x86_64, Intel)");
    buildForTarget(b, ios_sim_x86_step, "x86_64-ios-simulator", optimize);

    // iOS Universal (all architectures)
    const ios_all_step = b.step("ios-all", "Build for all iOS targets");
    ios_all_step.dependOn(ios_device_step);
    ios_all_step.dependOn(ios_sim_arm_step);
    ios_all_step.dependOn(ios_sim_x86_step);

    // ═══════════════════════════════════════════════════════════════════════════
    // Android Cross-Compilation Steps
    // ═══════════════════════════════════════════════════════════════════════════

    // Android ARM64
    const android_arm64_step = b.step("android-arm64", "Build for Android ARM64 (arm64-v8a)");
    buildForTarget(b, android_arm64_step, "aarch64-linux-android", optimize);

    // Android ARMv7
    const android_arm_step = b.step("android-arm", "Build for Android ARMv7 (armeabi-v7a)");
    buildForTarget(b, android_arm_step, "arm-linux-androideabi", optimize);

    // Android x86_64
    const android_x86_64_step = b.step("android-x86_64", "Build for Android x86_64");
    buildForTarget(b, android_x86_64_step, "x86_64-linux-android", optimize);

    // Android x86
    const android_x86_step = b.step("android-x86", "Build for Android x86 (i686)");
    buildForTarget(b, android_x86_step, "x86-linux-android", optimize);

    // Android Universal (all ABIs)
    const android_all_step = b.step("android-all", "Build for all Android ABIs");
    android_all_step.dependOn(android_arm64_step);
    android_all_step.dependOn(android_arm_step);
    android_all_step.dependOn(android_x86_64_step);
    android_all_step.dependOn(android_x86_step);

    // ═══════════════════════════════════════════════════════════════════════════
    // Mobile All-in-One
    // ═══════════════════════════════════════════════════════════════════════════

    const mobile_step = b.step("mobile", "Build for all mobile platforms (iOS + Android)");
    mobile_step.dependOn(ios_all_step);
    mobile_step.dependOn(android_all_step);

    // Suppress unused variable warning
    _ = is_android;
}

/// Helper function to build for a specific target triple
fn buildForTarget(
    b: *std.Build,
    step: *std.Build.Step,
    triple: []const u8,
    optimize: std.builtin.OptimizeMode,
) void {
    // Parse target triple
    const query = std.Target.Query.parse(.{
        .arch_os_abi = triple,
    }) catch {
        std.debug.print("Invalid target triple: {s}\n", .{triple});
        return;
    };

    const resolved_target = b.resolveTargetQuery(query);

    // Check if building for mobile platforms (iOS/Android)
    const is_ios = resolved_target.result.os.tag == .ios;
    const is_android = resolved_target.result.os.tag == .linux and
        (resolved_target.result.abi == .android or resolved_target.result.abi == .androideabi);
    const is_mobile = is_ios or is_android;

    // Determine iOS SDK path if needed
    const ios_sdk_path = if (is_ios) blk: {
        if (resolved_target.result.cpu.arch == .aarch64 and
            resolved_target.result.abi == .simulator)
        {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk";
        } else if (resolved_target.result.cpu.arch == .x86_64) {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk";
        } else {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk";
        }
    } else null;

    // For mobile platforms, use c_ffi.zig as root (exports C symbols)
    // For desktop platforms, use taptun.zig as root (pure Zig)
    const root_source = if (is_mobile)
        b.path("src/c_ffi.zig")
    else
        b.path("src/taptun.zig");

    // Create module for this target
    const target_module = b.addModule(b.fmt("taptun-{s}", .{triple}), .{
        .root_source_file = root_source,
        .target = resolved_target,
        .optimize = optimize,
    });

    // Add iOS SDK include paths if needed
    if (ios_sdk_path) |sdk| {
        const ios_include = b.fmt("{s}/usr/include", .{sdk});
        target_module.addSystemIncludePath(.{ .cwd_relative = ios_include });
    }

    // Create static library
    const lib = std.Build.Step.Compile.create(b, .{
        .name = b.fmt("taptun-{s}", .{triple}),
        .root_module = target_module,
        .kind = .lib,
        .linkage = .static,
    });

    // Install to target-specific directory
    const install_lib = b.addInstallArtifact(lib, .{
        .dest_dir = .{
            .override = .{
                .custom = b.fmt("lib/{s}", .{triple}),
            },
        },
    });

    step.dependOn(&install_lib.step);
}
