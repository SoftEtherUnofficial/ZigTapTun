//! Android Platform Support
//!
//! Android provides VPN functionality through the VpnService API.
//! Unlike desktop platforms, Android gives us a file descriptor to a TUN device
//! that's already configured by the system.
//!
//! Architecture:
//! - Java/Kotlin code creates VpnService
//! - Service establishes VPN and gets file descriptor
//! - FD passed to native code via JNI
//! - Zig code reads/writes packets through FD
//! - Packets processed with L2L3Translator
//!
//! Key Differences from Desktop:
//! - No direct device creation (system provides FD)
//! - No routing configuration (handled by VpnService.Builder)
//! - Must respect Android lifecycle (service can be killed)
//! - Background process restrictions

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// Android VPN device using VpnService API
pub const AndroidVpnDevice = struct {
    allocator: std.mem.Allocator,
    fd: i32,
    name: []const u8,
    mtu: u32,

    // Configuration (set by VpnService.Builder)
    ipv4_address: ?u32,
    ipv4_netmask: ?u32,
    ipv6_address: ?[16]u8,
    ipv6_prefix_length: ?u8,

    // State
    is_active: bool,
    bytes_read: u64,
    bytes_written: u64,
    packets_read: u64,
    packets_written: u64,

    const Self = @This();

    /// Open Android VPN device from file descriptor
    /// The FD is obtained from VpnService.Builder.establish()
    pub fn openFromFd(
        allocator: std.mem.Allocator,
        fd: i32,
        mtu: u32,
    ) !Self {
        if (fd < 0) return error.InvalidFileDescriptor;

        // Set non-blocking mode
        const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
        _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.O.NONBLOCK);

        const name = try allocator.dupe(u8, "android-vpn");
        errdefer allocator.free(name);

        return Self{
            .allocator = allocator,
            .fd = fd,
            .name = name,
            .mtu = mtu,
            .ipv4_address = null,
            .ipv4_netmask = null,
            .ipv6_address = null,
            .ipv6_prefix_length = null,
            .is_active = true,
            .bytes_read = 0,
            .bytes_written = 0,
            .packets_read = 0,
            .packets_written = 0,
        };
    }

    /// Close device
    pub fn close(self: *Self) void {
        if (self.fd >= 0) {
            posix.close(self.fd);
            self.fd = -1;
        }
        self.is_active = false;
        self.allocator.free(self.name);
    }

    /// Read packet from device
    pub fn read(self: *Self, buffer: []u8) !usize {
        if (!self.is_active) return error.DeviceNotActive;
        if (self.fd < 0) return error.InvalidFileDescriptor;

        const bytes_read = posix.read(self.fd, buffer) catch |err| {
            return switch (err) {
                error.WouldBlock => error.WouldBlock,
                else => error.ReadFailed,
            };
        };

        if (bytes_read == 0) {
            // EOF - device closed
            self.is_active = false;
            return error.DeviceClosed;
        }

        self.bytes_read += bytes_read;
        self.packets_read += 1;

        return bytes_read;
    }

    /// Write packet to device
    pub fn write(self: *Self, data: []const u8) !void {
        if (!self.is_active) return error.DeviceNotActive;
        if (self.fd < 0) return error.InvalidFileDescriptor;

        if (data.len > self.mtu) {
            return error.PacketTooLarge;
        }

        const bytes_written = posix.write(self.fd, data) catch |err| {
            return switch (err) {
                error.WouldBlock => error.WouldBlock,
                else => error.WriteFailed,
            };
        };

        if (bytes_written != data.len) {
            return error.PartialWrite;
        }

        self.bytes_written += bytes_written;
        self.packets_written += 1;
    }

    /// Set IPv4 configuration (for tracking only - actual config done in Java)
    pub fn setIpv4Address(self: *Self, address: u32, netmask: u32) void {
        self.ipv4_address = address;
        self.ipv4_netmask = netmask;
    }

    /// Set IPv6 configuration (for tracking only - actual config done in Java)
    pub fn setIpv6Address(self: *Self, address: [16]u8, prefix_len: u8) void {
        self.ipv6_address = address;
        self.ipv6_prefix_length = prefix_len;
    }

    /// Get device name
    pub fn getName(self: *const Self) []const u8 {
        return self.name;
    }

    /// Get MTU
    pub fn getMtu(self: *const Self) u32 {
        return self.mtu;
    }

    /// Get file descriptor (for polling)
    pub fn getFd(self: *const Self) i32 {
        return self.fd;
    }

    /// Get statistics
    pub fn getStats(self: *const Self) Stats {
        return Stats{
            .bytes_read = self.bytes_read,
            .bytes_written = self.bytes_written,
            .packets_read = self.packets_read,
            .packets_written = self.packets_written,
        };
    }

    pub const Stats = struct {
        bytes_read: u64,
        bytes_written: u64,
        packets_read: u64,
        packets_written: u64,
    };
};

// ═══════════════════════════════════════════════════════════════════════════
// JNI Bridge - C API for Java/Kotlin
// ═══════════════════════════════════════════════════════════════════════════

/// Opaque handle for JNI
pub const ZigTapTunHandle = *anyopaque;

/// Error codes for JNI
pub const ZigTapTunError = enum(c_int) {
    Success = 0,
    OutOfMemory = -1,
    InvalidParameter = -2,
    InvalidFileDescriptor = -3,
    DeviceNotActive = -4,
    DeviceClosed = -5,
    BufferTooSmall = -6,
    PacketTooLarge = -7,
    ReadFailed = -8,
    WriteFailed = -9,
    PartialWrite = -10,
    WouldBlock = -11,
    Unknown = -99,
};

/// Convert Zig error to JNI error code
fn errorToCode(err: anyerror) ZigTapTunError {
    return switch (err) {
        error.OutOfMemory => .OutOfMemory,
        error.InvalidFileDescriptor => .InvalidFileDescriptor,
        error.DeviceNotActive => .DeviceNotActive,
        error.DeviceClosed => .DeviceClosed,
        error.BufferTooSmall => .BufferTooSmall,
        error.PacketTooLarge => .PacketTooLarge,
        error.ReadFailed => .ReadFailed,
        error.WriteFailed => .WriteFailed,
        error.PartialWrite => .PartialWrite,
        error.WouldBlock => .WouldBlock,
        else => .Unknown,
    };
}

/// Create Android VPN device from file descriptor
/// Called from Java after VpnService.Builder.establish()
export fn zig_taptun_android_create(fd: i32, mtu: u32) ?ZigTapTunHandle {
    const allocator = std.heap.c_allocator;

    const device = AndroidVpnDevice.openFromFd(allocator, fd, mtu) catch return null;

    const device_ptr = allocator.create(AndroidVpnDevice) catch return null;
    device_ptr.* = device;

    return @ptrCast(device_ptr);
}

/// Destroy Android VPN device
export fn zig_taptun_android_destroy(handle: ZigTapTunHandle) void {
    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle));
    const allocator = device.allocator;
    device.close();
    allocator.destroy(device);
}

/// Read packet from device
/// Returns number of bytes read, or negative error code
export fn zig_taptun_android_read(
    handle: ZigTapTunHandle,
    buffer: [*]u8,
    buffer_size: usize,
) i32 {
    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle));

    const bytes_read = device.read(buffer[0..buffer_size]) catch |err| {
        const code = errorToCode(err);
        return @intFromEnum(code);
    };

    return @intCast(bytes_read);
}

/// Write packet to device
export fn zig_taptun_android_write(
    handle: ZigTapTunHandle,
    data: [*]const u8,
    length: usize,
) ZigTapTunError {
    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle));

    device.write(data[0..length]) catch |err| {
        return errorToCode(err);
    };

    return .Success;
}

/// Set IPv4 address (for tracking)
export fn zig_taptun_android_set_ipv4(
    handle: ZigTapTunHandle,
    address: u32,
    netmask: u32,
) void {
    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle));
    device.setIpv4Address(address, netmask);
}

/// Set IPv6 address (for tracking)
export fn zig_taptun_android_set_ipv6(
    handle: ZigTapTunHandle,
    address: [*]const u8,
    prefix_len: u8,
) void {
    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle));
    var addr: [16]u8 = undefined;
    @memcpy(&addr, address[0..16]);
    device.setIpv6Address(addr, prefix_len);
}

/// Get file descriptor for polling
export fn zig_taptun_android_get_fd(handle: ZigTapTunHandle) i32 {
    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle));
    return device.getFd();
}

/// Get MTU
export fn zig_taptun_android_get_mtu(handle: ZigTapTunHandle) u32 {
    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle));
    return device.getMtu();
}

/// Get statistics
export fn zig_taptun_android_get_stats(
    handle: ZigTapTunHandle,
    out_bytes_read: *u64,
    out_bytes_written: *u64,
    out_packets_read: *u64,
    out_packets_written: *u64,
) void {
    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle));
    const stats = device.getStats();

    out_bytes_read.* = stats.bytes_read;
    out_bytes_written.* = stats.bytes_written;
    out_packets_read.* = stats.packets_read;
    out_packets_written.* = stats.packets_written;
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "Android device basic" {
    // Note: This test requires a valid file descriptor
    // In actual Android environment, this would come from VpnService
    // For testing, we can't easily create a TUN fd

    // Test error handling with invalid FD
    const allocator = std.testing.allocator;

    const result = AndroidVpnDevice.openFromFd(allocator, -1, 1500);
    try std.testing.expectError(error.InvalidFileDescriptor, result);
}

test "Android JNI error codes" {
    try std.testing.expectEqual(
        ZigTapTunError.OutOfMemory,
        errorToCode(error.OutOfMemory),
    );

    try std.testing.expectEqual(
        ZigTapTunError.InvalidFileDescriptor,
        errorToCode(error.InvalidFileDescriptor),
    );

    try std.testing.expectEqual(
        ZigTapTunError.PacketTooLarge,
        errorToCode(error.PacketTooLarge),
    );
}
