//! Linux TUN/TAP device implementation
//!
//! This module provides a pure Zig implementation of Linux TUN/TAP device management,
//! porting functionality from SoftEther's NativeStack.c (lines 974-987).
//!
//! References:
//! - man 4 tun
//! - /usr/include/linux/if_tun.h
//! - https://www.kernel.org/doc/Documentation/networking/tuntap.txt

const std = @import("std");
const testing = std.testing;
const posix = std.posix;
const linux = std.os.linux;

// Import C functions for ioctl
const c = @cImport({
    @cInclude("sys/ioctl.h");
    @cInclude("net/if.h");
    @cInclude("linux/if_tun.h");
});

// Linux TUN/TAP constants (from linux/if_tun.h)
const TUNSETIFF: u32 = 0x400454ca;
const TUNSETPERSIST: u32 = 0x400454cb;
const TUNSETOWNER: u32 = 0x400454cc;
const TUNSETGROUP: u32 = 0x400454ce;

// Interface flags (from linux/if.h)
const IFF_TUN: u16 = 0x0001;
const IFF_TAP: u16 = 0x0002;
const IFF_NO_PI: u16 = 0x1000;
const IFF_UP: u16 = 0x1;
const IFF_RUNNING: u16 = 0x40;

// ioctl commands (from sys/ioctl.h)
const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCSIFADDR: u32 = 0x8916;
const SIOCSIFNETMASK: u32 = 0x891c;
const SIOCGIFMTU: u32 = 0x8921;
const SIOCSIFMTU: u32 = 0x8922;

// Socket address families
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// Standard file flags
const O_RDWR: u32 = 0x0002;
const O_NONBLOCK: u32 = 0x0800;

/// Linux TUN/TAP device interface modes
pub const DeviceMode = enum {
    /// Layer 3 (IP) tunnel device
    tun,
    /// Layer 2 (Ethernet) tunnel device
    tap,
};

/// Linux TUN/TAP device configuration
pub const LinuxTunConfig = struct {
    /// Device mode (TUN or TAP)
    mode: DeviceMode = .tun,

    /// Device name (e.g., "tun0", "tap0"). If null, kernel auto-assigns.
    name: ?[]const u8 = null,

    /// Enable packet information header (PI). Usually false for VPN.
    packet_info: bool = false,

    /// Make device persistent (survives process exit)
    persistent: bool = false,

    /// Owner UID (null = current user)
    owner: ?u32 = null,

    /// Group GID (null = current group)
    group: ?u32 = null,

    /// Non-blocking I/O
    non_blocking: bool = true,
};

/// Linux TUN/TAP device handle
pub const LinuxTunDevice = struct {
    /// File descriptor for /dev/net/tun
    fd: posix.fd_t,

    /// Actual device name (e.g., "tun0")
    name: [16]u8,

    /// Device mode (TUN or TAP)
    mode: DeviceMode,

    /// Allocator for operations
    allocator: std.mem.Allocator,

    /// MTU (Maximum Transmission Unit)
    mtu: u32 = 1500,

    /// Whether non-blocking I/O is enabled
    non_blocking: bool,

    /// Open a Linux TUN/TAP device
    ///
    /// Example:
    /// ```zig
    /// var device = try LinuxTunDevice.open(allocator, .{
    ///     .mode = .tun,
    ///     .name = "tun0",
    /// });
    /// defer device.close();
    /// ```
    pub fn open(allocator: std.mem.Allocator, config: LinuxTunConfig) !*LinuxTunDevice {
        // Open /dev/net/tun device
        const flags = if (config.non_blocking) O_RDWR | O_NONBLOCK else O_RDWR;
        const fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, flags);
        errdefer posix.close(fd);

        // Prepare interface request structure
        var ifr = std.mem.zeroes(c.ifreq);

        // Set device name if provided
        if (config.name) |name| {
            if (name.len >= c.IFNAMSIZ) {
                return error.NameTooLong;
            }
            @memcpy(ifr.ifr_name[0..name.len], name);
        }

        // Set device flags
        var flags_u16: u16 = if (config.mode == .tun) IFF_TUN else IFF_TAP;
        if (!config.packet_info) {
            flags_u16 |= IFF_NO_PI;
        }
        ifr.ifr_ifru.ifru_flags = @bitCast(flags_u16);

        // Create the TUN/TAP device
        if (c.ioctl(fd, TUNSETIFF, &ifr) < 0) {
            return error.DeviceCreationFailed;
        }

        // Get actual device name (kernel may have assigned one)
        const device_name_len = std.mem.indexOfScalar(u8, &ifr.ifr_name, 0) orelse c.IFNAMSIZ;
        var device_name: [16]u8 = undefined;
        @memset(&device_name, 0);
        @memcpy(device_name[0..@min(device_name_len, 16)], ifr.ifr_name[0..device_name_len]);

        // Set persistent mode if requested
        if (config.persistent) {
            const persist: c_int = 1;
            if (c.ioctl(fd, TUNSETPERSIST, &persist) < 0) {
                return error.PersistFailed;
            }
        }

        // Set owner if specified
        if (config.owner) |owner| {
            if (c.ioctl(fd, TUNSETOWNER, owner) < 0) {
                return error.SetOwnerFailed;
            }
        }

        // Set group if specified
        if (config.group) |group| {
            if (c.ioctl(fd, TUNSETGROUP, group) < 0) {
                return error.SetGroupFailed;
            }
        }

        // Allocate and return device
        const device = try allocator.create(LinuxTunDevice);
        device.* = LinuxTunDevice{
            .fd = fd,
            .name = device_name,
            .mode = config.mode,
            .allocator = allocator,
            .mtu = 1500,
            .non_blocking = config.non_blocking,
        };

        return device;
    }

    /// Close the TUN/TAP device
    pub fn close(self: *LinuxTunDevice) void {
        posix.close(self.fd);
        self.allocator.destroy(self);
    }

    /// Read a packet from the TUN/TAP device
    ///
    /// Returns the number of bytes read. The buffer should be at least MTU size.
    ///
    /// Example:
    /// ```zig
    /// var buffer: [1500]u8 = undefined;
    /// const size = try device.read(&buffer);
    /// const packet = buffer[0..size];
    /// ```
    pub fn read(self: *LinuxTunDevice, buffer: []u8) !usize {
        while (true) {
            const result = linux.read(self.fd, buffer.ptr, buffer.len);

            if (result < 0) {
                const err = linux.getErrno(result);
                switch (err) {
                    .INTR => continue, // Interrupted, retry
                    .AGAIN => {
                        if (self.non_blocking) {
                            return error.WouldBlock;
                        }
                        continue;
                    },
                    .BADF => return error.BadFileDescriptor,
                    .INVAL => return error.InvalidArgument,
                    .IO => return error.InputOutput,
                    else => return error.UnexpectedError,
                }
            }

            return @intCast(result);
        }
    }

    /// Write a packet to the TUN/TAP device
    ///
    /// Example:
    /// ```zig
    /// const packet = [_]u8{ /* IP packet bytes */ };
    /// try device.write(&packet);
    /// ```
    pub fn write(self: *LinuxTunDevice, packet: []const u8) !void {
        if (packet.len > self.mtu) {
            return error.PacketTooLarge;
        }

        var total_written: usize = 0;
        while (total_written < packet.len) {
            const result = linux.write(self.fd, packet.ptr + total_written, packet.len - total_written);

            if (result < 0) {
                const err = linux.getErrno(result);
                switch (err) {
                    .INTR => continue, // Interrupted, retry
                    .AGAIN => {
                        if (self.non_blocking) {
                            return error.WouldBlock;
                        }
                        continue;
                    },
                    .BADF => return error.BadFileDescriptor,
                    .INVAL => return error.InvalidArgument,
                    .IO => return error.InputOutput,
                    .NOSPC => return error.NoSpaceLeft,
                    else => return error.UnexpectedError,
                }
            }

            total_written += @intCast(result);
        }
    }

    /// Get the device name (e.g., "tun0")
    pub fn getName(self: *const LinuxTunDevice) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        return self.name[0..len];
    }

    /// Get the device MTU
    pub fn getMtu(self: *const LinuxTunDevice) u32 {
        return self.mtu;
    }

    /// Set the device MTU
    pub fn setMtu(self: *LinuxTunDevice, mtu: u32) !void {
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        defer posix.close(sock);

        var ifr = std.mem.zeroes(c.ifreq);
        const name_len = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        @memcpy(ifr.ifr_name[0..name_len], self.name[0..name_len]);
        ifr.ifr_ifru.ifru_mtu = @intCast(mtu);

        if (c.ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
            return error.SetMtuFailed;
        }

        self.mtu = mtu;
    }

    /// Configure IP address and netmask
    ///
    /// Example:
    /// ```zig
    /// try device.setIpAddress("10.0.0.1", "255.255.255.0");
    /// ```
    pub fn setIpAddress(self: *LinuxTunDevice, ip: []const u8, netmask: []const u8) !void {
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        defer posix.close(sock);

        var ifr = std.mem.zeroes(c.ifreq);
        const name_len = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        @memcpy(ifr.ifr_name[0..name_len], self.name[0..name_len]);

        // Parse and set IP address
        const ip_addr = try std.net.Address.parseIp4(ip, 0);
        const sockaddr_in = @as(*align(1) const std.posix.sockaddr.in, @ptrCast(&ip_addr.any));
        @memcpy(
            @as([*]u8, @ptrCast(&ifr.ifr_ifru.ifru_addr))[0..@sizeOf(std.posix.sockaddr.in)],
            std.mem.asBytes(sockaddr_in),
        );

        if (c.ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
            return error.SetIpAddressFailed;
        }

        // Parse and set netmask
        const mask_addr = try std.net.Address.parseIp4(netmask, 0);
        const sockaddr_mask = @as(*align(1) const std.posix.sockaddr.in, @ptrCast(&mask_addr.any));
        @memcpy(
            @as([*]u8, @ptrCast(&ifr.ifr_ifru.ifru_netmask))[0..@sizeOf(std.posix.sockaddr.in)],
            std.mem.asBytes(sockaddr_mask),
        );

        if (c.ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
            return error.SetNetmaskFailed;
        }
    }

    /// Bring the interface up
    pub fn up(self: *LinuxTunDevice) !void {
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        defer posix.close(sock);

        var ifr = std.mem.zeroes(c.ifreq);
        const name_len = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        @memcpy(ifr.ifr_name[0..name_len], self.name[0..name_len]);

        // Get current flags
        if (c.ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            return error.GetFlagsFailed;
        }

        // Set IFF_UP and IFF_RUNNING flags
        const current_flags: u16 = @bitCast(ifr.ifr_ifru.ifru_flags);
        ifr.ifr_ifru.ifru_flags = @bitCast(current_flags | IFF_UP | IFF_RUNNING);

        if (c.ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
            return error.SetFlagsFailed;
        }
    }

    /// Bring the interface down
    pub fn down(self: *LinuxTunDevice) !void {
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        defer posix.close(sock);

        var ifr = std.mem.zeroes(c.ifreq);
        const name_len = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        @memcpy(ifr.ifr_name[0..name_len], self.name[0..name_len]);

        // Get current flags
        if (c.ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            return error.GetFlagsFailed;
        }

        // Clear IFF_UP flag
        const current_flags: u16 = @bitCast(ifr.ifr_ifru.ifru_flags);
        ifr.ifr_ifru.ifru_flags = @bitCast(current_flags & ~IFF_UP);

        if (c.ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
            return error.SetFlagsFailed;
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "LinuxTunDevice basic structure" {
    // Basic compile-time checks
    const config = LinuxTunConfig{
        .mode = .tun,
        .name = "test",
    };

    try testing.expectEqual(DeviceMode.tun, config.mode);
    try testing.expectEqualStrings("test", config.name.?);
}

test "LinuxTunDevice config defaults" {
    const config = LinuxTunConfig{};

    try testing.expectEqual(DeviceMode.tun, config.mode);
    try testing.expectEqual(@as(?[]const u8, null), config.name);
    try testing.expectEqual(false, config.packet_info);
    try testing.expectEqual(false, config.persistent);
    try testing.expectEqual(@as(?u32, null), config.owner);
    try testing.expectEqual(@as(?u32, null), config.group);
    try testing.expectEqual(true, config.non_blocking);
}

test "LinuxTunDevice TUN mode flags" {
    const config = LinuxTunConfig{ .mode = .tun, .packet_info = false };
    try testing.expectEqual(DeviceMode.tun, config.mode);
}

test "LinuxTunDevice TAP mode flags" {
    const config = LinuxTunConfig{ .mode = .tap, .packet_info = false };
    try testing.expectEqual(DeviceMode.tap, config.mode);
}

// Integration tests - require root privileges and Linux OS
// These are skipped by default but can be run with:
// sudo zig test src/platform/linux.zig

test "LinuxTunDevice open/close TUN mode" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (std.posix.getuid() != 0) return error.SkipZigTest; // Requires root

    const allocator = testing.allocator;

    var device = try LinuxTunDevice.open(allocator, .{
        .mode = .tun,
        .non_blocking = true,
    });
    defer device.close();

    try testing.expect(device.getName().len > 0);
    try testing.expectEqual(@as(u32, 1500), device.getMtu());
    try testing.expectEqual(DeviceMode.tun, device.mode);
    try testing.expectEqual(true, device.non_blocking);
}

test "LinuxTunDevice open/close TAP mode" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (std.posix.getuid() != 0) return error.SkipZigTest; // Requires root

    const allocator = testing.allocator;

    var device = try LinuxTunDevice.open(allocator, .{
        .mode = .tap,
        .non_blocking = true,
    });
    defer device.close();

    try testing.expect(device.getName().len > 0);
    try testing.expectEqual(DeviceMode.tap, device.mode);
}

test "LinuxTunDevice named device" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (std.posix.getuid() != 0) return error.SkipZigTest; // Requires root

    const allocator = testing.allocator;

    var device = try LinuxTunDevice.open(allocator, .{
        .mode = .tun,
        .name = "testun99",
    });
    defer device.close();

    try testing.expectEqualStrings("testun99", device.getName());
}

test "LinuxTunDevice MTU get/set" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (std.posix.getuid() != 0) return error.SkipZigTest; // Requires root

    const allocator = testing.allocator;

    var device = try LinuxTunDevice.open(allocator, .{
        .mode = .tun,
    });
    defer device.close();

    // Default MTU
    try testing.expectEqual(@as(u32, 1500), device.getMtu());

    // Set custom MTU
    try device.setMtu(1400);
    try testing.expectEqual(@as(u32, 1400), device.getMtu());
}

test "LinuxTunDevice IP configuration" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (std.posix.getuid() != 0) return error.SkipZigTest; // Requires root

    const allocator = testing.allocator;

    var device = try LinuxTunDevice.open(allocator, .{
        .mode = .tun,
    });
    defer device.close();

    // Set IP address and netmask
    try device.setIpAddress("10.99.0.1", "255.255.255.0");

    // Bring interface up
    try device.up();

    // Bring interface down
    try device.down();
}

test "LinuxTunDevice interface up/down" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (std.posix.getuid() != 0) return error.SkipZigTest; // Requires root

    const allocator = testing.allocator;

    var device = try LinuxTunDevice.open(allocator, .{
        .mode = .tun,
    });
    defer device.close();

    try device.setIpAddress("10.99.0.1", "255.255.255.0");
    try device.up();
    try device.down();
}

test "LinuxTunDevice read/write simulation" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (std.posix.getuid() != 0) return error.SkipZigTest; // Requires root

    const allocator = testing.allocator;

    var device = try LinuxTunDevice.open(allocator, .{
        .mode = .tun,
        .non_blocking = true,
    });
    defer device.close();

    // Configure interface
    try device.setIpAddress("10.99.0.1", "255.255.255.0");
    try device.up();

    // Try reading (should get WouldBlock since nothing is queued)
    var buffer: [1500]u8 = undefined;
    const result = device.read(&buffer);
    try testing.expectError(error.WouldBlock, result);
}

test "LinuxTunDevice persistent mode" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (std.posix.getuid() != 0) return error.SkipZigTest; // Requires root

    const allocator = testing.allocator;

    var device = try LinuxTunDevice.open(allocator, .{
        .mode = .tun,
        .persistent = true,
    });
    defer device.close();

    try testing.expect(device.getName().len > 0);
}

test "LinuxTunDevice blocking mode" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (std.posix.getuid() != 0) return error.SkipZigTest; // Requires root

    const allocator = testing.allocator;

    var device = try LinuxTunDevice.open(allocator, .{
        .mode = .tun,
        .non_blocking = false,
    });
    defer device.close();

    try testing.expectEqual(false, device.non_blocking);
}
