/// Network Interface Configuration
///
/// Cross-platform interface for configuring network interface properties:
/// - IP address and netmask
/// - Interface status (up/down)
/// - MTU (Maximum Transmission Unit)
/// - Interface information queries
const std = @import("std");
const builtin = @import("builtin");

pub const Ipv4Address = [4]u8;

/// Interface configuration
pub const InterfaceConfig = struct {
    name: []const u8,
    ip_address: ?Ipv4Address = null,
    netmask: ?Ipv4Address = null,
    mtu: ?u16 = null,
    is_up: bool = false,
};

/// Platform-specific interface configurator
pub const InterfaceConfigurator = switch (builtin.os.tag) {
    .macos => MacOSConfigurator,
    .linux => LinuxConfigurator,
    .windows => WindowsConfigurator,
    else => UnsupportedConfigurator,
};

/// macOS Interface Configuration (using ifconfig)
const MacOSConfigurator = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{ .allocator = allocator };
        return self;
    }

    /// Set IP address and netmask
    pub fn setIpAddress(self: *Self, interface: []const u8, ip: Ipv4Address, netmask: Ipv4Address) !void {
        var ip_buf: [16]u8 = undefined;
        const ip_str = try std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });

        var mask_buf: [16]u8 = undefined;
        const mask_str = try std.fmt.bufPrint(&mask_buf, "{d}.{d}.{d}.{d}", .{ netmask[0], netmask[1], netmask[2], netmask[3] });

        std.log.info("Setting {s} IP: {s} netmask {s}", .{ interface, ip_str, mask_str });

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "ifconfig", interface, ip_str, "netmask", mask_str },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("Failed to set IP: {s}", .{result.stderr});
            return error.ConfigurationFailed;
        }

        std.log.info("✅ Interface {s} configured", .{interface});
    }

    /// Set interface status (up/down)
    pub fn setStatus(self: *Self, interface: []const u8, up: bool) !void {
        const status = if (up) "up" else "down";
        std.log.info("Setting {s} status: {s}", .{ interface, status });

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "ifconfig", interface, status },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("Failed to set status: {s}", .{result.stderr});
            return error.ConfigurationFailed;
        }

        std.log.info("✅ Interface {s} is now {s}", .{ interface, status });
    }

    /// Set MTU
    pub fn setMtu(self: *Self, interface: []const u8, mtu: u16) !void {
        var mtu_buf: [8]u8 = undefined;
        const mtu_str = try std.fmt.bufPrint(&mtu_buf, "{d}", .{mtu});

        std.log.info("Setting {s} MTU: {s}", .{ interface, mtu_str });

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "ifconfig", interface, "mtu", mtu_str },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("Failed to set MTU: {s}", .{result.stderr});
            return error.ConfigurationFailed;
        }

        std.log.info("✅ Interface {s} MTU set to {d}", .{ interface, mtu });
    }

    /// Get interface information
    pub fn getInfo(self: *Self, interface: []const u8) !InterfaceConfig {
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "ifconfig", interface },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            return error.InterfaceNotFound;
        }

        // Parse output (simplified)
        const config = InterfaceConfig{
            .name = interface,
            .is_up = std.mem.indexOf(u8, result.stdout, "UP") != null,
        };

        return config;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }
};

/// Linux Interface Configuration (using ip command)
const LinuxConfigurator = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{ .allocator = allocator };
        return self;
    }

    /// Set IP address and netmask
    pub fn setIpAddress(self: *Self, interface: []const u8, ip: Ipv4Address, netmask: Ipv4Address) !void {
        // Convert netmask to CIDR prefix length
        const prefix_len = netmaskToCidr(netmask);

        var ip_buf: [16]u8 = undefined;
        const ip_str = try std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });

        var cidr_buf: [20]u8 = undefined;
        const cidr_str = try std.fmt.bufPrint(&cidr_buf, "{s}/{d}", .{ ip_str, prefix_len });

        std.log.info("Setting {s} IP: {s}", .{ interface, cidr_str });

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "ip", "addr", "add", cidr_str, "dev", interface },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("Failed to set IP: {s}", .{result.stderr});
            return error.ConfigurationFailed;
        }

        std.log.info("✅ Interface {s} configured", .{interface});
    }

    /// Set interface status (up/down)
    pub fn setStatus(self: *Self, interface: []const u8, up: bool) !void {
        const status = if (up) "up" else "down";
        std.log.info("Setting {s} status: {s}", .{ interface, status });

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "ip", "link", "set", interface, status },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("Failed to set status: {s}", .{result.stderr});
            return error.ConfigurationFailed;
        }

        std.log.info("✅ Interface {s} is now {s}", .{ interface, status });
    }

    /// Set MTU
    pub fn setMtu(self: *Self, interface: []const u8, mtu: u16) !void {
        var mtu_buf: [8]u8 = undefined;
        const mtu_str = try std.fmt.bufPrint(&mtu_buf, "{d}", .{mtu});

        std.log.info("Setting {s} MTU: {s}", .{ interface, mtu_str });

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "ip", "link", "set", interface, "mtu", mtu_str },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("Failed to set MTU: {s}", .{result.stderr});
            return error.ConfigurationFailed;
        }

        std.log.info("✅ Interface {s} MTU set to {d}", .{ interface, mtu });
    }

    /// Get interface information
    pub fn getInfo(self: *Self, interface: []const u8) !InterfaceConfig {
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "ip", "addr", "show", interface },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            return error.InterfaceNotFound;
        }

        const config = InterfaceConfig{
            .name = interface,
            .is_up = std.mem.indexOf(u8, result.stdout, "UP") != null,
        };

        return config;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }
};

/// Windows Interface Configuration (using netsh)
const WindowsConfigurator = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{ .allocator = allocator };
        return self;
    }

    /// Set IP address and netmask
    pub fn setIpAddress(self: *Self, interface: []const u8, ip: Ipv4Address, netmask: Ipv4Address) !void {
        var ip_buf: [16]u8 = undefined;
        const ip_str = try std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });

        var mask_buf: [16]u8 = undefined;
        const mask_str = try std.fmt.bufPrint(&mask_buf, "{d}.{d}.{d}.{d}", .{ netmask[0], netmask[1], netmask[2], netmask[3] });

        std.log.info("Setting {s} IP: {s} netmask {s}", .{ interface, ip_str, mask_str });

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "netsh", "interface", "ip", "set", "address", interface, "static", ip_str, mask_str },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("Failed to set IP: {s}", .{result.stderr});
            return error.ConfigurationFailed;
        }

        std.log.info("✅ Interface {s} configured", .{interface});
    }

    /// Set interface status (up/down)
    pub fn setStatus(self: *Self, interface: []const u8, up: bool) !void {
        const status = if (up) "enable" else "disable";
        std.log.info("Setting {s} status: {s}", .{ interface, status });

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "netsh", "interface", "set", "interface", interface, status },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("Failed to set status: {s}", .{result.stderr});
            return error.ConfigurationFailed;
        }

        std.log.info("✅ Interface {s} is now {s}", .{ interface, status });
    }

    /// Set MTU
    pub fn setMtu(self: *Self, interface: []const u8, mtu: u16) !void {
        var mtu_buf: [8]u8 = undefined;
        const mtu_str = try std.fmt.bufPrint(&mtu_buf, "{d}", .{mtu});

        std.log.info("Setting {s} MTU: {s}", .{ interface, mtu_str });

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "netsh", "interface", "ipv4", "set", "subinterface", interface, "mtu=" ++ mtu_str, "store=persistent" },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("Failed to set MTU: {s}", .{result.stderr});
            return error.ConfigurationFailed;
        }

        std.log.info("✅ Interface {s} MTU set to {d}", .{ interface, mtu });
    }

    /// Get interface information
    pub fn getInfo(self: *Self, interface: []const u8) !InterfaceConfig {
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "netsh", "interface", "ip", "show", "config", interface },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            return error.InterfaceNotFound;
        }

        const config = InterfaceConfig{
            .name = interface,
            .is_up = true, // Simplified
        };

        return config;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }
};

/// Unsupported platform stub
const UnsupportedConfigurator = struct {
    pub fn init(_: std.mem.Allocator) !*UnsupportedConfigurator {
        return error.UnsupportedPlatform;
    }
};

/// Convert netmask to CIDR prefix length
fn netmaskToCidr(netmask: Ipv4Address) u8 {
    var prefix: u8 = 0;
    for (netmask) |octet| {
        var bits = octet;
        while (bits != 0) {
            prefix += bits & 1;
            bits >>= 1;
        }
    }
    return prefix;
}

test "netmask to CIDR conversion" {
    try std.testing.expectEqual(@as(u8, 24), netmaskToCidr([_]u8{ 255, 255, 255, 0 }));
    try std.testing.expectEqual(@as(u8, 16), netmaskToCidr([_]u8{ 255, 255, 0, 0 }));
    try std.testing.expectEqual(@as(u8, 8), netmaskToCidr([_]u8{ 255, 0, 0, 0 }));
    try std.testing.expectEqual(@as(u8, 32), netmaskToCidr([_]u8{ 255, 255, 255, 255 }));
}
