//! iOS Platform Support
//!
//! iOS uses Network Extension framework (NEPacketTunnelProvider) for VPN functionality.
//! Unlike macOS/Linux with direct TUN device access, iOS provides a packet-based API
//! through NEPacketFlow with async callbacks.
//!
//! Architecture:
//! - Swift/Objective-C code creates NEPacketTunnelProvider
//! - Provider calls into Zig code via C bridge
//! - Zig code processes packets with L2L3Translator
//! - Packets sent/received through NEPacketFlow callbacks
//!
//! Memory Management:
//! - Network Extensions have strict memory limits (~50MB typical)
//! - Use packet pools and ring buffers for efficiency
//! - Minimize allocations in hot paths

const std = @import("std");
const builtin = @import("builtin");

/// iOS VPN device using Network Extension framework
pub const iOSVpnDevice = struct {
    allocator: std.mem.Allocator,
    fd: i32, // Not used on iOS, kept for API compatibility
    name: []const u8,
    mtu: u32,

    // Packet queues for async I/O
    read_queue: PacketQueue,
    write_queue: PacketQueue,

    // Configuration
    ipv4_address: ?u32,
    ipv4_netmask: ?u32,
    ipv6_address: ?[16]u8,
    ipv6_prefix_length: ?u8,

    // State
    is_active: bool,

    const Self = @This();

    /// Open iOS VPN device
    /// Note: On iOS, the actual device is managed by NEPacketTunnelProvider
    /// This creates the internal state and queues
    pub fn open(allocator: std.mem.Allocator, name: ?[]const u8) !Self {
        const device_name = name orelse "iOS-VPN";
        const owned_name = try allocator.dupe(u8, device_name);
        errdefer allocator.free(owned_name);

        return Self{
            .allocator = allocator,
            .fd = -1, // iOS doesn't use file descriptors
            .name = owned_name,
            .mtu = 1500, // Default MTU, can be configured
            .read_queue = try PacketQueue.init(allocator, 256),
            .write_queue = try PacketQueue.init(allocator, 256),
            .ipv4_address = null,
            .ipv4_netmask = null,
            .ipv6_address = null,
            .ipv6_prefix_length = null,
            .is_active = false,
        };
    }

    /// Close device and free resources
    pub fn close(self: *Self) void {
        self.is_active = false;
        self.read_queue.deinit();
        self.write_queue.deinit();
        self.allocator.free(self.name);
    }

    /// Read packet from device
    /// On iOS, this reads from the packet queue populated by Swift callbacks
    pub fn read(self: *Self, buffer: []u8) !usize {
        if (!self.is_active) return error.DeviceNotActive;

        // Try to dequeue a packet
        if (try self.read_queue.dequeue()) |packet| {
            defer self.allocator.free(packet);

            if (packet.len > buffer.len) {
                return error.BufferTooSmall;
            }

            @memcpy(buffer[0..packet.len], packet);
            return packet.len;
        }

        // No packets available
        return error.WouldBlock;
    }

    /// Write packet to device
    /// On iOS, this enqueues packet for Swift to send via NEPacketFlow
    pub fn write(self: *Self, data: []const u8) !void {
        if (!self.is_active) return error.DeviceNotActive;

        if (data.len > self.mtu) {
            return error.PacketTooLarge;
        }

        // Make a copy and enqueue
        const packet_copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(packet_copy);

        try self.write_queue.enqueue(packet_copy);
    }

    /// Set IPv4 address and netmask
    pub fn setIpv4Address(self: *Self, address: u32, netmask: u32) !void {
        self.ipv4_address = address;
        self.ipv4_netmask = netmask;
    }

    /// Set IPv6 address and prefix length
    pub fn setIpv6Address(self: *Self, address: [16]u8, prefix_len: u8) !void {
        self.ipv6_address = address;
        self.ipv6_prefix_length = prefix_len;
    }

    /// Set MTU
    pub fn setMtu(self: *Self, mtu: u32) !void {
        if (mtu < 68 or mtu > 65535) {
            return error.InvalidMtu;
        }
        self.mtu = mtu;
    }

    /// Get device name
    pub fn getName(self: *const Self) []const u8 {
        return self.name;
    }

    /// Get MTU
    pub fn getMtu(self: *const Self) u32 {
        return self.mtu;
    }

    /// Activate device (called when NEPacketTunnelProvider starts)
    pub fn activate(self: *Self) void {
        self.is_active = true;
    }

    /// Deactivate device (called when NEPacketTunnelProvider stops)
    pub fn deactivate(self: *Self) void {
        self.is_active = false;
    }
};

/// Thread-safe packet queue for async I/O
const PacketQueue = struct {
    allocator: std.mem.Allocator,
    packets: std.ArrayList([]const u8),
    mutex: std.Thread.Mutex,
    capacity: usize,

    const Self = @This();

    fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
        return Self{
            .allocator = allocator,
            .packets = std.ArrayList([]const u8).init(allocator),
            .mutex = .{},
            .capacity = capacity,
        };
    }

    fn deinit(self: *Self) void {
        // Free all queued packets
        for (self.packets.items) |packet| {
            self.allocator.free(packet);
        }
        self.packets.deinit();
    }

    fn enqueue(self: *Self, packet: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.packets.items.len >= self.capacity) {
            return error.QueueFull;
        }

        try self.packets.append(packet);
    }

    fn dequeue(self: *Self) !?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.packets.items.len == 0) {
            return null;
        }

        return self.packets.orderedRemove(0);
    }

    fn count(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.packets.items.len;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// C API Exports for Swift Bridge
// ═══════════════════════════════════════════════════════════════════════════

/// Opaque handle type for Swift
pub const ZigTapTunHandle = *anyopaque;

/// Error codes for C API
pub const ZigTapTunError = enum(c_int) {
    Success = 0,
    OutOfMemory = -1,
    InvalidParameter = -2,
    DeviceNotActive = -3,
    BufferTooSmall = -4,
    PacketTooLarge = -5,
    QueueFull = -6,
    WouldBlock = -7,
    Unknown = -99,
};

/// Convert Zig error to C error code
fn errorToCode(err: anyerror) ZigTapTunError {
    return switch (err) {
        error.OutOfMemory => .OutOfMemory,
        error.DeviceNotActive => .DeviceNotActive,
        error.BufferTooSmall => .BufferTooSmall,
        error.PacketTooLarge => .PacketTooLarge,
        error.QueueFull => .QueueFull,
        error.WouldBlock => .WouldBlock,
        else => .Unknown,
    };
}

/// Create iOS VPN device (called from Swift)
export fn zig_taptun_ios_create(name: ?[*:0]const u8) ?ZigTapTunHandle {
    const allocator = std.heap.c_allocator;

    const device_name = if (name) |n|
        std.mem.span(n)
    else
        null;

    const device = iOSVpnDevice.open(allocator, device_name) catch return null;

    const device_ptr = allocator.create(iOSVpnDevice) catch return null;
    device_ptr.* = device;

    return @ptrCast(device_ptr);
}

/// Destroy iOS VPN device (called from Swift)
export fn zig_taptun_ios_destroy(handle: ZigTapTunHandle) void {
    const device: *iOSVpnDevice = @ptrCast(@alignCast(handle));
    const allocator = device.allocator;
    device.close();
    allocator.destroy(device);
}

/// Activate device (called when VPN starts)
export fn zig_taptun_ios_activate(handle: ZigTapTunHandle) void {
    const device: *iOSVpnDevice = @ptrCast(@alignCast(handle));
    device.activate();
}

/// Deactivate device (called when VPN stops)
export fn zig_taptun_ios_deactivate(handle: ZigTapTunHandle) void {
    const device: *iOSVpnDevice = @ptrCast(@alignCast(handle));
    device.deactivate();
}

/// Enqueue received packet from NEPacketFlow (called from Swift)
/// Swift provides the packet data, we queue it for processing
export fn zig_taptun_ios_enqueue_read(
    handle: ZigTapTunHandle,
    data: [*]const u8,
    length: usize,
) ZigTapTunError {
    const device: *iOSVpnDevice = @ptrCast(@alignCast(handle));

    const packet = device.allocator.dupe(u8, data[0..length]) catch {
        return .OutOfMemory;
    };

    device.read_queue.enqueue(packet) catch |err| {
        device.allocator.free(packet);
        return errorToCode(err);
    };

    return .Success;
}

/// Dequeue packet to send via NEPacketFlow (called from Swift)
/// Swift calls this periodically to get packets to send
export fn zig_taptun_ios_dequeue_write(
    handle: ZigTapTunHandle,
    buffer: [*]u8,
    buffer_size: usize,
    out_length: *usize,
) ZigTapTunError {
    const device: *iOSVpnDevice = @ptrCast(@alignCast(handle));

    const packet = device.write_queue.dequeue() catch |err| {
        return errorToCode(err);
    };

    if (packet) |pkt| {
        defer device.allocator.free(pkt);

        if (pkt.len > buffer_size) {
            return .BufferTooSmall;
        }

        @memcpy(buffer[0..pkt.len], pkt);
        out_length.* = pkt.len;
        return .Success;
    }

    return .WouldBlock;
}

/// Get number of packets pending to be sent
export fn zig_taptun_ios_pending_write_count(handle: ZigTapTunHandle) usize {
    const device: *iOSVpnDevice = @ptrCast(@alignCast(handle));
    return device.write_queue.count();
}

/// Set MTU
export fn zig_taptun_ios_set_mtu(handle: ZigTapTunHandle, mtu: u32) ZigTapTunError {
    const device: *iOSVpnDevice = @ptrCast(@alignCast(handle));
    device.setMtu(mtu) catch |err| {
        return errorToCode(err);
    };
    return .Success;
}

/// Set IPv4 address (network byte order)
export fn zig_taptun_ios_set_ipv4(
    handle: ZigTapTunHandle,
    address: u32,
    netmask: u32,
) ZigTapTunError {
    const device: *iOSVpnDevice = @ptrCast(@alignCast(handle));
    device.setIpv4Address(address, netmask) catch |err| {
        return errorToCode(err);
    };
    return .Success;
}

/// Set IPv6 address
export fn zig_taptun_ios_set_ipv6(
    handle: ZigTapTunHandle,
    address: [*]const u8,
    prefix_len: u8,
) ZigTapTunError {
    const device: *iOSVpnDevice = @ptrCast(@alignCast(handle));
    var addr: [16]u8 = undefined;
    @memcpy(&addr, address[0..16]);
    device.setIpv6Address(addr, prefix_len) catch |err| {
        return errorToCode(err);
    };
    return .Success;
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "iOS device creation" {
    const allocator = std.testing.allocator;

    var device = try iOSVpnDevice.open(allocator, "test-vpn");
    defer device.close();

    try std.testing.expectEqualStrings("test-vpn", device.getName());
    try std.testing.expectEqual(@as(u32, 1500), device.getMtu());
    try std.testing.expectEqual(false, device.is_active);
}

test "iOS device activation" {
    const allocator = std.testing.allocator;

    var device = try iOSVpnDevice.open(allocator, null);
    defer device.close();

    try std.testing.expectEqual(false, device.is_active);

    device.activate();
    try std.testing.expectEqual(true, device.is_active);

    device.deactivate();
    try std.testing.expectEqual(false, device.is_active);
}

test "iOS packet queue" {
    const allocator = std.testing.allocator;

    var queue = try PacketQueue.init(allocator, 10);
    defer queue.deinit();

    const test_packet = "Hello, iOS!";
    const packet_copy = try allocator.dupe(u8, test_packet);
    try queue.enqueue(packet_copy);

    try std.testing.expectEqual(@as(usize, 1), queue.count());

    const dequeued = (try queue.dequeue()).?;
    defer allocator.free(dequeued);

    try std.testing.expectEqualStrings(test_packet, dequeued);
    try std.testing.expectEqual(@as(usize, 0), queue.count());
}

test "iOS C API" {
    // Create device via C API
    const handle = zig_taptun_ios_create("test-vpn-c");
    try std.testing.expect(handle != null);
    defer zig_taptun_ios_destroy(handle.?);

    // Activate
    zig_taptun_ios_activate(handle.?);

    // Enqueue packet for reading
    const test_data = "Test packet data";
    const result = zig_taptun_ios_enqueue_read(
        handle.?,
        test_data.ptr,
        test_data.len,
    );
    try std.testing.expectEqual(ZigTapTunError.Success, result);

    // Deactivate
    zig_taptun_ios_deactivate(handle.?);
}
