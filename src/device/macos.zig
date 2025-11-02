//! macOS utun device implementation
//!
//! Implements TUN device support using the utun kernel control interface.
//! utun devices operate at Layer 3 (IP packets only).

const std = @import("std");
const posix = std.posix;
const system = std.posix.system;

// Import C ioctl and related functions
const c = @cImport({
    @cInclude("sys/ioctl.h");
    @cInclude("sys/kern_control.h");
    @cInclude("sys/sys_domain.h");
    @cInclude("sys/socket.h");
});

/// utun control name for kernel control socket
pub const UTUN_CONTROL_NAME = "com.apple.net.utun_control";

/// Socket option names
pub const UTUN_OPT_FLAGS = 1;
pub const UTUN_OPT_IFNAME = 2;

/// Socket families
pub const PF_SYSTEM = 32;
pub const AF_SYSTEM = 32;
pub const AF_SYS_CONTROL = 2;
pub const SYSPROTO_CONTROL = 2;

/// ioctl commands
pub const CTLIOCGINFO: c_ulong = 0xc0644e03;

/// Maximum kernel control name length
pub const MAX_KCTL_NAME = 96;

/// Kernel control info structure
pub const ctl_info = extern struct {
    ctl_id: u32,
    ctl_name: [MAX_KCTL_NAME]u8,
};

/// Socket address for kernel control
pub const sockaddr_ctl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

/// Protocol family constants
pub const AF_INET = 2;
pub const AF_INET6 = 30;

/// macOS utun device
pub const MacOSUtunDevice = struct {
    fd: std.posix.fd_t,
    name: [16]u8,
    name_len: usize,
    unit: u32,
    mtu: u16,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn open(allocator: std.mem.Allocator, unit_hint: ?u32) !Self {
        const fd = try posix.socket(PF_SYSTEM, posix.SOCK.DGRAM, SYSPROTO_CONTROL);
        errdefer posix.close(fd);

        var info = std.mem.zeroes(ctl_info);
        @memcpy(info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);

        // Use C ioctl - it will handle the correct type on macOS
        const result = c.ioctl(fd, c.CTLIOCGINFO, &info);
        if (result != 0) {
            return error.DeviceNotFound;
        }

        var addr = std.mem.zeroes(sockaddr_ctl);
        addr.sc_len = @sizeOf(sockaddr_ctl);
        addr.sc_family = AF_SYSTEM;
        addr.ss_sysaddr = AF_SYS_CONTROL;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = if (unit_hint) |u| u + 1 else 0;

        const addr_ptr: *const posix.sockaddr = @ptrCast(&addr);
        try posix.connect(fd, addr_ptr, @sizeOf(sockaddr_ctl));

        var ifname: [16]u8 = undefined;
        var ifname_len: u32 = ifname.len;

        const getsockopt_result = system.getsockopt(
            fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            &ifname,
            &ifname_len,
        );

        if (getsockopt_result != 0) {
            return error.InvalidConfiguration;
        }

        const name_str = ifname[0..ifname_len];
        var unit: u32 = 0;
        if (std.mem.startsWith(u8, name_str, "utun")) {
            unit = std.fmt.parseInt(u32, name_str[4..], 10) catch 0;
        }

        return Self{
            .fd = fd,
            .name = ifname,
            .name_len = ifname_len,
            .unit = unit,
            .mtu = 1500,
            .allocator = allocator,
        };
    }

    pub fn close(self: *Self) void {
        posix.close(self.fd);
    }

    pub fn getName(self: *const Self) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn getUnit(self: *const Self) u32 {
        return self.unit;
    }

    pub fn read(self: *Self, buffer: []u8) ![]const u8 {
        const bytes_read = try posix.read(self.fd, buffer);
        if (bytes_read == 0) {
            return error.EndOfStream;
        }
        return buffer[0..bytes_read];
    }

    pub fn write(self: *Self, data: []const u8) !void {
        const bytes_written = try posix.write(self.fd, data);
        if (bytes_written != data.len) {
            return error.IncompleteWrite;
        }
    }

    pub fn setNonBlocking(self: *Self, enabled: bool) !void {
        const O_NONBLOCK: u32 = 0x0004; // O_NONBLOCK on macOS
        const flags = try posix.fcntl(self.fd, posix.F.GETFL, 0);
        const new_flags = if (enabled)
            flags | O_NONBLOCK
        else
            flags & ~O_NONBLOCK;
        _ = try posix.fcntl(self.fd, posix.F.SETFL, new_flags);
    }
};

pub fn addProtocolHeader(allocator: std.mem.Allocator, ip_packet: []const u8) ![]u8 {
    if (ip_packet.len == 0) {
        return error.InvalidPacket;
    }

    const version = ip_packet[0] & 0xF0;
    const af: u32 = if (version == 0x40)
        AF_INET
    else if (version == 0x60)
        AF_INET6
    else
        return error.InvalidPacket;

    const packet = try allocator.alloc(u8, 4 + ip_packet.len);
    std.mem.writeInt(u32, packet[0..4], af, .big);
    @memcpy(packet[4..], ip_packet);

    return packet;
}
pub fn stripProtocolHeader(packet: []const u8) ![]const u8 {
    if (packet.len < 4) {
        return error.InvalidPacket;
    }

    const af = std.mem.readInt(u32, packet[0..4], .big);
    if (af != AF_INET and af != AF_INET6) {
        return error.InvalidPacket;
    }

    return packet[4..];
}

test "utun protocol header helpers" {
    const allocator = std.testing.allocator;
    const ipv4_packet = [_]u8{ 0x45, 0x00, 0x00, 0x28 } ++ [_]u8{0} ** 36;

    const with_header = try addProtocolHeader(allocator, &ipv4_packet);
    defer allocator.free(with_header);

    try std.testing.expectEqual(@as(usize, 4 + ipv4_packet.len), with_header.len);
    try std.testing.expectEqual(@as(u32, AF_INET), std.mem.readInt(u32, with_header[0..4], .big));

    const stripped = try stripProtocolHeader(with_header);
    try std.testing.expectEqualSlices(u8, &ipv4_packet, stripped);
}

test "MacOSUtunDevice open and query (requires root)" {
    // Skip in CI or if SKIP_INTEGRATION_TESTS is set
    if (std.posix.getenv("CI") != null or std.posix.getenv("SKIP_INTEGRATION_TESTS") != null) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    std.debug.print("\n=== Integration Test: Opening utun Device ===\n", .{});
    std.debug.print("(This test requires root/sudo privileges)\n\n", .{});

    var device = MacOSUtunDevice.open(allocator, null) catch |err| {
        std.debug.print("❌ Failed to open device: {}\n", .{err});
        std.debug.print("\nThis is expected if not running as root.\n", .{});
        std.debug.print("To run this test: sudo zig test src/platform/macos.zig\n\n", .{});
        // Don't fail the test - just skip it
        return error.SkipZigTest;
    };
    defer device.close();

    const name = device.getName();
    std.debug.print("✅ Device opened: {s}\n", .{name});
    std.debug.print("   Unit: {}\n", .{device.getUnit()});
    std.debug.print("   MTU: {}\n", .{device.mtu});
    std.debug.print("   FD: {}\n\n", .{device.fd});

    // Verify device properties
    try std.testing.expect(std.mem.startsWith(u8, name, "utun"));
    try std.testing.expect(device.fd >= 0);
    try std.testing.expect(device.mtu > 0);

    std.debug.print("🎉 Integration test passed!\n", .{});
    std.debug.print("\nTo configure this interface:\n", .{});
    std.debug.print("  sudo ifconfig {s} 10.0.0.1 10.0.0.2 netmask 255.255.255.0\n", .{name});
    std.debug.print("  ping 10.0.0.2\n\n", .{});
}
