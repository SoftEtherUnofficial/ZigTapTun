//! ZigTapTun - Cross-Platform TAP/TUN Library
//!
//! Platform-specific TUN/TAP device abstraction and routing management.
//! ONLY handles L3 (IP) device I/O and system routing - no protocol translation!
//!
//! Features:
//! - Platform-specific device I/O (macOS utun, Linux /dev/tun, Windows Wintun)
//! - Route management (save/restore default gateway, add host routes)
//! - Cross-platform device abstraction
//!
//! NOT included (moved to parent SoftEtherClient/src/protocol/):
//! - L2↔L3 translation (translator.zig)
//! - ARP handling (arp.zig)
//! - DHCP client (dhcp_client.zig)
//! - DNS protocol (dns.zig)

const std = @import("std");
const builtin = @import("builtin");

// Platform-specific device implementations
pub const platform = switch (builtin.os.tag) {
    .macos, .ios => @import("device/macos.zig"),
    .linux => @import("device/linux.zig"),
    .windows => @import("device/windows.zig"),
    else => @compileError("Platform not yet supported. Available: macOS, Linux, Windows"),
};

/// Platform-specific TUN device (low-level, for advanced users)
pub const TunDevice = switch (builtin.os.tag) {
    .macos, .ios => platform.MacOSUtunDevice,
    .linux => platform.LinuxTunDevice,
    .windows => platform.WindowsTapDevice,
    else => @compileError("Platform not yet supported"),
};

// Route management (platform-agnostic interface)
pub const RouteManager = @import("routing.zig").RouteManager;

/// Device options for TUN/TAP creation
pub const DeviceOptions = struct {
    unit: ?u32 = null, // Device unit number (null = auto-assign)
    mtu: u16 = 1500,
    non_blocking: bool = true,
};

/// Error set for TUN/TAP operations
pub const TapTunError = error{
    DeviceNotFound,
    InvalidConfiguration,
    UnsupportedPlatform,
    RoutingFailed,
};

test {
    std.testing.refAllDecls(@This());
}
