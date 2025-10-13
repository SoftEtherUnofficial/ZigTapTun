//! ZigTapTun - Cross-Platform TAP/TUN Library
//!
//! Complete TUN/TAP device abstraction with L2↔L3 protocol translation.
//!
//! Features:
//! - Platform-specific device I/O (macOS utun, Linux /dev/tun, Windows Wintun)
//! - L2↔L3 translation (Ethernet ↔ IP)
//! - ARP handling
//! - IP and gateway MAC learning

const std = @import("std");
const builtin = @import("builtin");

// Core modules
pub const L2L3Translator = @import("translator.zig").L2L3Translator;
pub const ArpHandler = @import("arp.zig").ArpHandler;
pub const DhcpClient = @import("dhcp_client.zig").DhcpClient;
pub const DhcpPacket = @import("dhcp_client.zig").DhcpPacket;

// High-level adapter (combines device + translator)
pub const TunAdapter = @import("tun_adapter.zig").TunAdapter;

// Platform-specific device implementations
pub const platform = switch (builtin.os.tag) {
    .macos, .ios => @import("platform/macos.zig"),
    .windows => @import("platform/windows.zig"),
    else => @compileError("Platform not yet supported. Available: macOS, Windows. Coming soon: Linux, FreeBSD"),
};

/// Platform-specific TUN device (low-level, for advanced users)
pub const TunDevice = switch (builtin.os.tag) {
    .macos, .ios => platform.MacOSUtunDevice,
    .windows => platform.WindowsTapDevice,
    else => @compileError("Platform not yet supported"),
};

// Public types for L2L3 translation
pub const TranslatorOptions = struct {
    our_mac: [6]u8,
    learn_ip: bool = true,
    learn_gateway_mac: bool = true,
    handle_arp: bool = true,
    arp_timeout_ms: u32 = 60000,
    verbose: bool = false,
};

/// Device options for TUN/TAP creation
pub const DeviceOptions = struct {
    unit: ?u32 = null, // Device unit number (null = auto-assign)
    mtu: u16 = 1500,
    non_blocking: bool = true,
};

/// Error set for TUN/TAP operations
pub const TapTunError = error{
    InvalidPacket,
    TranslationFailed,
    DeviceNotFound,
    InvalidConfiguration,
    UnsupportedPlatform,
};

test {
    std.testing.refAllDecls(@This());
}
