# TapTun - Cross-Platform TUN Device Library

A minimal, cross-platform TUN interface library for VPN and network virtualization written in Zig.

## What is TUN?

**TUN (Layer 3)**: Virtual network interface operating at the IP layer.
- Handles raw IP packets (no Ethernet headers)
- Point-to-point interface
- Used by: OpenVPN, WireGuard, VPN clients

## Scope

TapTun provides **platform-specific TUN device abstraction and routing management**:

✅ **Device I/O**: Cross-platform TUN device creation and packet I/O  
✅ **Route Management**: Save/restore system routing tables  
✅ **Platform Support**: macOS, Linux, Windows  

❌ **Not Included** (handled by parent SoftEtherClient):
- L2↔L3 protocol translation
- ARP/DHCP/DNS protocols
- Packet translation logic

## Features

- Cross-platform TUN device support (macOS, Linux, Windows)
- Non-blocking I/O
- Automatic route management (save/restore default gateway)
- Platform-specific optimizations
- Clean, minimal API

### Platform Details

| Platform | Implementation | Route Management |
|----------|---------------|------------------|
| macOS | \`utun\` kernel control | \`route\` command |
| Linux | \`/dev/net/tun\` | \`ip route\` command |
| Windows | Wintun driver | \`netsh\`/\`route.exe\` |

## Quick Start

\`\`\`zig
const std = @import("std");
const taptun = @import("taptun");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // Open TUN device
    var device = try taptun.TunDevice.open(allocator, .{
        .unit = null,  // Auto-assign device number
        .mtu = 1500,
        .non_blocking = true,
    });
    defer device.close();

    // Initialize route manager
    var route_manager = try taptun.RouteManager.init(allocator);
    defer route_manager.deinit();
    
    // Save original gateway (for restoration on exit)
    try route_manager.getDefaultGateway();

    // Read/write IP packets
    var buffer: [2048]u8 = undefined;
    const ip_packet = try device.read(&buffer);
    try device.write(ip_packet);
}
\`\`\`

## Directory Structure

\`\`\`
TapTun/
├── src/
│   ├── taptun.zig          # Main module
│   ├── device/             # Platform-specific device implementations
│   │   ├── macos.zig       # macOS utun
│   │   ├── linux.zig       # Linux /dev/net/tun
│   │   ├── windows.zig     # Windows Wintun
│   │   ├── ios.zig         # iOS (Network Extension)
│   │   └── android.zig     # Android (VpnService)
│   ├── routing/            # Platform-specific route management
│   │   ├── macos.zig       # macOS route command
│   │   ├── linux.zig       # Linux ip route
│   │   └── windows.zig     # Windows netsh
│   └── utils/
│       └── ifconfig.zig    # Helper utilities
├── build.zig
└── README.md
\`\`\`

## License

See parent SoftEtherClient project for license information.
