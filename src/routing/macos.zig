const std = @import("std");
const routing = @import("../routing.zig");
const ifconfig = @import("../utils/ifconfig.zig");

const ArrayListType = std.ArrayList([4]u8);

pub const RouteManager = struct {
    allocator: std.mem.Allocator,
    local_gateway: ?[4]u8 = null, // Store as IPv4 octets
    vpn_gateway: ?[4]u8 = null,
    vpn_server_ips: ArrayListType,
    routes_configured: bool = false,

    const Self = @This();

    /// Initialize route manager
    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .vpn_server_ips = ArrayListType{},
        };
        return self;
    }

    /// Get current default gateway by parsing netstat output
    /// Returns without error if no gateway exists (e.g., no network connection yet)
    pub fn getDefaultGateway(self: *Self) !void {
        const stdout = routing.execCommand(
            self.allocator,
            &[_][]const u8{
                "/bin/sh",
                "-c",
                "netstat -rn | grep '^default' | grep -v utun | awk '{print $2}' | head -1",
            },
        ) catch |err| {
            if (err == error.CommandFailed) {
                std.log.info("No default gateway found (network may not be up yet)", .{});
                return;
            }
            return err;
        };
        defer self.allocator.free(stdout);

        if (stdout.len == 0) {
            std.log.info("No default gateway found (network may not be up yet)", .{});
            return;
        }

        // Parse IP address (format: "192.168.1.1\n")
        const ip_str = std.mem.trim(u8, stdout, " \t\n\r");
        var octets: [4]u8 = undefined;
        var iter = std.mem.splitSequence(u8, ip_str, ".");
        var i: usize = 0;
        while (iter.next()) |octet_str| : (i += 1) {
            if (i >= 4) return error.InvalidIpAddress;
            octets[i] = try std.fmt.parseInt(u8, octet_str, 10);
        }
        if (i != 4) return error.InvalidIpAddress;

        self.local_gateway = octets;
        std.log.info("Saved original gateway: {d}.{d}.{d}.{d}", .{
            octets[0],
            octets[1],
            octets[2],
            octets[3],
        });
    }

    /// Replace default gateway with VPN gateway
    pub fn replaceDefaultGateway(self: *Self, vpn_gw: [4]u8) !void {
        self.vpn_gateway = vpn_gw;

        // Delete all existing default routes (macOS may have multiple)
        for (0..3) |_| {
            routing.execCommandSimple(self.allocator, &[_][]const u8{
                "route",
                "-n",
                "delete",
                "default",
            }) catch {};
        }

        // Add VPN default route
        var cmd_buf: [256]u8 = undefined;
        const cmd = try std.fmt.bufPrint(&cmd_buf, "{d}.{d}.{d}.{d}", .{
            vpn_gw[0],
            vpn_gw[1],
            vpn_gw[2],
            vpn_gw[3],
        });

        routing.execCommandSimple(self.allocator, &[_][]const u8{
            "route",
            "-n",
            "add",
            "-inet",
            "default",
            cmd,
        }) catch {
            // Try without -n flag as fallback
            routing.execCommandSimple(self.allocator, &[_][]const u8{
                "route",
                "add",
                "-inet",
                "default",
                cmd,
            }) catch {
                std.log.err("Failed to add default route", .{});
                return error.RouteAddFailed;
            };
        };

        self.routes_configured = true;
    }

    /// Add host route (e.g., VPN server through original gateway)
    pub fn addHostRoute(self: *Self, destination: [4]u8, gateway: [4]u8) !void {
        var dest_buf: [16]u8 = undefined;
        const dest_str = try std.fmt.bufPrint(&dest_buf, "{d}.{d}.{d}.{d}", .{
            destination[0],
            destination[1],
            destination[2],
            destination[3],
        });

        var gw_buf: [16]u8 = undefined;
        const gw_str = try std.fmt.bufPrint(&gw_buf, "{d}.{d}.{d}.{d}", .{
            gateway[0],
            gateway[1],
            gateway[2],
            gateway[3],
        });

        std.log.info("Adding host route: {s} via {s}", .{ dest_str, gw_str });

        try routing.execCommandSimple(self.allocator, &[_][]const u8{
            "route",
            "add",
            "-host",
            dest_str,
            gw_str,
        });

        // Store for cleanup
        try self.vpn_server_ips.append(self.allocator, destination);
    }

    /// Add network route for VPN subnet (e.g., 10.21.0.0/16 via gateway)
    /// This is critical for point-to-point TUN interfaces on macOS
    pub fn addNetworkRoute(self: *Self, network: [4]u8, netmask: [4]u8, gateway: [4]u8) !void {
        var net_buf: [16]u8 = undefined;
        const net_str = try std.fmt.bufPrint(&net_buf, "{d}.{d}.{d}.{d}", .{
            network[0],
            network[1],
            network[2],
            network[3],
        });

        var mask_buf: [16]u8 = undefined;
        const mask_str = try std.fmt.bufPrint(&mask_buf, "{d}.{d}.{d}.{d}", .{
            netmask[0],
            netmask[1],
            netmask[2],
            netmask[3],
        });

        var gw_buf: [16]u8 = undefined;
        const gw_str = try std.fmt.bufPrint(&gw_buf, "{d}.{d}.{d}.{d}", .{
            gateway[0],
            gateway[1],
            gateway[2],
            gateway[3],
        });

        std.log.info("🔧 Adding VPN network route: {s}/{s} via {s}", .{ net_str, mask_str, gw_str });

        routing.execCommandSimple(self.allocator, &[_][]const u8{
            "route",
            "add",
            "-net",
            net_str,
            gw_str,
            "-netmask",
            mask_str,
        }) catch |err| {
            std.log.warn("Failed to add network route", .{});
            return err;
        };

        std.log.info("✅ VPN network route added successfully", .{});
    }

    /// Restore original routing configuration
    pub fn restore(self: *Self) !void {
        if (!self.routes_configured or self.local_gateway == null) {
            std.log.debug("No routes to restore", .{});
            return;
        }

        const orig_gw = self.local_gateway.?;
        var gw_buf: [16]u8 = undefined;
        const gw_str = try std.fmt.bufPrint(&gw_buf, "{d}.{d}.{d}.{d}", .{
            orig_gw[0],
            orig_gw[1],
            orig_gw[2],
            orig_gw[3],
        });

        std.log.info("🔄 [ROUTE RESTORE] Starting restoration (gateway: {s})", .{gw_str});

        // Delete VPN default route
        std.log.info("[ROUTE RESTORE] Step 1/3: Removing VPN default route...", .{});
        try routing.execCommandSimple(self.allocator, &[_][]const u8{
            "route",
            "delete",
            "default",
        });
        std.log.info("[ROUTE RESTORE] Step 1/3 ✅ VPN route deleted", .{});

        // Restore original default route
        std.log.info("[ROUTE RESTORE] Step 2/3: Restoring original default route: {s}", .{gw_str});
        try routing.execCommandSimple(self.allocator, &[_][]const u8{
            "route",
            "add",
            "default",
            gw_str,
        });
        std.log.info("[ROUTE RESTORE] Step 2/3 ✅ Original route restored", .{});

        // Clean up VPN server host routes
        std.log.info("[ROUTE RESTORE] Step 3/3: Cleaning up {} VPN server routes...", .{self.vpn_server_ips.items.len});
        for (self.vpn_server_ips.items) |server_ip| {
            var server_buf: [16]u8 = undefined;
            const server_str = try std.fmt.bufPrint(&server_buf, "{d}.{d}.{d}.{d}", .{
                server_ip[0],
                server_ip[1],
                server_ip[2],
                server_ip[3],
            });

            std.log.debug("Cleaning up VPN server route: {s}", .{server_str});
            routing.execCommandSimple(self.allocator, &[_][]const u8{
                "route",
                "delete",
                "-host",
                server_str,
            }) catch {};
        }

        std.log.info("[ROUTE RESTORE] ✅ All routing restored successfully", .{});
        self.routes_configured = false;
    }

    /// Cleanup (automatically restores routes)
    pub fn deinit(self: *Self) void {
        // Restore routes if configured
        self.restore() catch |err| {
            std.log.err("Failed to restore routes during deinit: {}", .{err});
        };

        self.vpn_server_ips.deinit(self.allocator);
        self.allocator.destroy(self);
    }
};

test "RouteManager basic operations" {
    // Skip tests in CI or when integration tests are disabled
    if (std.process.hasEnvVarConstant("CI") or std.process.hasEnvVarConstant("SKIP_INTEGRATION_TESTS")) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    var rm = try RouteManager.init(allocator);
    defer rm.deinit();

    // Get default gateway (requires root)
    rm.getDefaultGateway() catch |err| {
        std.debug.print("Skipping test (requires root): {}\n", .{err});
        return error.SkipZigTest;
    };

    try std.testing.expect(rm.local_gateway != null);
}
