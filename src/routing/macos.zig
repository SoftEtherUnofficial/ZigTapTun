const std = @import("std");

const ArrayListType = std.array_list.AlignedManaged([4]u8, null);

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
            .vpn_server_ips = ArrayListType.init(allocator),
        };
        return self;
    }

    /// Get current default gateway by parsing netstat output
    /// Returns without error if no gateway exists (e.g., no network connection yet)
    pub fn getDefaultGateway(self: *Self) !void {
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "/bin/sh",
                "-c",
                "netstat -rn | grep '^default' | grep -v utun | awk '{print $2}' | head -1",
            },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.stdout.len == 0) {
            std.log.info("No default gateway found (network may not be up yet)", .{});
            return; // Not an error - just means no gateway to save
        }

        // Parse IP address (format: "192.168.1.1\n")
        const ip_str = std.mem.trim(u8, result.stdout, " \t\n\r");
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
        std.log.info("Deleting existing default routes...", .{});
        for (0..3) |attempt| {
            const delete_result = try std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{ "route", "-n", "delete", "default" },
            });
            defer self.allocator.free(delete_result.stdout);
            defer self.allocator.free(delete_result.stderr);

            if (attempt == 0) {
                std.log.debug("Delete attempt {d}, exit: {}", .{ attempt + 1, delete_result.term });
            }
        }

        // Add VPN default route
        var cmd_buf: [256]u8 = undefined;
        const cmd = try std.fmt.bufPrint(&cmd_buf, "{d}.{d}.{d}.{d}", .{
            vpn_gw[0],
            vpn_gw[1],
            vpn_gw[2],
            vpn_gw[3],
        });

        std.log.info("Adding VPN default route: {s}", .{cmd});
        const add_result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "route", "-n", "add", "-inet", "default", cmd },
        });
        defer self.allocator.free(add_result.stdout);
        defer self.allocator.free(add_result.stderr);

        if (add_result.term != .Exited or add_result.term.Exited != 0) {
            // Try without -n flag as fallback
            const fallback_result = try std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{ "route", "add", "-inet", "default", cmd },
            });
            defer self.allocator.free(fallback_result.stdout);
            defer self.allocator.free(fallback_result.stderr);

            if (fallback_result.term != .Exited or fallback_result.term.Exited != 0) {
                std.log.err("Failed to add default route", .{});
                return error.RouteAddFailed;
            }
        }

        self.routes_configured = true;
        std.log.info("✅ Default route now points to VPN gateway {d}.{d}.{d}.{d}", .{
            vpn_gw[0],
            vpn_gw[1],
            vpn_gw[2],
            vpn_gw[3],
        });
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

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "route", "add", "-host", dest_str, gw_str },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        // Store for cleanup
        try self.vpn_server_ips.append(destination);
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
        const delete_result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "route", "delete", "default" },
        });
        defer self.allocator.free(delete_result.stdout);
        defer self.allocator.free(delete_result.stderr);
        std.log.info("[ROUTE RESTORE] Step 1/3 ✅ VPN route deleted", .{});

        // Restore original default route
        std.log.info("[ROUTE RESTORE] Step 2/3: Restoring original default route: {s}", .{gw_str});
        const add_result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "route", "add", "default", gw_str },
        });
        defer self.allocator.free(add_result.stdout);
        defer self.allocator.free(add_result.stderr);
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
            const cleanup_result = try std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{ "route", "delete", "-host", server_str },
            });
            defer self.allocator.free(cleanup_result.stdout);
            defer self.allocator.free(cleanup_result.stderr);
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

        self.vpn_server_ips.deinit();
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
