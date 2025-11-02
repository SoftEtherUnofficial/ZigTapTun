//! Windows TAP-Windows6 device implementation
//!
//! Implements TUN/TAP device support using the TAP-Windows6 adapter.
//! TAP-Windows6 is a virtual network interface driver developed by the OpenVPN project.
//!
//! Requirements:
//! - TAP-Windows6 driver installed (from OpenVPN installation)
//! - Administrator privileges required

const std = @import("std");
const windows = std.os.windows;

// Windows API functions not in Zig stdlib
extern "kernel32" fn CreateEventW(
    lpEventAttributes: ?*windows.SECURITY_ATTRIBUTES,
    bManualReset: u32,
    bInitialState: u32,
    lpName: ?[*:0]const u16,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn DeviceIoControl(
    hDevice: windows.HANDLE,
    dwIoControlCode: u32,
    lpInBuffer: ?*const anyopaque,
    nInBufferSize: u32,
    lpOutBuffer: ?*anyopaque,
    nOutBufferSize: u32,
    lpBytesReturned: ?*u32,
    lpOverlapped: ?*windows.OVERLAPPED,
) callconv(.winapi) u32;

extern "advapi32" fn RegEnumKeyExW(
    hKey: windows.HKEY,
    dwIndex: u32,
    lpName: [*:0]u16,
    lpcchName: *u32,
    lpReserved: ?*u32,
    lpClass: ?[*:0]u16,
    lpcchClass: ?*u32,
    lpftLastWriteTime: ?*windows.FILETIME,
) callconv(.winapi) windows.Win32Error;

/// Windows Registry HKEY constants
const HKEY_LOCAL_MACHINE: windows.HKEY = @ptrFromInt(0x80000002);

/// TAP-Windows6 IOCTL codes
pub const TAP_WIN_IOCTL_GET_MAC = CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const TAP_WIN_IOCTL_GET_VERSION = CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const TAP_WIN_IOCTL_GET_MTU = CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const TAP_WIN_IOCTL_GET_INFO = CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT = CTL_CODE(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const TAP_WIN_IOCTL_SET_MEDIA_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const TAP_WIN_IOCTL_CONFIG_DHCP_MASQ = CTL_CODE(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const TAP_WIN_IOCTL_GET_LOG_LINE = CTL_CODE(FILE_DEVICE_UNKNOWN, 8, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT = CTL_CODE(FILE_DEVICE_UNKNOWN, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// Windows device types
const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;

/// IOCTL access
const FILE_ANY_ACCESS: u32 = 0;

/// IOCTL method
const METHOD_BUFFERED: u32 = 0;

/// Build a Windows IOCTL code
fn CTL_CODE(device_type: u32, function: u32, method: u32, access: u32) u32 {
    return (device_type << 16) | (access << 14) | (function << 2) | method;
}

/// Registry paths for TAP adapter enumeration
const ADAPTER_KEY = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
const NETWORK_CONNECTIONS_KEY = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}";

/// TAP adapter component ID
const TAP_COMPONENT_ID = "tap0901";

/// Windows TAP device structure
pub const WindowsTapDevice = struct {
    handle: windows.HANDLE,
    name: [256]u8,
    name_len: usize,
    mac_address: [6]u8,
    mtu: u16,
    read_overlapped: windows.OVERLAPPED,
    write_overlapped: windows.OVERLAPPED,
    read_event: windows.HANDLE,
    write_event: windows.HANDLE,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Open a TAP-Windows6 device
    pub fn open(allocator: std.mem.Allocator, unit_hint: ?u32) !Self {
        _ = unit_hint; // TAP-Windows6 doesn't use unit hints

        // Find first available TAP adapter
        const adapter_id = try findTapAdapter(allocator);
        defer allocator.free(adapter_id);

        // Build device path: \\.\Global\{GUID}.tap
        var device_path_buf: [512]u8 = undefined;
        const device_path = try std.fmt.bufPrintZ(&device_path_buf, "\\\\.\\Global\\{s}.tap", .{adapter_id});

        // Convert to UTF-16
        const device_path_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, device_path);
        defer allocator.free(device_path_w);

        // Open the device
        const handle = windows.kernel32.CreateFileW(
            device_path_w,
            windows.GENERIC_READ | windows.GENERIC_WRITE,
            0,
            null,
            windows.OPEN_EXISTING,
            windows.FILE_ATTRIBUTE_SYSTEM | windows.FILE_FLAG_OVERLAPPED,
            null,
        );

        if (handle == windows.INVALID_HANDLE_VALUE) {
            return error.DeviceNotFound;
        }
        errdefer windows.CloseHandle(handle);

        // Create events for overlapped I/O
        const read_event = CreateEventW(null, 0, 0, null) orelse return error.CreateEventFailed;
        errdefer windows.CloseHandle(read_event);

        const write_event = CreateEventW(null, 0, 0, null) orelse return error.CreateEventFailed;
        errdefer windows.CloseHandle(write_event);

        // Set media status to connected
        var status: u32 = 1;
        var bytes_returned: u32 = 0;
        const media_result = DeviceIoControl(
            handle,
            TAP_WIN_IOCTL_SET_MEDIA_STATUS,
            &status,
            @sizeOf(u32),
            &status,
            @sizeOf(u32),
            &bytes_returned,
            null,
        );
        if (media_result == 0) {
            return error.SetMediaStatusFailed;
        }

        // Get MAC address
        var mac_addr: [6]u8 = undefined;
        const mac_result = DeviceIoControl(
            handle,
            TAP_WIN_IOCTL_GET_MAC,
            null,
            0,
            &mac_addr,
            6,
            &bytes_returned,
            null,
        );
        if (mac_result == 0) {
            return error.GetMacFailed;
        }
        const mac = mac_addr;

        // Get friendly name from registry
        const friendly_name = try getAdapterFriendlyName(allocator, adapter_id);
        defer allocator.free(friendly_name);

        var name_buf: [256]u8 = undefined;
        const name_len = @min(friendly_name.len, name_buf.len - 1);
        @memcpy(name_buf[0..name_len], friendly_name[0..name_len]);
        name_buf[name_len] = 0;

        return Self{
            .handle = handle,
            .name = name_buf,
            .name_len = name_len,
            .mac_address = mac,
            .mtu = 1500,
            .read_overlapped = std.mem.zeroes(windows.OVERLAPPED),
            .write_overlapped = std.mem.zeroes(windows.OVERLAPPED),
            .read_event = read_event,
            .write_event = write_event,
            .allocator = allocator,
        };
    }

    /// Close the TAP device
    pub fn close(self: *Self) void {
        windows.CloseHandle(self.write_event);
        windows.CloseHandle(self.read_event);
        windows.CloseHandle(self.handle);
    }

    /// Get device name
    pub fn getName(self: *const Self) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Get device unit number (not applicable for Windows TAP)
    pub fn getUnit(self: *const Self) u32 {
        _ = self;
        return 0;
    }

    /// Read a packet from the TAP device
    pub fn read(self: *Self, buffer: []u8) ![]const u8 {
        var bytes_read: u32 = 0;

        // Setup overlapped structure
        self.read_overlapped = std.mem.zeroes(windows.OVERLAPPED);
        self.read_overlapped.hEvent = self.read_event;

        // Start async read
        const read_result = windows.kernel32.ReadFile(
            self.handle,
            buffer.ptr,
            @intCast(buffer.len),
            &bytes_read,
            &self.read_overlapped,
        );

        if (read_result == 0) {
            const err = windows.kernel32.GetLastError();
            if (err == .IO_PENDING) {
                // Wait for completion
                try windows.WaitForSingleObject(self.read_event, windows.INFINITE);

                // Get the result
                const overlap_result = windows.kernel32.GetOverlappedResult(
                    self.handle,
                    &self.read_overlapped,
                    &bytes_read,
                    0,
                );
                if (overlap_result == 0) {
                    return error.InputOutput;
                }
            } else {
                return error.InputOutput;
            }
        }

        if (bytes_read == 0) {
            return error.EndOfStream;
        }

        return buffer[0..bytes_read];
    }

    /// Write a packet to the TAP device
    pub fn write(self: *Self, data: []const u8) !void {
        var bytes_written: u32 = 0;

        // Setup overlapped structure
        self.write_overlapped = std.mem.zeroes(windows.OVERLAPPED);
        self.write_overlapped.hEvent = self.write_event;

        // Start async write
        const write_result = windows.kernel32.WriteFile(
            self.handle,
            data.ptr,
            @intCast(data.len),
            &bytes_written,
            &self.write_overlapped,
        );

        if (write_result == 0) {
            const err = windows.kernel32.GetLastError();
            if (err == .IO_PENDING) {
                // Wait for completion with 5 second timeout
                windows.WaitForSingleObject(self.write_event, 5000) catch {
                    return error.Timeout;
                };

                // Get the result
                const overlap_result = windows.kernel32.GetOverlappedResult(
                    self.handle,
                    &self.write_overlapped,
                    &bytes_written,
                    0,
                );
                if (overlap_result == 0) {
                    return error.InputOutput;
                }
            } else {
                return error.InputOutput;
            }
        }

        if (bytes_written != data.len) {
            return error.IncompleteWrite;
        }
    }

    /// Set non-blocking mode (already handled by overlapped I/O)
    pub fn setNonBlocking(self: *Self, enabled: bool) !void {
        _ = self;
        _ = enabled;
        // TAP-Windows6 with overlapped I/O is always non-blocking
    }
};

/// Find the first available TAP adapter
fn findTapAdapter(allocator: std.mem.Allocator) ![]const u8 {
    // Open network adapters key
    var adapter_key: windows.HKEY = undefined;
    const adapter_key_result = windows.advapi32.RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        std.unicode.utf8ToUtf16LeStringLiteral("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"),
        0,
        windows.KEY_READ,
        &adapter_key,
    );

    if (adapter_key_result != 0) {
        return error.DeviceNotFound;
    }
    defer _ = windows.advapi32.RegCloseKey(adapter_key);

    // Enumerate subkeys to find TAP adapter
    var index: u32 = 0;
    while (true) : (index += 1) {
        var subkey_name: [256:0]u16 = undefined;
        var subkey_name_len: u32 = 256;

        const enum_result = RegEnumKeyExW(
            adapter_key,
            index,
            &subkey_name,
            &subkey_name_len,
            null,
            null,
            null,
            null,
        );

        if (enum_result == windows.Win32Error.NO_MORE_ITEMS) {
            break;
        }
        if (enum_result != windows.Win32Error.SUCCESS) {
            continue;
        }

        // Open this subkey
        var subkey: windows.HKEY = undefined;
        const subkey_result = windows.advapi32.RegOpenKeyExW(
            adapter_key,
            &subkey_name,
            0,
            windows.KEY_READ,
            &subkey,
        );

        if (subkey_result != 0) {
            continue;
        }
        defer _ = windows.advapi32.RegCloseKey(subkey);

        // Check ComponentId
        var component_id: [256]u16 = undefined;
        var component_id_len: u32 = @sizeOf(@TypeOf(component_id));
        var value_type: u32 = 0;

        const component_result = windows.advapi32.RegQueryValueExW(
            subkey,
            std.unicode.utf8ToUtf16LeStringLiteral("ComponentId"),
            null,
            &value_type,
            @ptrCast(&component_id),
            &component_id_len,
        );

        if (component_result != 0) {
            continue;
        }

        // Check if it's a TAP adapter
        const tap_id = std.unicode.utf8ToUtf16LeStringLiteral("tap0901");
        const component_id_slice = component_id[0 .. component_id_len / 2];

        if (std.mem.startsWith(u16, component_id_slice, tap_id)) {
            // Get NetCfgInstanceId (the GUID)
            var instance_id: [256]u16 = undefined;
            var instance_id_len: u32 = @sizeOf(@TypeOf(instance_id));

            const instance_result = windows.advapi32.RegQueryValueExW(
                subkey,
                std.unicode.utf8ToUtf16LeStringLiteral("NetCfgInstanceId"),
                null,
                &value_type,
                @ptrCast(&instance_id),
                &instance_id_len,
            );

            if (instance_result == 0) {
                // Convert UTF-16 to UTF-8
                const instance_id_slice = instance_id[0 .. (instance_id_len / 2) - 1]; // -1 to remove null terminator
                const utf8_len = std.unicode.utf16LeToUtf8Alloc(allocator, instance_id_slice) catch continue;
                return utf8_len;
            }
        }
    }

    return error.DeviceNotFound;
}

/// Get the friendly name of an adapter from the registry
fn getAdapterFriendlyName(allocator: std.mem.Allocator, adapter_id: []const u8) ![]const u8 {
    // Build registry path
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "SYSTEM\\CurrentControlSet\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{s}\\Connection", .{adapter_id});

    // Convert to UTF-16
    const path_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, path);
    defer allocator.free(path_w);

    // Open key
    var conn_key: windows.HKEY = undefined;
    const key_result = windows.advapi32.RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        path_w,
        0,
        windows.KEY_READ,
        &conn_key,
    );

    if (key_result != 0) {
        return try allocator.dupe(u8, "TAP-Windows Adapter");
    }
    defer _ = windows.advapi32.RegCloseKey(conn_key);

    // Query the Name value
    var name: [256]u16 = undefined;
    var name_len: u32 = @sizeOf(@TypeOf(name));
    var value_type: u32 = 0;

    const name_result = windows.advapi32.RegQueryValueExW(
        conn_key,
        std.unicode.utf8ToUtf16LeStringLiteral("Name"),
        null,
        &value_type,
        @ptrCast(&name),
        &name_len,
    );

    if (name_result != 0) {
        return try allocator.dupe(u8, "TAP-Windows Adapter");
    }

    // Convert UTF-16 to UTF-8
    const name_slice = name[0 .. (name_len / 2) - 1]; // -1 to remove null terminator
    return try std.unicode.utf16LeToUtf8Alloc(allocator, name_slice);
}

/// No protocol header needed for TAP devices (already Layer 2)
pub fn addProtocolHeader(allocator: std.mem.Allocator, ethernet_frame: []const u8) ![]u8 {
    // TAP devices work at Layer 2, so no header needed
    const frame = try allocator.alloc(u8, ethernet_frame.len);
    @memcpy(frame, ethernet_frame);
    return frame;
}

/// No protocol header to strip for TAP devices
pub fn stripProtocolHeader(packet: []const u8) ![]const u8 {
    // TAP devices work at Layer 2, so no header to strip
    return packet;
}

test "Windows TAP device structure" {
    // Basic structure tests
    const device = WindowsTapDevice{
        .handle = undefined,
        .name = undefined,
        .name_len = 0,
        .mac_address = [_]u8{ 0x02, 0x00, 0x5E, 0x00, 0x00, 0x01 },
        .mtu = 1500,
        .read_overlapped = std.mem.zeroes(windows.OVERLAPPED),
        .write_overlapped = std.mem.zeroes(windows.OVERLAPPED),
        .read_event = undefined,
        .write_event = undefined,
        .allocator = std.testing.allocator,
    };

    try std.testing.expectEqual(@as(u16, 1500), device.mtu);
    try std.testing.expectEqual(@as(u8, 0x02), device.mac_address[0]);
}
