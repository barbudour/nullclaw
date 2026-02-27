const std = @import("std");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const config_types = @import("../config_types.zig");

const log = std.log.scoped(.web);

pub const WebChannel = struct {
    allocator: std.mem.Allocator,
    port: u16,
    listen_address: []const u8,
    max_connections: u16,
    account_id: []const u8,
    bus: ?*bus_mod.Bus = null,

    // Auth token: 32 random bytes → 64 hex chars
    token: [64]u8 = undefined,
    token_initialized: bool = false,

    // Runtime state
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    const vtable = root.Channel.VTable{
        .start = wsStart,
        .stop = wsStop,
        .send = wsSend,
        .name = wsName,
        .healthCheck = wsHealthCheck,
    };

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WebConfig) WebChannel {
        return .{
            .allocator = allocator,
            .port = cfg.port,
            .listen_address = cfg.listen,
            .max_connections = cfg.max_connections,
            .account_id = cfg.account_id,
        };
    }

    pub fn channel(self: *WebChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    pub fn setBus(self: *WebChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    /// Generate a random auth token (64 hex chars from 32 random bytes).
    pub fn generateToken(self: *WebChannel) void {
        var random_bytes: [32]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        self.token = std.fmt.bytesToHex(random_bytes, .lower);
        self.token_initialized = true;
    }

    /// Validate a token string against the stored token.
    pub fn validateToken(self: *const WebChannel, candidate: []const u8) bool {
        if (!self.token_initialized) return false;
        if (candidate.len != 64) return false;
        return std.crypto.timing_safe.eql([64]u8, candidate[0..64].*, self.token);
    }

    // ── vtable implementations (stubs for now, Task 5 fills them) ──

    fn wsStart(ctx: *anyopaque) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        self.generateToken();
        self.running.store(true, .release);

        if (!@import("builtin").is_test) {
            log.info("Web channel ready on {s}:{d}", .{ self.listen_address, self.port });
            log.info("Token: {s}", .{&self.token});
        }
    }

    fn wsStop(ctx: *anyopaque) void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        self.running.store(false, .release);
    }

    fn wsSend(ctx: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        _ = self;
        _ = target;
        _ = message;
        // TODO: Task 5 — send to WS connections
    }

    fn wsName(_: *anyopaque) []const u8 {
        return "web";
    }

    fn wsHealthCheck(ctx: *anyopaque) bool {
        const self: *const WebChannel = @ptrCast(@alignCast(ctx));
        return self.running.load(.acquire);
    }
};

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

test "WebChannel initFromConfig uses defaults" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expectEqual(@as(u16, 32123), ch.port);
    try std.testing.expectEqualStrings("127.0.0.1", ch.listen_address);
    try std.testing.expectEqual(@as(u16, 10), ch.max_connections);
    try std.testing.expectEqualStrings("default", ch.account_id);
    try std.testing.expect(ch.bus == null);
    try std.testing.expect(!ch.running.load(.acquire));
}

test "WebChannel initFromConfig uses custom values" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .port = 8080,
        .listen = "0.0.0.0",
        .max_connections = 5,
        .account_id = "web-main",
    });
    try std.testing.expectEqual(@as(u16, 8080), ch.port);
    try std.testing.expectEqualStrings("0.0.0.0", ch.listen_address);
    try std.testing.expectEqual(@as(u16, 5), ch.max_connections);
    try std.testing.expectEqualStrings("web-main", ch.account_id);
}

test "WebChannel vtable name returns web" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("web", iface.name());
}

test "WebChannel generateToken produces 64 hex chars" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expect(!ch.token_initialized);
    ch.generateToken();
    try std.testing.expect(ch.token_initialized);
    try std.testing.expectEqual(@as(usize, 64), ch.token.len);
    // All chars should be hex
    for (&ch.token) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "WebChannel validateToken accepts correct token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    try std.testing.expect(ch.validateToken(&ch.token));
}

test "WebChannel validateToken rejects wrong token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    var bad_token: [64]u8 = undefined;
    @memset(&bad_token, 'x');
    try std.testing.expect(!ch.validateToken(&bad_token));
}

test "WebChannel validateToken rejects wrong length" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    try std.testing.expect(!ch.validateToken("short"));
    try std.testing.expect(!ch.validateToken(""));
}

test "WebChannel validateToken rejects before init" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expect(!ch.validateToken("a" ** 64));
}

test "WebChannel start sets running and generates token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    const iface = ch.channel();
    try std.testing.expect(!ch.running.load(.acquire));
    try iface.start();
    try std.testing.expect(ch.running.load(.acquire));
    try std.testing.expect(ch.token_initialized);
}

test "WebChannel stop clears running" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    const iface = ch.channel();
    try iface.start();
    try std.testing.expect(ch.running.load(.acquire));
    iface.stop();
    try std.testing.expect(!ch.running.load(.acquire));
}

test "WebChannel healthCheck reflects running state" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    const iface = ch.channel();
    try std.testing.expect(!iface.healthCheck());
    try iface.start();
    try std.testing.expect(iface.healthCheck());
    iface.stop();
    try std.testing.expect(!iface.healthCheck());
}

test "WebChannel setBus stores bus reference" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);
    try std.testing.expect(ch.bus == &bus);
}

test "WebChannel two instances have different tokens" {
    var ch1 = WebChannel.initFromConfig(std.testing.allocator, .{});
    var ch2 = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch1.generateToken();
    ch2.generateToken();
    // Extremely unlikely to be equal (2^256 keyspace)
    try std.testing.expect(!std.mem.eql(u8, &ch1.token, &ch2.token));
}

test {
    @import("std").testing.refAllDecls(@This());
}
