const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const ws_client = @import("../websocket.zig");
const config_types = @import("../config_types.zig");
const websocket = @import("websocket");

const log = std.log.scoped(.web);

pub const WebChannel = struct {
    const WebTransport = enum {
        local,
        relay,
    };

    allocator: std.mem.Allocator,
    transport: WebTransport,
    port: u16,
    listen_address: []const u8,
    ws_path: []const u8,
    max_connections: u16,
    account_id: []const u8,
    configured_auth_token: ?[]const u8,
    allowed_origins: []const []const u8,
    relay_url: ?[]const u8,
    relay_agent_id: []const u8,
    configured_relay_token: ?[]const u8,
    bus: ?*bus_mod.Bus = null,

    // Active auth token (configured/env/generate).
    token: [128]u8 = [_]u8{0} ** 128,
    token_len: u8 = 0,
    token_initialized: bool = false,

    // Runtime state
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    server: ?WsServer = null,
    server_thread: ?std.Thread = null,
    relay_thread: ?std.Thread = null,

    // Connection tracking
    connections: ConnectionList = .{},

    // Relay state
    relay_client_mu: std.Thread.Mutex = .{},
    relay_client: ?*ws_client.WsClient = null,
    relay_connected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    relay_socket_fd: std.atomic.Value(SocketFd) = std.atomic.Value(SocketFd).init(invalid_socket),

    const SocketFd = std.net.Stream.Handle;
    const invalid_socket: SocketFd = switch (builtin.os.tag) {
        .windows => std.os.windows.ws2_32.INVALID_SOCKET,
        else => -1,
    };

    const WsServer = websocket.Server(WsHandler);

    const vtable = root.Channel.VTable{
        .start = wsStart,
        .stop = wsStop,
        .send = wsSend,
        .name = wsName,
        .healthCheck = wsHealthCheck,
    };

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WebConfig) WebChannel {
        const clamped_max_connections: u16 = if (@as(usize, cfg.max_connections) > ConnectionList.MAX_TRACKED)
            @intCast(ConnectionList.MAX_TRACKED)
        else
            cfg.max_connections;
        const normalized_path = config_types.WebConfig.normalizePath(cfg.path);
        return .{
            .allocator = allocator,
            .transport = parseTransport(cfg.transport),
            .port = cfg.port,
            .listen_address = cfg.listen,
            .ws_path = normalized_path,
            .max_connections = clamped_max_connections,
            .account_id = cfg.account_id,
            .configured_auth_token = cfg.auth_token,
            .allowed_origins = cfg.allowed_origins,
            .relay_url = cfg.relay_url,
            .relay_agent_id = cfg.relay_agent_id,
            .configured_relay_token = cfg.relay_token,
        };
    }

    fn parseTransport(raw: []const u8) WebTransport {
        if (config_types.WebConfig.isRelayTransport(raw)) return .relay;
        return .local;
    }

    pub fn channel(self: *WebChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    pub fn setBus(self: *WebChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    fn setActiveToken(self: *WebChannel, raw: []const u8) !void {
        if (!config_types.WebConfig.isValidAuthToken(raw)) return error.InvalidAuthToken;
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        @memset(self.token[0..], 0);
        @memcpy(self.token[0..trimmed.len], trimmed);
        self.token_len = @intCast(trimmed.len);
        self.token_initialized = true;
    }

    fn loadTokenFromEnvCandidates(self: *WebChannel, env_candidates: []const []const u8) !bool {
        for (env_candidates) |name| {
            if (std.process.getEnvVarOwned(self.allocator, name)) |raw| {
                defer self.allocator.free(raw);
                self.setActiveToken(raw) catch |err| {
                    if (err == error.InvalidAuthToken) {
                        log.warn("Ignoring invalid Web channel auth token from env {s}", .{name});
                        continue;
                    }
                    return err;
                };
                log.info("Web channel auth token loaded from env {s}", .{name});
                return true;
            } else |_| {}
        }
        return false;
    }

    fn loadLocalTokenFromEnv(self: *WebChannel) !bool {
        return self.loadTokenFromEnvCandidates(&.{
            "NULLCLAW_WEB_TOKEN",
            "NULLCLAW_GATEWAY_TOKEN",
            "OPENCLAW_GATEWAY_TOKEN",
        });
    }

    fn loadRelayTokenFromEnv(self: *WebChannel) !bool {
        return self.loadTokenFromEnvCandidates(&.{
            "NULLCLAW_RELAY_TOKEN",
            "NULLCLAW_WEB_TOKEN",
            "NULLCLAW_GATEWAY_TOKEN",
            "OPENCLAW_GATEWAY_TOKEN",
        });
    }

    /// Generate a random auth token (64 hex chars from 32 random bytes).
    pub fn generateToken(self: *WebChannel) void {
        var random_bytes: [32]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        const hex = std.fmt.bytesToHex(random_bytes, .lower);
        @memset(self.token[0..], 0);
        @memcpy(self.token[0..hex.len], &hex);
        self.token_len = @intCast(hex.len);
        self.token_initialized = true;
    }

    /// Validate a token string against the stored token.
    pub fn validateToken(self: *const WebChannel, candidate: []const u8) bool {
        if (!self.token_initialized) return false;
        const active = self.token[0..self.token_len];
        if (candidate.len != active.len) return false;
        var diff: u8 = 0;
        for (candidate, active) |a, b| diff |= a ^ b;
        return diff == 0;
    }

    fn activeToken(self: *const WebChannel) []const u8 {
        if (!self.token_initialized) return "";
        return self.token[0..self.token_len];
    }

    // ── vtable implementations ──

    fn wsStart(ctx: *anyopaque) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        switch (self.transport) {
            .local => try self.startLocalTransport(),
            .relay => try self.startRelayTransport(),
        }
    }

    fn startLocalTransport(self: *WebChannel) !void {
        var token_source: enum { config, env, ephemeral } = .ephemeral;
        if (self.configured_auth_token) |token| {
            try self.setActiveToken(token);
            token_source = .config;
            log.info("Web channel auth token loaded from channels.web auth_token", .{});
        } else if (try self.loadLocalTokenFromEnv()) {
            token_source = .env;
        } else {
            self.generateToken();
            token_source = .ephemeral;
            log.warn("Web channel using ephemeral auth token for this run", .{});
        }

        self.server = WsServer.init(self.allocator, .{
            .port = self.port,
            .address = self.listen_address,
            .max_conn = @intCast(self.max_connections),
        }) catch |err| {
            log.err("Failed to init WebSocket server: {}", .{err});
            return err;
        };

        self.running.store(true, .release);

        self.server_thread = std.Thread.spawn(.{}, serverListenThread, .{self}) catch |err| {
            log.err("Failed to spawn WS server thread: {}", .{err});
            self.running.store(false, .release);
            if (self.server) |*s| s.deinit();
            self.server = null;
            return err;
        };

        log.info("Web channel ready on ws://{s}:{d}{s}", .{ self.listen_address, self.port, self.ws_path });
        switch (token_source) {
            .ephemeral => log.warn("Web channel one-time token: {s}", .{self.activeToken()}),
            .config, .env => log.info("Web channel auth token active (hidden in logs)", .{}),
        }
    }

    fn startRelayTransport(self: *WebChannel) !void {
        if (self.configured_relay_token) |token| {
            try self.setActiveToken(token);
            log.info("Web relay token loaded from channels.web relay_token", .{});
        } else if (self.configured_auth_token) |token| {
            try self.setActiveToken(token);
            log.info("Web relay token loaded from channels.web auth_token", .{});
        } else if (!(try self.loadRelayTokenFromEnv())) {
            self.generateToken();
            log.warn("Web relay using ephemeral token for this run: {s}", .{self.activeToken()});
        }

        const relay_url = self.relay_url orelse return error.InvalidConfiguration;
        const endpoint = try parseRelayEndpoint(relay_url);

        var auth_header_buf: [256]u8 = undefined;
        const auth_header = try std.fmt.bufPrint(&auth_header_buf, "Authorization: Bearer {s}", .{self.activeToken()});
        var agent_header_buf: [128]u8 = undefined;
        const agent_header = try std.fmt.bufPrint(&agent_header_buf, "X-NullClaw-Agent: {s}", .{self.relay_agent_id});

        const ws_ptr = try self.allocator.create(ws_client.WsClient);
        errdefer self.allocator.destroy(ws_ptr);
        ws_ptr.* = try ws_client.WsClient.connect(
            self.allocator,
            endpoint.host,
            endpoint.port,
            endpoint.path,
            &.{ auth_header, agent_header, "X-WebChannel-Version: 1" },
        );
        errdefer ws_ptr.deinit();

        self.relay_client_mu.lock();
        self.relay_client = ws_ptr;
        self.relay_client_mu.unlock();
        self.relay_socket_fd.store(ws_ptr.stream.handle, .release);
        self.relay_connected.store(true, .release);
        self.running.store(true, .release);

        self.relay_thread = std.Thread.spawn(.{}, relayReadThread, .{self}) catch |err| {
            self.relay_client_mu.lock();
            self.relay_client = null;
            self.relay_client_mu.unlock();
            self.relay_connected.store(false, .release);
            self.relay_socket_fd.store(invalid_socket, .release);
            self.running.store(false, .release);
            ws_ptr.deinit();
            self.allocator.destroy(ws_ptr);
            return err;
        };

        log.info("Web relay connected to {s}", .{relay_url});
    }

    fn serverListenThread(self: *WebChannel) void {
        if (self.server) |*s| {
            s.listen(self) catch |err| {
                if (self.running.load(.acquire)) {
                    log.err("WebSocket server listen error: {}", .{err});
                    self.running.store(false, .release);
                }
                return;
            };
            if (self.running.load(.acquire)) {
                log.err("WebSocket server stopped unexpectedly", .{});
                self.running.store(false, .release);
            }
        } else {
            self.running.store(false, .release);
        }
    }

    fn relayReadThread(self: *WebChannel) void {
        while (self.running.load(.acquire)) {
            self.relay_client_mu.lock();
            const ws_ptr = self.relay_client;
            self.relay_client_mu.unlock();
            if (ws_ptr == null) break;

            const message_opt = ws_ptr.?.readTextMessage() catch |err| {
                if (self.running.load(.acquire)) {
                    log.warn("Web relay read failed: {}", .{err});
                }
                break;
            };
            const message = message_opt orelse break;
            defer self.allocator.free(message);

            self.handleInboundEvent(message, null);
        }

        self.relay_connected.store(false, .release);
        self.relay_socket_fd.store(invalid_socket, .release);
        if (self.running.load(.acquire)) {
            self.running.store(false, .release);
            log.warn("Web relay disconnected", .{});
        }
    }

    fn wsStop(ctx: *anyopaque) void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));
        switch (self.transport) {
            .local => self.stopLocalTransport(),
            .relay => self.stopRelayTransport(),
        }
    }

    fn stopLocalTransport(self: *WebChannel) void {
        self.running.store(false, .release);

        // Stop the server (closes listening socket, triggers listen loop exit)
        if (self.server) |*s| {
            if (comptime builtin.os.tag == .windows) {
                // websocket.zig 0.1.0 on Zig 0.15.2 has a Windows type mismatch in
                // Server.stop(); mimic its logic without posix.shutdown().
                s._mut.lock();
                defer s._mut.unlock();
                for (s._signals) |fd| {
                    std.posix.close(fd);
                }
                s._cond.wait(&s._mut);
            } else {
                s.stop();
            }
        }

        if (self.server_thread) |t| {
            t.join();
            self.server_thread = null;
        }

        self.connections.closeAll();

        if (self.server) |*s| {
            s.deinit();
            self.server = null;
        }
    }

    fn stopRelayTransport(self: *WebChannel) void {
        self.running.store(false, .release);
        self.relay_connected.store(false, .release);

        self.relay_client_mu.lock();
        const ws_ptr = self.relay_client;
        self.relay_client_mu.unlock();
        if (ws_ptr) |ws| {
            ws.writeClose();
        }

        // Force-close socket to unblock blocking read when relay does not answer close.
        const fd = self.relay_socket_fd.load(.acquire);
        if (fd != invalid_socket) {
            if (comptime builtin.os.tag == .windows) {
                _ = std.os.windows.ws2_32.closesocket(fd);
            } else {
                std.posix.close(fd);
            }
            self.relay_socket_fd.store(invalid_socket, .release);
        }

        if (self.relay_thread) |t| {
            t.join();
            self.relay_thread = null;
        }

        self.relay_client_mu.lock();
        const client = self.relay_client;
        self.relay_client = null;
        self.relay_client_mu.unlock();
        if (client) |ws| {
            ws.deinit();
            self.allocator.destroy(ws);
        }
    }

    fn wsSend(ctx: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WebChannel = @ptrCast(@alignCast(ctx));

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        // WebChannel v1 envelope; keep top-level content for legacy clients.
        try w.writeAll("{\"v\":1,\"type\":\"assistant_final\",\"session_id\":");
        try root.appendJsonStringW(w, target);
        try w.writeAll(",\"agent_id\":");
        try root.appendJsonStringW(w, self.account_id);
        try w.writeAll(",\"payload\":{\"content\":");
        try root.appendJsonStringW(w, message);
        try w.writeAll("},\"content\":");
        try root.appendJsonStringW(w, message);
        try w.writeByte('}');

        switch (self.transport) {
            .local => self.connections.broadcast(target, buf.items),
            .relay => {
                self.relay_client_mu.lock();
                defer self.relay_client_mu.unlock();
                const ws_ptr = self.relay_client orelse return error.NotConnected;
                try ws_ptr.writeText(buf.items);
            },
        }
    }

    fn wsName(_: *anyopaque) []const u8 {
        return "web";
    }

    fn wsHealthCheck(ctx: *anyopaque) bool {
        const self: *const WebChannel = @ptrCast(@alignCast(ctx));
        return switch (self.transport) {
            .local => self.running.load(.acquire),
            .relay => self.running.load(.acquire) and self.relay_connected.load(.acquire),
        };
    }

    fn handleInboundEvent(self: *WebChannel, data: []const u8, forced_session_id: ?[]const u8) void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch {
            log.warn("WS: invalid JSON from client", .{});
            return;
        };
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => {
                log.warn("WS: expected JSON object", .{});
                return;
            },
        };

        if (obj.get("type")) |type_val| {
            if (type_val != .string) return;
            if (!std.mem.eql(u8, type_val.string, "user_message")) return;
        }

        var payload_obj: ?std.json.ObjectMap = null;
        if (obj.get("payload")) |payload_val| {
            if (payload_val == .object) payload_obj = payload_val.object;
        }

        const content = blk: {
            if (payload_obj) |p| {
                if (p.get("content")) |v| {
                    if (v == .string) break :blk v.string;
                }
            }
            if (obj.get("content")) |v| {
                if (v == .string) break :blk v.string;
            }
            return;
        };

        const sender_id = blk: {
            if (payload_obj) |p| {
                if (p.get("sender_id")) |v| {
                    if (v == .string and v.string.len > 0) break :blk v.string;
                }
            }
            if (obj.get("sender_id")) |v| {
                if (v == .string and v.string.len > 0) break :blk v.string;
            }
            break :blk "web-user";
        };

        const request_id: ?[]const u8 = blk: {
            if (obj.get("request_id")) |v| {
                if (v == .string and v.string.len > 0) break :blk v.string;
            }
            break :blk null;
        };

        const session_id = blk: {
            if (forced_session_id) |sid| break :blk sid;
            if (obj.get("session_id")) |v| {
                if (v == .string and v.string.len > 0) break :blk v.string;
            }
            break :blk "default";
        };

        if (forced_session_id) |bound_sid| {
            if (obj.get("session_id")) |v| {
                if (v == .string and !std.mem.eql(u8, v.string, bound_sid)) {
                    log.warn("WS: ignoring session_id override for established connection", .{});
                }
            }
        }

        self.publishInboundMessage(sender_id, session_id, content, request_id);
    }

    fn publishInboundMessage(self: *WebChannel, sender_id: []const u8, session_id: []const u8, content: []const u8, request_id: ?[]const u8) void {
        const allocator = self.allocator;
        const session_key = std.fmt.allocPrint(allocator, "web:{s}:direct:{s}", .{
            self.account_id,
            session_id,
        }) catch return;
        defer allocator.free(session_key);

        var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer metadata_buf.deinit(allocator);
        const mw = metadata_buf.writer(allocator);
        mw.writeAll("{\"is_dm\":true,\"account_id\":") catch return;
        root.appendJsonStringW(mw, self.account_id) catch return;
        if (request_id) |rid| {
            mw.writeAll(",\"request_id\":") catch return;
            root.appendJsonStringW(mw, rid) catch return;
        }
        mw.writeByte('}') catch return;

        const msg = bus_mod.makeInboundFull(
            allocator,
            "web",
            sender_id,
            session_id,
            content,
            session_key,
            &.{},
            metadata_buf.items,
        ) catch |err| {
            log.warn("WS: failed to create inbound message: {}", .{err});
            return;
        };

        if (self.bus) |b| {
            b.publishInbound(msg) catch |err| {
                log.warn("WS: failed to publish inbound: {}", .{err});
                msg.deinit(allocator);
            };
        } else {
            msg.deinit(allocator);
        }
    }

    // ── Connection tracking ──

    pub const ConnectionList = struct {
        mutex: std.Thread.Mutex = .{},
        entries: [MAX_TRACKED]?ConnEntry = [_]?ConnEntry{null} ** MAX_TRACKED,

        const MAX_TRACKED = 64;

        const ConnEntry = struct {
            conn: *websocket.Conn,
            session_id: [64]u8 = [_]u8{0} ** 64,
            session_len: u8 = 0,
        };

        fn add(self: *ConnectionList, conn: *websocket.Conn, session_id: []const u8) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.* == null) {
                    var entry = ConnEntry{ .conn = conn };
                    const len = @min(session_id.len, 64);
                    @memcpy(entry.session_id[0..len], session_id[0..len]);
                    entry.session_len = @intCast(len);
                    slot.* = entry;
                    return true;
                }
            }
            return false;
        }

        fn remove(self: *ConnectionList, conn: *websocket.Conn) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    if (entry.conn == conn) {
                        slot.* = null;
                        return;
                    }
                }
            }
        }

        fn broadcast(self: *ConnectionList, session_id: []const u8, data: []const u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    const sid = entry.session_id[0..entry.session_len];
                    if (std.mem.eql(u8, sid, session_id)) {
                        entry.conn.write(data) catch |err| {
                            log.warn("Failed to send to WS client: {}", .{err});
                            slot.* = null;
                        };
                    }
                }
            }
        }

        fn closeAll(self: *ConnectionList) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.entries) |*slot| {
                if (slot.*) |entry| {
                    entry.conn.close(.{ .code = 1001, .reason = "server shutting down" }) catch {};
                    slot.* = null;
                }
            }
        }
    };

    // ── WebSocket Handler (used by websocket.Server) ──

    const WsHandler = struct {
        web_channel: *WebChannel,
        conn: *websocket.Conn,
        session_id: [64]u8 = [_]u8{0} ** 64,
        session_len: u8 = 0,

        pub fn init(h: *websocket.Handshake, conn: *websocket.Conn, web_channel: *WebChannel) !WsHandler {
            const url = h.url;
            const path = trimTrailingSlash(extractPath(url));
            if (!std.mem.eql(u8, path, web_channel.ws_path)) {
                log.warn("WS connection rejected: invalid path '{s}'", .{path});
                return error.Forbidden;
            }

            if (web_channel.allowed_origins.len > 0) {
                const origin = h.headers.get("origin") orelse {
                    log.warn("WS connection rejected: missing origin", .{});
                    return error.Forbidden;
                };
                if (!isOriginAllowed(web_channel.allowed_origins, origin)) {
                    log.warn("WS connection rejected: origin not allowed", .{});
                    return error.Forbidden;
                }
            }

            const auth_header = h.headers.get("authorization");
            const token = extractQueryParam(url, "token") orelse
                extractBearerToken(auth_header orelse "") orelse {
                log.warn("WS connection rejected: no token", .{});
                return error.Forbidden;
            };

            if (!web_channel.validateToken(token)) {
                log.warn("WS connection rejected: invalid token", .{});
                return error.Forbidden;
            }

            // Extract session_id from query (optional, default to "default")
            const sid_raw = extractQueryParam(url, "session_id") orelse "default";
            const sid = if (sid_raw.len == 0) "default" else sid_raw;

            var handler = WsHandler{
                .web_channel = web_channel,
                .conn = conn,
            };
            const len = @min(sid.len, 64);
            @memcpy(handler.session_id[0..len], sid[0..len]);
            handler.session_len = @intCast(len);

            if (!web_channel.connections.add(conn, sid)) {
                log.warn("WS connection rejected: connection list full", .{});
                return error.ServiceUnavailable;
            }
            log.info("WS client connected (session={s})", .{sid});

            return handler;
        }

        pub fn clientMessage(self: *WsHandler, data: []const u8) !void {
            const msg_session = self.session_id[0..self.session_len];
            self.web_channel.handleInboundEvent(data, msg_session);
        }

        pub fn close(self: *WsHandler) void {
            self.web_channel.connections.remove(self.conn);
            log.info("WS client disconnected", .{});
        }
    };
};

/// Extract a query parameter value from a URL string.
/// Returns the value slice or null if not found.
fn extractQueryParam(url: []const u8, param_name: []const u8) ?[]const u8 {
    // Find '?' start of query string
    const query_start = std.mem.indexOfScalar(u8, url, '?') orelse return null;
    var remaining = url[query_start + 1 ..];

    while (remaining.len > 0) {
        // Find end of this param (& or end of string)
        const amp = std.mem.indexOfScalar(u8, remaining, '&');
        const pair = if (amp) |i| remaining[0..i] else remaining;

        // Split on '='
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
            const key = pair[0..eq];
            const value = pair[eq + 1 ..];
            if (std.mem.eql(u8, key, param_name)) {
                return value;
            }
        }

        remaining = if (amp) |i| remaining[i + 1 ..] else &.{};
    }

    return null;
}

fn extractPath(url: []const u8) []const u8 {
    const qmark = std.mem.indexOfScalar(u8, url, '?') orelse return url;
    return url[0..qmark];
}

fn trimTrailingSlash(value: []const u8) []const u8 {
    if (value.len <= 1) return value;
    if (value[value.len - 1] == '/') return value[0 .. value.len - 1];
    return value;
}

fn isOriginAllowed(allowed_origins: []const []const u8, origin: []const u8) bool {
    const normalized_origin = trimTrailingSlash(std.mem.trim(u8, origin, " \t\r\n"));
    for (allowed_origins) |entry_raw| {
        const entry = trimTrailingSlash(std.mem.trim(u8, entry_raw, " \t\r\n"));
        if (std.mem.eql(u8, entry, "*")) return true;
        if (std.ascii.eqlIgnoreCase(entry, normalized_origin)) return true;
    }
    return false;
}

fn extractBearerToken(authorization_header: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, authorization_header, " \t\r\n");
    const prefix = "Bearer ";
    if (trimmed.len <= prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(trimmed[0..prefix.len], prefix)) return null;
    const token = std.mem.trim(u8, trimmed[prefix.len..], " \t\r\n");
    if (token.len == 0) return null;
    return token;
}

const RelayEndpoint = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

fn parseRelayEndpoint(url: []const u8) !RelayEndpoint {
    const trimmed = std.mem.trim(u8, url, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, "wss://")) return error.InvalidRelayUrl;

    const rest = trimmed["wss://".len..];
    if (rest.len == 0) return error.InvalidRelayUrl;

    const path_start = std.mem.indexOfAny(u8, rest, "/?");
    const authority = if (path_start) |idx| rest[0..idx] else rest;
    if (authority.len == 0) return error.InvalidRelayUrl;

    const path = if (path_start) |idx| blk: {
        const p = rest[idx..];
        if (p[0] != '/') return error.InvalidRelayUrl;
        break :blk p;
    } else "/ws";

    var host: []const u8 = authority;
    var port: u16 = 443;

    if (authority[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidRelayUrl;
        host = authority[1..close_idx];
        if (host.len == 0) return error.InvalidRelayUrl;
        const tail = authority[close_idx + 1 ..];
        if (tail.len > 0) {
            if (tail[0] != ':') return error.InvalidRelayUrl;
            if (tail.len == 1) return error.InvalidRelayUrl;
            port = std.fmt.parseInt(u16, tail[1..], 10) catch return error.InvalidRelayUrl;
        }
        return .{ .host = host, .port = port, .path = path };
    }

    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon_idx| {
        const host_part = authority[0..colon_idx];
        const port_part = authority[colon_idx + 1 ..];
        if (host_part.len == 0 or port_part.len == 0) return error.InvalidRelayUrl;
        if (std.mem.indexOfScalar(u8, host_part, ':') != null) return error.InvalidRelayUrl;
        host = host_part;
        port = std.fmt.parseInt(u16, port_part, 10) catch return error.InvalidRelayUrl;
    }

    if (host.len == 0 or std.mem.indexOfAny(u8, host, " \t\r\n") != null) {
        return error.InvalidRelayUrl;
    }
    return .{ .host = host, .port = port, .path = path };
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

test "WebChannel initFromConfig uses defaults" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expectEqual(WebChannel.WebTransport.local, ch.transport);
    try std.testing.expectEqual(@as(u16, 32123), ch.port);
    try std.testing.expectEqualStrings("127.0.0.1", ch.listen_address);
    try std.testing.expectEqualStrings(config_types.WebConfig.DEFAULT_PATH, ch.ws_path);
    try std.testing.expectEqual(@as(u16, 10), ch.max_connections);
    try std.testing.expectEqualStrings("default", ch.account_id);
    try std.testing.expect(ch.configured_auth_token == null);
    try std.testing.expectEqual(@as(usize, 0), ch.allowed_origins.len);
    try std.testing.expect(ch.relay_url == null);
    try std.testing.expectEqualStrings("default", ch.relay_agent_id);
    try std.testing.expect(ch.configured_relay_token == null);
    try std.testing.expect(ch.bus == null);
    try std.testing.expect(!ch.running.load(.acquire));
}

test "WebChannel initFromConfig uses custom values" {
    const origins = [_][]const u8{
        "http://localhost:5173",
        "chrome-extension://testid",
    };
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .port = 8080,
        .listen = "0.0.0.0",
        .path = "/relay/",
        .max_connections = 5,
        .account_id = "web-main",
        .auth_token = "test-token-123456",
        .allowed_origins = &origins,
    });
    try std.testing.expectEqual(@as(u16, 8080), ch.port);
    try std.testing.expectEqualStrings("0.0.0.0", ch.listen_address);
    try std.testing.expectEqualStrings("/relay", ch.ws_path);
    try std.testing.expectEqual(@as(u16, 5), ch.max_connections);
    try std.testing.expectEqualStrings("web-main", ch.account_id);
    try std.testing.expectEqualStrings("test-token-123456", ch.configured_auth_token.?);
    try std.testing.expectEqual(@as(usize, 2), ch.allowed_origins.len);
}

test "WebChannel initFromConfig maps relay transport settings" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .transport = "relay",
        .relay_url = "wss://relay.nullclaw.io/ws/agent",
        .relay_agent_id = "edge-1",
        .relay_token = "relay-token-123456",
    });
    try std.testing.expectEqual(WebChannel.WebTransport.relay, ch.transport);
    try std.testing.expectEqualStrings("wss://relay.nullclaw.io/ws/agent", ch.relay_url.?);
    try std.testing.expectEqualStrings("edge-1", ch.relay_agent_id);
    try std.testing.expectEqualStrings("relay-token-123456", ch.configured_relay_token.?);
}

test "WebChannel initFromConfig falls back to default path for invalid value" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .path = "relay",
    });
    try std.testing.expectEqualStrings(config_types.WebConfig.DEFAULT_PATH, ch.ws_path);
}

test "WebChannel initFromConfig clamps max_connections to tracked limit" {
    const ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .max_connections = 500,
    });
    try std.testing.expectEqual(@as(u16, 64), ch.max_connections);
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
    try std.testing.expectEqual(@as(usize, 64), ch.token_len);
    for (ch.token[0..ch.token_len]) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "WebChannel validateToken accepts correct token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    try std.testing.expect(ch.validateToken(ch.token[0..ch.token_len]));
}

test "WebChannel validateToken rejects wrong token" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    ch.generateToken();
    var bad_token: [64]u8 = undefined;
    @memset(&bad_token, 'x');
    try std.testing.expect(!ch.validateToken(bad_token[0..]));
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
    try std.testing.expect(!std.mem.eql(u8, ch1.token[0..ch1.token_len], ch2.token[0..ch2.token_len]));
}

test "extractQueryParam finds token" {
    try std.testing.expectEqualStrings("abc123", extractQueryParam("/ws?token=abc123", "token").?);
}

test "extractQueryParam finds param among multiple" {
    try std.testing.expectEqualStrings("hello", extractQueryParam("/ws?token=abc&session_id=hello", "session_id").?);
    try std.testing.expectEqualStrings("abc", extractQueryParam("/ws?token=abc&session_id=hello", "token").?);
}

test "extractQueryParam returns null for missing param" {
    try std.testing.expect(extractQueryParam("/ws?token=abc", "session_id") == null);
    try std.testing.expect(extractQueryParam("/ws", "token") == null);
    try std.testing.expect(extractQueryParam("/ws?", "token") == null);
}

test "extractPath strips query" {
    try std.testing.expectEqualStrings("/ws", extractPath("/ws?token=abc"));
    try std.testing.expectEqualStrings("/relay", extractPath("/relay"));
}

test "isOriginAllowed handles exact wildcard and slash normalization" {
    const allowed = [_][]const u8{
        "http://localhost:5173/",
        "chrome-extension://abc",
    };
    try std.testing.expect(isOriginAllowed(&allowed, "http://localhost:5173"));
    try std.testing.expect(isOriginAllowed(&allowed, "chrome-extension://abc/"));
    try std.testing.expect(!isOriginAllowed(&allowed, "https://example.com"));

    const wildcard = [_][]const u8{"*"};
    try std.testing.expect(isOriginAllowed(&wildcard, "https://anything.example"));
}

test "extractBearerToken parses bearer auth header" {
    try std.testing.expectEqualStrings("tok123", extractBearerToken("Bearer tok123").?);
    try std.testing.expectEqualStrings("tok123", extractBearerToken("bearer tok123").?);
    try std.testing.expect(extractBearerToken("Basic abc") == null);
    try std.testing.expect(extractBearerToken("") == null);
}

test "parseRelayEndpoint parses host path and default port" {
    const ep = try parseRelayEndpoint("wss://relay.nullclaw.io/ws/agent");
    try std.testing.expectEqualStrings("relay.nullclaw.io", ep.host);
    try std.testing.expectEqual(@as(u16, 443), ep.port);
    try std.testing.expectEqualStrings("/ws/agent", ep.path);
}

test "parseRelayEndpoint parses explicit port" {
    const ep = try parseRelayEndpoint("wss://relay.nullclaw.io:9443/ws");
    try std.testing.expectEqualStrings("relay.nullclaw.io", ep.host);
    try std.testing.expectEqual(@as(u16, 9443), ep.port);
    try std.testing.expectEqualStrings("/ws", ep.path);
}

test "parseRelayEndpoint rejects non-wss URL" {
    try std.testing.expectError(error.InvalidRelayUrl, parseRelayEndpoint("https://relay.nullclaw.io/ws"));
    try std.testing.expectError(error.InvalidRelayUrl, parseRelayEndpoint("ws://relay.nullclaw.io/ws"));
}

test "WebChannel setActiveToken rejects non url-safe tokens" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{});
    try std.testing.expectError(error.InvalidAuthToken, ch.setActiveToken("bad token with spaces"));
}

test "ConnectionList add and remove" {
    const list = WebChannel.ConnectionList{};
    // We can't create real websocket.Conn in tests, but we can verify the structure compiles
    try std.testing.expectEqual(@as(usize, 64), list.entries.len);
}

test "WsHandler clientMessage uses connection session id" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .account_id = "web-main",
    });
    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);

    var handler = WebChannel.WsHandler{
        .web_channel = &ch,
        .conn = undefined,
    };
    const connection_sid = "conn-session";
    @memcpy(handler.session_id[0..connection_sid.len], connection_sid);
    handler.session_len = @intCast(connection_sid.len);

    try handler.clientMessage("{\"content\":\"hello\",\"session_id\":\"other-session\",\"sender_id\":\"user-1\"}");

    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());
    const msg = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("conn-session", msg.chat_id);
    try std.testing.expectEqualStrings("web:web-main:direct:conn-session", msg.session_key);
}

test "WebChannel handleInboundEvent parses v1 envelope payload" {
    var ch = WebChannel.initFromConfig(std.testing.allocator, .{
        .account_id = "web-main",
    });
    var bus = bus_mod.Bus.init();
    ch.setBus(&bus);

    const event =
        \\{"v":1,"type":"user_message","session_id":"sess-42","request_id":"req-7","payload":{"content":"hello from ui","sender_id":"ui-1"}}
    ;
    ch.handleInboundEvent(event, null);

    try std.testing.expectEqual(@as(usize, 1), bus.inboundDepth());
    const msg = bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("sess-42", msg.chat_id);
    try std.testing.expectEqualStrings("ui-1", msg.sender_id);
    try std.testing.expect(msg.metadata_json != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"request_id\":\"req-7\"") != null);
}

test {
    @import("std").testing.refAllDecls(@This());
}
