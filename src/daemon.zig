//! Daemon — main event loop with component supervision.
//!
//! Mirrors ZeroClaw's daemon module:
//!   - Spawns gateway, channels, heartbeat, scheduler
//!   - Exponential backoff on component failure
//!   - Periodic state file writing (daemon_state.json)
//!   - Ctrl+C graceful shutdown

const std = @import("std");
const health = @import("health.zig");
const Config = @import("config.zig").Config;
const CronScheduler = @import("cron.zig").CronScheduler;
const cron = @import("cron.zig");
const bus_mod = @import("bus.zig");
const dispatch = @import("channels/dispatch.zig");
const channel_loop = @import("channel_loop.zig");
const channel_manager = @import("channel_manager.zig");
const agent_routing = @import("agent_routing.zig");

const log = std.log.scoped(.daemon);

/// How often the daemon state file is flushed (seconds).
const STATUS_FLUSH_SECONDS: u64 = 5;

/// Maximum number of supervised components.
const MAX_COMPONENTS: usize = 8;

/// Component status for state file serialization.
pub const ComponentStatus = struct {
    name: []const u8,
    running: bool = false,
    restart_count: u64 = 0,
    last_error: ?[]const u8 = null,
};

/// Daemon state written to daemon_state.json periodically.
pub const DaemonState = struct {
    started: bool = false,
    gateway_host: []const u8 = "127.0.0.1",
    gateway_port: u16 = 3000,
    components: [MAX_COMPONENTS]?ComponentStatus = .{null} ** MAX_COMPONENTS,
    component_count: usize = 0,

    pub fn addComponent(self: *DaemonState, name: []const u8) void {
        if (self.component_count < MAX_COMPONENTS) {
            self.components[self.component_count] = .{ .name = name, .running = true };
            self.component_count += 1;
        }
    }

    pub fn markError(self: *DaemonState, name: []const u8, err_msg: []const u8) void {
        for (self.components[0..self.component_count]) |*comp_opt| {
            if (comp_opt.*) |*comp| {
                if (std.mem.eql(u8, comp.name, name)) {
                    comp.running = false;
                    comp.last_error = err_msg;
                    comp.restart_count += 1;
                    return;
                }
            }
        }
    }

    pub fn markRunning(self: *DaemonState, name: []const u8) void {
        for (self.components[0..self.component_count]) |*comp_opt| {
            if (comp_opt.*) |*comp| {
                if (std.mem.eql(u8, comp.name, name)) {
                    comp.running = true;
                    comp.last_error = null;
                    return;
                }
            }
        }
    }
};

/// Compute the path to daemon_state.json from config.
pub fn stateFilePath(allocator: std.mem.Allocator, config: *const Config) ![]u8 {
    // Use config directory (parent of config_path)
    if (std.fs.path.dirname(config.config_path)) |dir| {
        return std.fs.path.join(allocator, &.{ dir, "daemon_state.json" });
    }
    return allocator.dupe(u8, "daemon_state.json");
}

/// Write daemon state to disk as JSON.
pub fn writeStateFile(allocator: std.mem.Allocator, path: []const u8, state: *const DaemonState) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\n");
    try buf.appendSlice(allocator, "  \"status\": \"running\",\n");
    try std.fmt.format(buf.writer(allocator), "  \"gateway\": \"{s}:{d}\",\n", .{ state.gateway_host, state.gateway_port });

    // Components array
    try buf.appendSlice(allocator, "  \"components\": [\n");
    var first = true;
    for (state.components[0..state.component_count]) |comp_opt| {
        if (comp_opt) |comp| {
            if (!first) try buf.appendSlice(allocator, ",\n");
            first = false;
            try std.fmt.format(buf.writer(allocator),
                \\    {{"name": "{s}", "running": {}, "restart_count": {d}}}
            , .{ comp.name, comp.running, comp.restart_count });
        }
    }
    try buf.appendSlice(allocator, "\n  ]\n}\n");

    const file = try std.fs.createFileAbsolute(path, .{});
    defer file.close();
    try file.writeAll(buf.items);
}

/// Compute exponential backoff duration.
pub fn computeBackoff(current_backoff: u64, max_backoff: u64) u64 {
    const doubled = current_backoff *| 2;
    return @min(doubled, max_backoff);
}

/// Check if any real-time channels are configured.
pub fn hasSupervisedChannels(config: *const Config) bool {
    return config.channels.telegram.len > 0 or
        config.channels.discord.len > 0 or
        config.channels.slack.len > 0 or
        config.channels.imessage != null or
        config.channels.matrix != null or
        config.channels.whatsapp != null or
        config.channels.signal.len > 0 or
        config.channels.irc != null or
        config.channels.lark != null or
        config.channels.dingtalk != null or
        config.channels.email != null or
        config.channels.line != null or
        config.channels.qq.len > 0 or
        config.channels.onebot.len > 0 or
        config.channels.maixcam.len > 0;
}

/// Shutdown signal — set to true to stop the daemon.
var shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Request a graceful shutdown of the daemon.
pub fn requestShutdown() void {
    shutdown_requested.store(true, .release);
}

/// Check if shutdown has been requested.
pub fn isShutdownRequested() bool {
    return shutdown_requested.load(.acquire);
}

/// Gateway thread entry point.
fn gatewayThread(allocator: std.mem.Allocator, config: *const Config, host: []const u8, port: u16, state: *DaemonState, event_bus: *bus_mod.Bus) void {
    const gateway = @import("gateway.zig");
    gateway.run(allocator, host, port, config, event_bus) catch |err| {
        state.markError("gateway", @errorName(err));
        health.markComponentError("gateway", @errorName(err));
        return;
    };
}

/// Heartbeat thread — periodically writes state file and checks health.
fn heartbeatThread(allocator: std.mem.Allocator, config: *const Config, state: *DaemonState) void {
    const state_path = stateFilePath(allocator, config) catch return;
    defer allocator.free(state_path);

    while (!isShutdownRequested()) {
        writeStateFile(allocator, state_path, state) catch {};
        health.markComponentOk("heartbeat");
        std.Thread.sleep(STATUS_FLUSH_SECONDS * std.time.ns_per_s);
    }
}

/// Initial backoff for scheduler restarts (seconds).
const SCHEDULER_INITIAL_BACKOFF_SECS: u64 = 1;

/// Maximum backoff for scheduler restarts (seconds).
const SCHEDULER_MAX_BACKOFF_SECS: u64 = 60;

/// How often the channel watcher checks health (seconds).
const CHANNEL_WATCH_INTERVAL_SECS: u64 = 60;

/// Scheduler supervision thread — loads cron jobs and runs the scheduler loop.
/// On error (scheduler crash), logs and restarts with exponential backoff.
fn schedulerThread(allocator: std.mem.Allocator, config: *const Config, state: *DaemonState, event_bus: *bus_mod.Bus) void {
    var backoff_secs: u64 = SCHEDULER_INITIAL_BACKOFF_SECS;

    while (!isShutdownRequested()) {
        var scheduler = CronScheduler.init(allocator, config.scheduler.max_tasks, config.scheduler.enabled);
        defer scheduler.deinit();

        // Load persisted jobs (ignore errors — fresh start if file missing)
        cron.loadJobs(&scheduler) catch {};

        state.markRunning("scheduler");
        health.markComponentOk("scheduler");

        // run() blocks forever (while(true) loop) — if it returns, something went wrong.
        // Since run() can't actually return an error (it catches internally), we treat
        // any return from run() as an unexpected exit.
        scheduler.run(config.reliability.scheduler_poll_secs, event_bus);

        // If we reach here, scheduler exited unexpectedly
        if (isShutdownRequested()) break;

        state.markError("scheduler", "unexpected exit");
        health.markComponentError("scheduler", "unexpected exit");

        // Exponential backoff before restart
        std.Thread.sleep(backoff_secs * std.time.ns_per_s);
        backoff_secs = computeBackoff(backoff_secs, SCHEDULER_MAX_BACKOFF_SECS);
    }
}

/// Stale detection threshold: 3x the Telegram long-poll timeout (30s).
const STALE_THRESHOLD_SECS: i64 = 90;

/// Channel supervisor thread — spawns polling threads for configured channels,
/// monitors their health, and restarts on failure using SupervisedChannel.
fn channelSupervisorThread(
    allocator: std.mem.Allocator,
    config: *const Config,
    state: *DaemonState,
    channel_registry: *dispatch.ChannelRegistry,
    channel_rt: ?*channel_loop.ChannelRuntime,
    event_bus: *bus_mod.Bus,
) void {
    var mgr = channel_manager.ChannelManager.init(allocator, config, channel_registry) catch {
        state.markError("channels", "init_failed");
        health.markComponentError("channels", "init_failed");
        return;
    };
    defer mgr.deinit();

    if (channel_rt) |rt| mgr.setRuntime(rt);
    mgr.setEventBus(event_bus);

    mgr.collectConfiguredChannels() catch |err| {
        state.markError("channels", @errorName(err));
        health.markComponentError("channels", @errorName(err));
        return;
    };

    const started = mgr.startAll() catch |err| {
        state.markError("channels", @errorName(err));
        health.markComponentError("channels", @errorName(err));
        return;
    };

    if (started > 0) {
        state.markRunning("channels");
        health.markComponentOk("channels");
        mgr.supervisionLoop(state); // blocks until shutdown
    } else {
        health.markComponentOk("channels");
    }
}

/// Inbound dispatcher thread:
/// consumes inbound events from channels, runs SessionManager, publishes outbound replies.
fn resolveInboundRouteSessionKey(
    allocator: std.mem.Allocator,
    config: *const Config,
    msg: *const bus_mod.InboundMessage,
) ?[]const u8 {
    var account_id: []const u8 = "default";
    var has_account_id_meta = false;
    var peer: ?agent_routing.PeerRef = null;
    var guild_id: ?[]const u8 = null;
    var is_dm_meta: ?bool = null;
    var is_group_meta: ?bool = null;
    var channel_id_meta: ?[]const u8 = null;
    const maixcam_name = if (config.channels.maixcamPrimary()) |mc| mc.name else "maixcam";

    var parsed_meta: ?std.json.Parsed(std.json.Value) = null;
    defer if (parsed_meta) |*pm| pm.deinit();
    if (msg.metadata_json) |meta_json| {
        parsed_meta = std.json.parseFromSlice(std.json.Value, allocator, meta_json, .{}) catch null;
        if (parsed_meta) |*pm| {
            if (pm.value == .object) {
                if (pm.value.object.get("account_id") orelse pm.value.object.get("accountId")) |v| {
                    if (v == .string) {
                        account_id = v.string;
                        has_account_id_meta = true;
                    }
                }
                if (pm.value.object.get("guild_id") orelse pm.value.object.get("guildId")) |v| {
                    if (v == .string) guild_id = v.string;
                }
                if (pm.value.object.get("channel_id")) |v| {
                    if (v == .string) channel_id_meta = v.string;
                }
                if (pm.value.object.get("is_dm")) |v| {
                    if (v == .bool) is_dm_meta = v.bool;
                }
                if (pm.value.object.get("is_group")) |v| {
                    if (v == .bool) is_group_meta = v.bool;
                }
            }
        }
    }

    if (!has_account_id_meta) {
        if (std.mem.eql(u8, msg.channel, "discord")) {
            if (config.channels.discordPrimary()) |dc| account_id = dc.account_id;
        } else if (std.mem.eql(u8, msg.channel, "qq")) {
            if (config.channels.qqPrimary()) |qc| account_id = qc.account_id;
        } else if (std.mem.eql(u8, msg.channel, "onebot")) {
            if (config.channels.onebotPrimary()) |oc| account_id = oc.account_id;
        } else if (std.mem.eql(u8, msg.channel, "maixcam") or std.mem.eql(u8, msg.channel, maixcam_name)) {
            if (config.channels.maixcamPrimary()) |mc| account_id = mc.account_id;
        }
    }

    if (std.mem.eql(u8, msg.channel, "discord")) {
        const is_dm = is_dm_meta orelse (guild_id == null);
        peer = .{
            .kind = if (is_dm) .direct else .channel,
            .id = if (is_dm) msg.sender_id else msg.chat_id,
        };
    } else if (std.mem.eql(u8, msg.channel, "qq")) {
        const is_dm = is_dm_meta orelse std.mem.startsWith(u8, msg.chat_id, "dm:");
        const raw_channel = channel_id_meta orelse msg.chat_id;
        const channel_id = if (std.mem.startsWith(u8, raw_channel, "channel:"))
            raw_channel["channel:".len..]
        else
            raw_channel;
        peer = .{
            .kind = if (is_dm) .direct else .channel,
            .id = if (is_dm) msg.sender_id else channel_id,
        };
    } else if (std.mem.eql(u8, msg.channel, "onebot")) {
        if (std.mem.startsWith(u8, msg.chat_id, "group:")) {
            peer = .{ .kind = .group, .id = msg.chat_id["group:".len..] };
        } else if (is_group_meta orelse false) {
            peer = .{ .kind = .group, .id = msg.chat_id };
        } else {
            peer = .{ .kind = .direct, .id = msg.sender_id };
        }
    } else if (std.mem.eql(u8, msg.channel, "maixcam") or std.mem.eql(u8, msg.channel, maixcam_name)) {
        peer = .{ .kind = .direct, .id = msg.chat_id };
    } else {
        return null;
    }

    const route = agent_routing.resolveRoute(allocator, .{
        .channel = msg.channel,
        .account_id = account_id,
        .peer = peer,
        .guild_id = guild_id,
    }, config.agent_bindings, config.agents) catch return null;
    allocator.free(route.main_session_key);
    return route.session_key;
}

fn inboundDispatcherThread(
    allocator: std.mem.Allocator,
    event_bus: *bus_mod.Bus,
    runtime: *channel_loop.ChannelRuntime,
    state: *DaemonState,
) void {
    var evict_counter: u32 = 0;

    while (event_bus.consumeInbound()) |msg| {
        defer msg.deinit(allocator);

        const routed_session_key = resolveInboundRouteSessionKey(allocator, runtime.config, &msg);
        defer if (routed_session_key) |key| allocator.free(key);
        const session_key = routed_session_key orelse msg.session_key;

        const reply = runtime.session_mgr.processMessage(session_key, msg.content) catch |err| {
            log.warn("inbound dispatch process failed: {}", .{err});

            // Send user-visible error reply back to the originating channel
            const err_msg: []const u8 = switch (err) {
                error.CurlFailed, error.CurlReadError, error.CurlWaitError => "Network error. Please try again.",
                error.ProviderDoesNotSupportVision => "The current provider does not support image input.",
                error.OutOfMemory => "Out of memory.",
                else => "An error occurred. Try again.",
            };
            const err_out = bus_mod.makeOutbound(allocator, msg.channel, msg.chat_id, err_msg) catch continue;
            event_bus.publishOutbound(err_out) catch {
                err_out.deinit(allocator);
            };
            continue;
        };
        defer allocator.free(reply);

        const out = bus_mod.makeOutbound(allocator, msg.channel, msg.chat_id, reply) catch |err| {
            log.err("inbound dispatch makeOutbound failed: {}", .{err});
            continue;
        };

        event_bus.publishOutbound(out) catch |err| {
            out.deinit(allocator);
            if (err == error.Closed) break;
            log.err("inbound dispatch publishOutbound failed: {}", .{err});
            continue;
        };

        state.markRunning("inbound_dispatcher");
        health.markComponentOk("inbound_dispatcher");

        // Periodic session eviction for bus-based channels
        evict_counter += 1;
        if (evict_counter >= 100) {
            evict_counter = 0;
            _ = runtime.session_mgr.evictIdle(runtime.config.agent.session_idle_timeout_secs);
        }
    }
}

/// Run the daemon. This is the main entry point for `nullclaw daemon`.
/// Spawns threads for gateway, heartbeat, and channels, then loops until
/// shutdown is requested (Ctrl+C signal or explicit request).
/// `host` and `port` are CLI-parsed values that override `config.gateway`.
pub fn run(allocator: std.mem.Allocator, config: *const Config, host: []const u8, port: u16) !void {
    health.markComponentOk("daemon");
    shutdown_requested.store(false, .release);

    var state = DaemonState{
        .started = true,
        .gateway_host = host,
        .gateway_port = port,
    };
    state.addComponent("gateway");

    if (hasSupervisedChannels(config)) {
        state.addComponent("channels");
    } else {
        health.markComponentOk("channels");
    }

    if (config.heartbeat.enabled) {
        state.addComponent("heartbeat");
    }

    state.addComponent("scheduler");

    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &bw.interface;
    try stdout.print("nullclaw daemon started\n", .{});
    try stdout.print("  Gateway:  http://{s}:{d}\n", .{ state.gateway_host, state.gateway_port });
    try stdout.print("  Components: {d} active\n", .{state.component_count});
    try stdout.print("  Ctrl+C to stop\n\n", .{});
    try stdout.flush();

    // Write initial state file
    const state_path = try stateFilePath(allocator, config);
    defer allocator.free(state_path);
    writeStateFile(allocator, state_path, &state) catch |err| {
        try stdout.print("Warning: could not write state file: {}\n", .{err});
    };

    // Event bus (created before gateway+scheduler so all threads can publish)
    var event_bus = bus_mod.Bus.init();

    // Spawn gateway thread
    state.markRunning("gateway");
    const gw_thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, gatewayThread, .{ allocator, config, host, port, &state, &event_bus }) catch |err| {
        state.markError("gateway", @errorName(err));
        try stdout.print("Failed to spawn gateway: {}\n", .{err});
        return err;
    };

    // Spawn heartbeat thread
    var hb_thread: ?std.Thread = null;
    if (config.heartbeat.enabled) {
        state.markRunning("heartbeat");
        if (std.Thread.spawn(.{ .stack_size = 128 * 1024 }, heartbeatThread, .{ allocator, config, &state })) |thread| {
            hb_thread = thread;
        } else |err| {
            state.markError("heartbeat", @errorName(err));
            stdout.print("Warning: heartbeat thread failed: {}\n", .{err}) catch {};
        }
    }

    // Spawn scheduler thread
    var sched_thread: ?std.Thread = null;
    if (config.scheduler.enabled) {
        state.markRunning("scheduler");
        if (std.Thread.spawn(.{ .stack_size = 256 * 1024 }, schedulerThread, .{ allocator, config, &state, &event_bus })) |thread| {
            sched_thread = thread;
        } else |err| {
            state.markError("scheduler", @errorName(err));
            stdout.print("Warning: scheduler thread failed: {}\n", .{err}) catch {};
        }
    }

    // Outbound dispatcher (created before supervisor so channels can register)
    var channel_registry = dispatch.ChannelRegistry.init(allocator);
    defer channel_registry.deinit();

    // Channel runtime for supervised polling (provider, tools, sessions)
    var channel_rt: ?*channel_loop.ChannelRuntime = null;
    if (hasSupervisedChannels(config)) {
        channel_rt = channel_loop.ChannelRuntime.init(allocator, config) catch |err| blk: {
            stdout.print("Warning: channel runtime init failed: {}\n", .{err}) catch {};
            state.markError("channels", @errorName(err));
            break :blk null;
        };
    }
    defer if (channel_rt) |rt| rt.deinit();

    // Spawn channel supervisor thread (only if channels are configured)
    var chan_thread: ?std.Thread = null;
    if (hasSupervisedChannels(config)) {
        if (std.Thread.spawn(.{ .stack_size = 256 * 1024 }, channelSupervisorThread, .{
            allocator, config, &state, &channel_registry, channel_rt, &event_bus,
        })) |thread| {
            chan_thread = thread;
        } else |err| {
            state.markError("channels", @errorName(err));
            stdout.print("Warning: channel supervisor thread failed: {}\n", .{err}) catch {};
        }
    }

    var inbound_thread: ?std.Thread = null;
    if (channel_rt) |rt| {
        state.addComponent("inbound_dispatcher");
        if (std.Thread.spawn(.{ .stack_size = 512 * 1024 }, inboundDispatcherThread, .{
            allocator, &event_bus, rt, &state,
        })) |thread| {
            inbound_thread = thread;
            state.markRunning("inbound_dispatcher");
            health.markComponentOk("inbound_dispatcher");
        } else |err| {
            state.markError("inbound_dispatcher", @errorName(err));
            stdout.print("Warning: inbound dispatcher thread failed: {}\n", .{err}) catch {};
        }
    }

    var dispatch_stats = dispatch.DispatchStats{};

    state.addComponent("outbound_dispatcher");

    var dispatcher_thread: ?std.Thread = null;
    if (std.Thread.spawn(.{ .stack_size = 512 * 1024 }, dispatch.runOutboundDispatcher, .{
        allocator, &event_bus, &channel_registry, &dispatch_stats,
    })) |thread| {
        dispatcher_thread = thread;
        state.markRunning("outbound_dispatcher");
        health.markComponentOk("outbound_dispatcher");
    } else |err| {
        state.markError("outbound_dispatcher", @errorName(err));
        stdout.print("Warning: outbound dispatcher thread failed: {}\n", .{err}) catch {};
    }

    // Main thread: wait for shutdown signal (poll-based)
    while (!isShutdownRequested()) {
        std.Thread.sleep(1 * std.time.ns_per_s);
    }

    try stdout.print("\nShutting down...\n", .{});

    // Close bus to signal dispatcher to exit
    event_bus.close();

    // Write final state
    state.markError("gateway", "shutting down");
    writeStateFile(allocator, state_path, &state) catch {};

    // Wait for threads
    if (inbound_thread) |t| t.join();
    if (dispatcher_thread) |t| t.join();
    if (chan_thread) |t| t.join();
    if (sched_thread) |t| t.join();
    if (hb_thread) |t| t.join();
    gw_thread.join();

    try stdout.print("nullclaw daemon stopped.\n", .{});
}

// ── Tests ────────────────────────────────────────────────────────

test "DaemonState addComponent" {
    var state = DaemonState{};
    state.addComponent("gateway");
    state.addComponent("channels");
    try std.testing.expectEqual(@as(usize, 2), state.component_count);
    try std.testing.expectEqualStrings("gateway", state.components[0].?.name);
    try std.testing.expectEqualStrings("channels", state.components[1].?.name);
}

test "DaemonState markError and markRunning" {
    var state = DaemonState{};
    state.addComponent("gateway");
    state.markError("gateway", "connection refused");
    try std.testing.expect(!state.components[0].?.running);
    try std.testing.expectEqual(@as(u64, 1), state.components[0].?.restart_count);
    try std.testing.expectEqualStrings("connection refused", state.components[0].?.last_error.?);

    state.markRunning("gateway");
    try std.testing.expect(state.components[0].?.running);
    try std.testing.expect(state.components[0].?.last_error == null);
}

test "computeBackoff doubles up to max" {
    try std.testing.expectEqual(@as(u64, 4), computeBackoff(2, 60));
    try std.testing.expectEqual(@as(u64, 60), computeBackoff(32, 60));
    try std.testing.expectEqual(@as(u64, 60), computeBackoff(60, 60));
}

test "computeBackoff saturating" {
    try std.testing.expectEqual(std.math.maxInt(u64), computeBackoff(std.math.maxInt(u64), std.math.maxInt(u64)));
}

test "hasSupervisedChannels false for defaults" {
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
    };
    try std.testing.expect(!hasSupervisedChannels(&config));
}

test "resolveInboundRouteSessionKey falls back to configured account_id" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "onebot-agent",
            .match = .{
                .channel = "onebot",
                .account_id = "onebot-main",
                .peer = .{ .kind = .direct, .id = "12345" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .onebot = &[_]@import("config_types.zig").OneBotConfig{.{
                .account_id = "onebot-main",
            }},
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "onebot",
        .sender_id = "12345",
        .chat_id = "12345",
        .content = "hello",
        .session_key = "onebot:12345",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:onebot-agent:onebot:direct:12345", routed.?);
}

test "resolveInboundRouteSessionKey supports custom maixcam channel name" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "camera-agent",
            .match = .{
                .channel = "vision-cam",
                .account_id = "cam-main",
                .peer = .{ .kind = .direct, .id = "device-1" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .maixcam = &[_]@import("config_types.zig").MaixCamConfig{.{
                .name = "vision-cam",
                .account_id = "cam-main",
            }},
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "vision-cam",
        .sender_id = "device-1",
        .chat_id = "device-1",
        .content = "person detected",
        .session_key = "vision-cam:device-1",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:camera-agent:vision-cam:direct:device-1", routed.?);
}

test "stateFilePath derives from config_path" {
    const config = Config{
        .workspace_dir = "/tmp/workspace",
        .config_path = "/home/user/.nullclaw/config.json",
        .allocator = std.testing.allocator,
    };
    const path = try stateFilePath(std.testing.allocator, &config);
    defer std.testing.allocator.free(path);
    const expected = try std.fs.path.join(std.testing.allocator, &.{ "/home/user/.nullclaw", "daemon_state.json" });
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, path);
}

test "scheduler backoff constants" {
    try std.testing.expectEqual(@as(u64, 1), SCHEDULER_INITIAL_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 60), SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 60), CHANNEL_WATCH_INTERVAL_SECS);
}

test "scheduler backoff progression" {
    var backoff: u64 = SCHEDULER_INITIAL_BACKOFF_SECS;
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 2), backoff);
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 4), backoff);
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 8), backoff);
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 16), backoff);
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 32), backoff);
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 60), backoff); // capped at max
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 60), backoff); // stays at max
}

test "channelSupervisorThread respects shutdown" {
    // Pre-request shutdown so the supervisor exits immediately
    shutdown_requested.store(true, .release);
    defer shutdown_requested.store(false, .release);

    // Config with no telegram → supervisor goes straight to idle loop → exits on shutdown
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
    };

    var state = DaemonState{};
    state.addComponent("channels");

    var channel_registry = dispatch.ChannelRegistry.init(std.testing.allocator);
    defer channel_registry.deinit();
    var event_bus = bus_mod.Bus.init();

    const thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, channelSupervisorThread, .{
        std.testing.allocator, &config, &state, &channel_registry, null, &event_bus,
    });
    thread.join();

    // Channel component should have been marked running before the loop
    try std.testing.expect(state.components[0].?.running);
}

test "DaemonState supports all supervised components" {
    var state = DaemonState{};
    state.addComponent("gateway");
    state.addComponent("channels");
    state.addComponent("heartbeat");
    state.addComponent("scheduler");
    try std.testing.expectEqual(@as(usize, 4), state.component_count);
    try std.testing.expectEqualStrings("scheduler", state.components[3].?.name);
    try std.testing.expect(state.components[3].?.running);
}

test "writeStateFile produces valid content" {
    var state = DaemonState{
        .started = true,
        .gateway_host = "127.0.0.1",
        .gateway_port = 8080,
    };
    state.addComponent("test-comp");

    // Write to a temp path
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir);
    const path = try std.fs.path.join(std.testing.allocator, &.{ dir, "daemon_state.json" });
    defer std.testing.allocator.free(path);

    try writeStateFile(std.testing.allocator, path, &state);

    // Read back and verify
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"status\": \"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "test-comp") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "127.0.0.1:8080") != null);
}
