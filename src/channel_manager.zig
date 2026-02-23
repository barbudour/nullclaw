//! Channel Manager — centralizes channel lifecycle (init, start, supervise, stop).
//!
//! Replaces the hardcoded Telegram/Signal-only logic in daemon.zig with a
//! generic system that handles all configured channels.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bus_mod = @import("bus.zig");
const Config = @import("config.zig").Config;
const dispatch = @import("channels/dispatch.zig");
const channel_loop = @import("channel_loop.zig");
const health = @import("health.zig");
const daemon = @import("daemon.zig");

// Channel modules
const telegram = @import("channels/telegram.zig");
const signal_ch = @import("channels/signal.zig");
const discord = @import("channels/discord.zig");
const qq = @import("channels/qq.zig");
const onebot = @import("channels/onebot.zig");
const slack = @import("channels/slack.zig");
const matrix = @import("channels/matrix.zig");
const irc = @import("channels/irc.zig");
const imessage = @import("channels/imessage.zig");
const email = @import("channels/email.zig");
const dingtalk = @import("channels/dingtalk.zig");
const maixcam = @import("channels/maixcam.zig");
const whatsapp = @import("channels/whatsapp.zig");
const line = @import("channels/line.zig");
const lark = @import("channels/lark.zig");

// Channel type from channels/root.zig
const Channel = @import("channels/root.zig").Channel;

const log = std.log.scoped(.channel_manager);

pub const ListenerType = enum {
    /// Telegram, Signal — poll in a loop
    polling,
    /// Discord, QQ, OneBot — internal WebSocket/gateway
    gateway_loop,
    /// WhatsApp, Line, Lark — HTTP gateway receives
    webhook_only,
    /// Outbound-only channel lifecycle (start/stop/send, no inbound listener thread yet)
    send_only,
    /// Channel exists but no listener yet
    not_implemented,
};

pub const Entry = struct {
    name: []const u8,
    account_id: []const u8 = "default",
    channel: Channel,
    listener_type: ListenerType,
    supervised: dispatch.SupervisedChannel,
    thread: ?std.Thread = null,
    polling_state: ?PollingState = null,
};

pub const PollingState = union(enum) {
    telegram: *channel_loop.TelegramLoopState,
    signal: *channel_loop.SignalLoopState,
};

pub const ChannelManager = struct {
    allocator: Allocator,
    config: *const Config,
    registry: *dispatch.ChannelRegistry,
    runtime: ?*channel_loop.ChannelRuntime = null,
    event_bus: ?*bus_mod.Bus = null,
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    pub fn init(allocator: Allocator, config: *const Config, registry: *dispatch.ChannelRegistry) !*ChannelManager {
        const self = try allocator.create(ChannelManager);
        self.* = .{
            .allocator = allocator,
            .config = config,
            .registry = registry,
        };
        return self;
    }

    pub fn deinit(self: *ChannelManager) void {
        // Stop all threads
        self.stopAll();

        self.entries.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn setRuntime(self: *ChannelManager, rt: *channel_loop.ChannelRuntime) void {
        self.runtime = rt;
    }

    pub fn setEventBus(self: *ChannelManager, eb: *bus_mod.Bus) void {
        self.event_bus = eb;
    }

    fn pollingLastActivity(state: PollingState) i64 {
        return switch (state) {
            .telegram => |ls| ls.last_activity.load(.acquire),
            .signal => |ls| ls.last_activity.load(.acquire),
        };
    }

    fn requestPollingStop(state: PollingState) void {
        switch (state) {
            .telegram => |ls| ls.stop_requested.store(true, .release),
            .signal => |ls| ls.stop_requested.store(true, .release),
        }
    }

    fn destroyPollingState(self: *ChannelManager, state: PollingState) void {
        switch (state) {
            .telegram => |ls| self.allocator.destroy(ls),
            .signal => |ls| self.allocator.destroy(ls),
        }
    }

    fn spawnPollingThread(self: *ChannelManager, entry: *Entry, rt: *channel_loop.ChannelRuntime) !void {
        if (std.mem.eql(u8, entry.name, "telegram")) {
            const tg_ls = try self.allocator.create(channel_loop.TelegramLoopState);
            errdefer self.allocator.destroy(tg_ls);
            tg_ls.* = channel_loop.TelegramLoopState.init();

            // Cast the opaque vtable pointer back to the concrete TelegramChannel
            // so the polling loop operates on the same instance as the supervisor.
            const tg_ptr: *telegram.TelegramChannel = @ptrCast(@alignCast(entry.channel.ptr));

            const thread = try std.Thread.spawn(
                .{ .stack_size = 512 * 1024 },
                channel_loop.runTelegramLoop,
                .{ self.allocator, self.config, rt, tg_ls, tg_ptr },
            );
            tg_ls.thread = thread;
            entry.polling_state = .{ .telegram = tg_ls };
            entry.thread = thread;
            return;
        }

        if (std.mem.eql(u8, entry.name, "signal")) {
            const sg_ls = try self.allocator.create(channel_loop.SignalLoopState);
            errdefer self.allocator.destroy(sg_ls);
            sg_ls.* = channel_loop.SignalLoopState.init();

            const thread = try std.Thread.spawn(
                .{ .stack_size = 512 * 1024 },
                channel_loop.runSignalLoop,
                .{ self.allocator, self.config, rt, sg_ls },
            );
            sg_ls.thread = thread;
            entry.polling_state = .{ .signal = sg_ls };
            entry.thread = thread;
            return;
        }

        return error.UnsupportedChannel;
    }

    fn stopPollingThread(self: *ChannelManager, entry: *Entry) void {
        if (entry.polling_state) |state| {
            requestPollingStop(state);
        }

        if (entry.thread) |t| {
            t.join();
            entry.thread = null;
        }

        if (entry.polling_state) |state| {
            self.destroyPollingState(state);
            entry.polling_state = null;
        }
    }

    /// Scan config, create channel instances, register in registry.
    pub fn collectConfiguredChannels(self: *ChannelManager) !void {
        // Telegram (all accounts)
        for (self.config.channels.telegram) |tg_cfg| {
            const tg_ptr = try self.allocator.create(telegram.TelegramChannel);
            tg_ptr.* = telegram.TelegramChannel.init(
                self.allocator,
                tg_cfg.bot_token,
                tg_cfg.allow_from,
                tg_cfg.group_allow_from,
                tg_cfg.group_policy,
            );
            tg_ptr.proxy = tg_cfg.proxy;
            try self.registry.register(tg_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "telegram",
                .account_id = tg_cfg.account_id,
                .channel = tg_ptr.channel(),
                .listener_type = .polling,
                .supervised = dispatch.spawnSupervisedChannel(tg_ptr.channel(), 5),
            });
        }

        // Signal (all accounts)
        for (self.config.channels.signal) |sg_cfg| {
            const sg_ptr = try self.allocator.create(signal_ch.SignalChannel);
            sg_ptr.* = signal_ch.SignalChannel.init(
                self.allocator,
                sg_cfg.http_url,
                sg_cfg.account,
                sg_cfg.allow_from,
                sg_cfg.group_allow_from,
                sg_cfg.ignore_attachments,
                sg_cfg.ignore_stories,
            );
            sg_ptr.group_policy = sg_cfg.group_policy;
            try self.registry.register(sg_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "signal",
                .account_id = sg_cfg.account_id,
                .channel = sg_ptr.channel(),
                .listener_type = .polling,
                .supervised = dispatch.spawnSupervisedChannel(sg_ptr.channel(), 5),
            });
        }

        // Discord (all accounts)
        for (self.config.channels.discord) |dc_cfg| {
            const dc_ptr = try self.allocator.create(discord.DiscordChannel);
            dc_ptr.* = discord.DiscordChannel.initFromConfig(self.allocator, dc_cfg);
            dc_ptr.bus = self.event_bus;
            try self.registry.register(dc_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "discord",
                .account_id = dc_cfg.account_id,
                .channel = dc_ptr.channel(),
                .listener_type = .gateway_loop,
                .supervised = dispatch.spawnSupervisedChannel(dc_ptr.channel(), 5),
            });
            log.info("Discord channel configured (gateway_loop)", .{});
        }

        // QQ (all accounts)
        for (self.config.channels.qq) |qq_cfg| {
            const qq_ptr = try self.allocator.create(qq.QQChannel);
            qq_ptr.* = qq.QQChannel.init(self.allocator, qq_cfg);
            if (self.event_bus) |eb| qq_ptr.setBus(eb);
            try self.registry.register(qq_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "qq",
                .account_id = qq_cfg.account_id,
                .channel = qq_ptr.channel(),
                .listener_type = .gateway_loop,
                .supervised = dispatch.spawnSupervisedChannel(qq_ptr.channel(), 5),
            });
        }

        // OneBot (all accounts)
        for (self.config.channels.onebot) |ob_cfg| {
            const ob_ptr = try self.allocator.create(onebot.OneBotChannel);
            ob_ptr.* = onebot.OneBotChannel.init(self.allocator, ob_cfg);
            if (self.event_bus) |eb| ob_ptr.setBus(eb);
            try self.registry.register(ob_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "onebot",
                .account_id = ob_cfg.account_id,
                .channel = ob_ptr.channel(),
                .listener_type = .gateway_loop,
                .supervised = dispatch.spawnSupervisedChannel(ob_ptr.channel(), 5),
            });
        }

        // WhatsApp — webhook only (inbound via gateway)
        if (self.config.channels.whatsapp) |wa_cfg| {
            const wa_ptr = try self.allocator.create(whatsapp.WhatsAppChannel);
            wa_ptr.* = whatsapp.WhatsAppChannel.init(
                self.allocator,
                wa_cfg.access_token,
                wa_cfg.phone_number_id,
                wa_cfg.verify_token,
                wa_cfg.allow_from,
                wa_cfg.group_allow_from,
                wa_cfg.group_policy,
            );
            try self.registry.register(wa_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "whatsapp",
                .channel = wa_ptr.channel(),
                .listener_type = .webhook_only,
                .supervised = dispatch.spawnSupervisedChannel(wa_ptr.channel(), 5),
            });
        }

        // Line — webhook only
        if (self.config.channels.line) |ln_cfg| {
            const ln_ptr = try self.allocator.create(line.LineChannel);
            ln_ptr.* = line.LineChannel.init(self.allocator, ln_cfg);
            try self.registry.register(ln_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "line",
                .channel = ln_ptr.channel(),
                .listener_type = .webhook_only,
                .supervised = dispatch.spawnSupervisedChannel(ln_ptr.channel(), 5),
            });
        }

        // Lark — webhook only
        if (self.config.channels.lark) |lk_cfg| {
            const lk_ptr = try self.allocator.create(lark.LarkChannel);
            lk_ptr.* = lark.LarkChannel.init(
                self.allocator,
                lk_cfg.app_id,
                lk_cfg.app_secret,
                lk_cfg.verification_token orelse "",
                lk_cfg.port orelse 9000,
                lk_cfg.allow_from,
            );
            try self.registry.register(lk_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "lark",
                .channel = lk_ptr.channel(),
                .listener_type = .webhook_only,
                .supervised = dispatch.spawnSupervisedChannel(lk_ptr.channel(), 5),
            });
        }

        // Slack (all accounts) — send-only (outbound ready; inbound listener not wired yet)
        for (self.config.channels.slack) |sl_cfg| {
            const sl_ptr = try self.allocator.create(slack.SlackChannel);
            sl_ptr.* = slack.SlackChannel.init(
                self.allocator,
                sl_cfg.bot_token,
                sl_cfg.app_token,
                sl_cfg.channel_id,
                sl_cfg.allow_from,
            );
            try self.registry.register(sl_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "slack",
                .account_id = sl_cfg.account_id,
                .channel = sl_ptr.channel(),
                .listener_type = .send_only,
                .supervised = dispatch.spawnSupervisedChannel(sl_ptr.channel(), 5),
            });
        }

        // Matrix — send-only (outbound ready; inbound listener not wired yet)
        if (self.config.channels.matrix != null) {
            const mx_cfg = self.config.channels.matrix.?;
            const mx_ptr = try self.allocator.create(matrix.MatrixChannel);
            mx_ptr.* = matrix.MatrixChannel.init(
                self.allocator,
                mx_cfg.homeserver,
                mx_cfg.access_token,
                mx_cfg.room_id,
                mx_cfg.allow_from,
            );
            try self.registry.register(mx_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "matrix",
                .channel = mx_ptr.channel(),
                .listener_type = .send_only,
                .supervised = dispatch.spawnSupervisedChannel(mx_ptr.channel(), 5),
            });
        }

        // IRC — send-only lifecycle (connect/start for outbound sends)
        if (self.config.channels.irc != null) {
            const irc_cfg = self.config.channels.irc.?;
            const irc_ptr = try self.allocator.create(irc.IrcChannel);
            irc_ptr.* = irc.IrcChannel.init(
                self.allocator,
                irc_cfg.host,
                irc_cfg.port,
                irc_cfg.nick,
                irc_cfg.username,
                irc_cfg.channels,
                irc_cfg.allow_from,
                irc_cfg.server_password,
                irc_cfg.nickserv_password,
                irc_cfg.sasl_password,
                irc_cfg.tls,
            );
            try self.registry.register(irc_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "irc",
                .channel = irc_ptr.channel(),
                .listener_type = .send_only,
                .supervised = dispatch.spawnSupervisedChannel(irc_ptr.channel(), 5),
            });
        }

        // iMessage — send-only
        if (self.config.channels.imessage != null) {
            const im_cfg = self.config.channels.imessage.?;
            const im_ptr = try self.allocator.create(imessage.IMessageChannel);
            im_ptr.* = imessage.IMessageChannel.init(
                self.allocator,
                im_cfg.allow_from,
                im_cfg.group_allow_from,
                im_cfg.group_policy,
            );
            try self.registry.register(im_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "imessage",
                .channel = im_ptr.channel(),
                .listener_type = .send_only,
                .supervised = dispatch.spawnSupervisedChannel(im_ptr.channel(), 5),
            });
        }

        // Email — send-only
        if (self.config.channels.email != null) {
            const em_cfg = self.config.channels.email.?;
            const em_ptr = try self.allocator.create(email.EmailChannel);
            em_ptr.* = email.EmailChannel.init(self.allocator, em_cfg);
            try self.registry.register(em_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "email",
                .channel = em_ptr.channel(),
                .listener_type = .send_only,
                .supervised = dispatch.spawnSupervisedChannel(em_ptr.channel(), 5),
            });
        }

        // DingTalk — send-only
        if (self.config.channels.dingtalk != null) {
            const dt_cfg = self.config.channels.dingtalk.?;
            const dt_ptr = try self.allocator.create(dingtalk.DingTalkChannel);
            dt_ptr.* = dingtalk.DingTalkChannel.init(
                self.allocator,
                dt_cfg.client_id,
                dt_cfg.client_secret,
                dt_cfg.allow_from,
            );
            try self.registry.register(dt_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "dingtalk",
                .channel = dt_ptr.channel(),
                .listener_type = .send_only,
                .supervised = dispatch.spawnSupervisedChannel(dt_ptr.channel(), 5),
            });
        }

        // MaixCam (all accounts) — send-only lifecycle
        for (self.config.channels.maixcam) |mx_cfg| {
            const mx_ptr = try self.allocator.create(maixcam.MaixCamChannel);
            mx_ptr.* = maixcam.MaixCamChannel.init(self.allocator, mx_cfg);
            mx_ptr.event_bus = self.event_bus;
            try self.registry.register(mx_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "maixcam",
                .account_id = mx_cfg.account_id,
                .channel = mx_ptr.channel(),
                .listener_type = .send_only,
                .supervised = dispatch.spawnSupervisedChannel(mx_ptr.channel(), 5),
            });
        }
    }

    /// Spawn listener threads for polling/gateway channels.
    pub fn startAll(self: *ChannelManager) !usize {
        var started: usize = 0;

        for (self.entries.items) |*entry| {
            switch (entry.listener_type) {
                .polling => {
                    if (self.runtime == null) {
                        log.warn("Cannot start {s}: no runtime available", .{entry.name});
                        continue;
                    }

                    self.spawnPollingThread(entry, self.runtime.?) catch |err| {
                        log.err("Failed to spawn {s} thread: {}", .{ entry.name, err });
                        continue;
                    };

                    entry.supervised.recordSuccess();
                    started += 1;
                    log.info("{s} polling thread started", .{entry.name});
                },
                .gateway_loop => {
                    // Gateway-loop channels (Discord, QQ, OneBot) manage their own connections
                    entry.channel.start() catch |err| {
                        log.warn("Failed to start {s} gateway: {}", .{ entry.name, err });
                        continue;
                    };
                    started += 1;
                    log.info("{s} gateway started", .{entry.name});
                },
                .webhook_only => {
                    // Webhook channels don't need a thread — they receive via the HTTP gateway
                    entry.channel.start() catch |err| {
                        log.warn("Failed to start {s}: {}", .{ entry.name, err });
                        continue;
                    };
                    started += 1;
                    log.info("{s} registered (webhook-only)", .{entry.name});
                },
                .send_only => {
                    entry.channel.start() catch |err| {
                        log.warn("Failed to start {s}: {}", .{ entry.name, err });
                        continue;
                    };
                    started += 1;
                    log.info("{s} started (send-only)", .{entry.name});
                },
                .not_implemented => {
                    log.info("{s} configured but not implemented — skipping", .{entry.name});
                },
            }
        }

        return started;
    }

    /// Signal all threads to stop and join them.
    pub fn stopAll(self: *ChannelManager) void {
        for (self.entries.items) |*entry| {
            switch (entry.listener_type) {
                .polling => self.stopPollingThread(entry),
                .gateway_loop, .webhook_only, .send_only => entry.channel.stop(),
                .not_implemented => {},
            }
        }
    }

    /// Monitoring loop: check health, restart failed channels with backoff.
    /// Blocks until shutdown.
    pub fn supervisionLoop(self: *ChannelManager, state: *daemon.DaemonState) void {
        const STALE_THRESHOLD_SECS: i64 = 90;
        const WATCH_INTERVAL_SECS: u64 = 10;

        while (!daemon.isShutdownRequested()) {
            std.Thread.sleep(WATCH_INTERVAL_SECS * std.time.ns_per_s);
            if (daemon.isShutdownRequested()) break;

            for (self.entries.items) |*entry| {
                // Gateway-loop channels: health check + restart on failure
                if (entry.listener_type == .gateway_loop) {
                    const probe_ok = entry.channel.healthCheck();
                    if (probe_ok) {
                        health.markComponentOk(entry.name);
                        if (entry.supervised.state != .running) entry.supervised.recordSuccess();
                    } else {
                        log.warn("{s} gateway health check failed", .{entry.name});
                        health.markComponentError(entry.name, "gateway health check failed");
                        entry.supervised.recordFailure();

                        if (entry.supervised.shouldRestart()) {
                            log.info("Restarting {s} gateway (attempt {d})", .{ entry.name, entry.supervised.restart_count });
                            state.markError("channels", "gateway health check failed");
                            entry.channel.stop();
                            std.Thread.sleep(entry.supervised.currentBackoffMs() * std.time.ns_per_ms);
                            entry.channel.start() catch |err| {
                                log.err("Failed to restart {s} gateway: {}", .{ entry.name, err });
                                continue;
                            };
                            entry.supervised.recordSuccess();
                            state.markRunning("channels");
                            health.markComponentOk(entry.name);
                        } else if (entry.supervised.state == .gave_up) {
                            state.markError("channels", "gave up after max restarts");
                            health.markComponentError(entry.name, "gave up after max restarts");
                        }
                    }
                    continue;
                }

                if (entry.listener_type != .polling) continue;

                const polling_state = entry.polling_state orelse continue;
                const now = std.time.timestamp();
                const last = pollingLastActivity(polling_state);
                const stale = (now - last) > STALE_THRESHOLD_SECS;

                const probe_ok = entry.channel.healthCheck();

                if (!stale and probe_ok) {
                    health.markComponentOk(entry.name);
                    state.markRunning("channels");
                    if (entry.supervised.state != .running) entry.supervised.recordSuccess();
                } else {
                    const reason: []const u8 = if (stale) "polling thread stale" else "health check failed";
                    log.warn("{s} issue: {s}", .{ entry.name, reason });
                    health.markComponentError(entry.name, reason);

                    entry.supervised.recordFailure();

                    if (entry.supervised.shouldRestart()) {
                        log.info("Restarting {s} (attempt {d})", .{ entry.name, entry.supervised.restart_count });
                        state.markError("channels", reason);

                        // Stop old thread
                        self.stopPollingThread(entry);

                        // Backoff
                        std.Thread.sleep(entry.supervised.currentBackoffMs() * std.time.ns_per_ms);

                        // Respawn
                        if (self.runtime) |rt| {
                            self.spawnPollingThread(entry, rt) catch |err| {
                                log.err("Failed to respawn {s} thread: {}", .{ entry.name, err });
                                continue;
                            };
                            entry.supervised.recordSuccess();
                            state.markRunning("channels");
                            health.markComponentOk(entry.name);
                        }
                    } else if (entry.supervised.state == .gave_up) {
                        state.markError("channels", "gave up after max restarts");
                        health.markComponentError(entry.name, "gave up after max restarts");
                    }
                }
            }

            // If no polling channels, just mark healthy
            const has_polling = for (self.entries.items) |entry| {
                if (entry.listener_type == .polling) break true;
            } else false;
            if (!has_polling) {
                health.markComponentOk("channels");
            }
        }
    }

    /// Get all configured channel entries.
    pub fn channelEntries(self: *const ChannelManager) []const Entry {
        return self.entries.items;
    }

    /// Return the number of configured channels.
    pub fn count(self: *const ChannelManager) usize {
        return self.entries.items.len;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "PollingState has telegram and signal variants" {
    try std.testing.expect(@intFromEnum(@as(std.meta.Tag(PollingState), .telegram)) !=
        @intFromEnum(@as(std.meta.Tag(PollingState), .signal)));
}

test "ListenerType enum values distinct" {
    try std.testing.expect(@intFromEnum(ListenerType.polling) != @intFromEnum(ListenerType.gateway_loop));
    try std.testing.expect(@intFromEnum(ListenerType.gateway_loop) != @intFromEnum(ListenerType.webhook_only));
    try std.testing.expect(@intFromEnum(ListenerType.webhook_only) != @intFromEnum(ListenerType.not_implemented));
}

test "ChannelManager init and deinit" {
    const allocator = std.testing.allocator;
    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
    };
    const mgr = try ChannelManager.init(allocator, &config, &reg);
    try std.testing.expectEqual(@as(usize, 0), mgr.count());
    mgr.deinit();
}

test "ChannelManager no channels configured" {
    const allocator = std.testing.allocator;
    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
    };
    const mgr = try ChannelManager.init(allocator, &config, &reg);
    defer mgr.deinit();

    try mgr.collectConfiguredChannels();
    try std.testing.expectEqual(@as(usize, 0), mgr.count());
    try std.testing.expectEqual(@as(usize, 0), mgr.channelEntries().len);
}
