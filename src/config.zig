const std = @import("std");
pub const config_types = @import("config_types.zig");
pub const config_parse = @import("config_parse.zig");

// ── Re-export all types so downstream `@import("config.zig").Foo` still works ──

pub const AutonomyLevel = config_types.AutonomyLevel;
pub const HardwareTransport = config_types.HardwareTransport;
pub const SandboxBackend = config_types.SandboxBackend;
pub const ObservabilityConfig = config_types.ObservabilityConfig;
pub const AutonomyConfig = config_types.AutonomyConfig;
pub const DockerRuntimeConfig = config_types.DockerRuntimeConfig;
pub const RuntimeConfig = config_types.RuntimeConfig;
pub const ModelFallbackEntry = config_types.ModelFallbackEntry;
pub const ReliabilityConfig = config_types.ReliabilityConfig;
pub const SchedulerConfig = config_types.SchedulerConfig;
pub const AgentConfig = config_types.AgentConfig;
pub const ModelRouteConfig = config_types.ModelRouteConfig;
pub const HeartbeatConfig = config_types.HeartbeatConfig;
pub const CronConfig = config_types.CronConfig;
pub const TelegramConfig = config_types.TelegramConfig;
pub const DiscordConfig = config_types.DiscordConfig;
pub const SlackConfig = config_types.SlackConfig;
pub const WebhookConfig = config_types.WebhookConfig;
pub const IMessageConfig = config_types.IMessageConfig;
pub const MatrixConfig = config_types.MatrixConfig;
pub const WhatsAppConfig = config_types.WhatsAppConfig;
pub const IrcConfig = config_types.IrcConfig;
pub const LarkReceiveMode = config_types.LarkReceiveMode;
pub const LarkConfig = config_types.LarkConfig;
pub const DingTalkConfig = config_types.DingTalkConfig;
pub const ChannelsConfig = config_types.ChannelsConfig;
pub const MemoryConfig = config_types.MemoryConfig;
pub const TunnelConfig = config_types.TunnelConfig;
pub const GatewayConfig = config_types.GatewayConfig;
pub const ComposioConfig = config_types.ComposioConfig;
pub const SecretsConfig = config_types.SecretsConfig;
pub const BrowserComputerUseConfig = config_types.BrowserComputerUseConfig;
pub const BrowserConfig = config_types.BrowserConfig;
pub const HttpRequestConfig = config_types.HttpRequestConfig;
pub const IdentityConfig = config_types.IdentityConfig;
pub const CostConfig = config_types.CostConfig;
pub const PeripheralBoardConfig = config_types.PeripheralBoardConfig;
pub const PeripheralsConfig = config_types.PeripheralsConfig;
pub const HardwareConfig = config_types.HardwareConfig;
pub const SandboxConfig = config_types.SandboxConfig;
pub const ResourceLimitsConfig = config_types.ResourceLimitsConfig;
pub const AuditConfig = config_types.AuditConfig;
pub const SecurityConfig = config_types.SecurityConfig;
pub const DelegateAgentConfig = config_types.DelegateAgentConfig;
pub const NamedAgentConfig = config_types.NamedAgentConfig;
pub const McpServerConfig = config_types.McpServerConfig;
pub const ModelPricing = config_types.ModelPricing;
pub const ToolsConfig = config_types.ToolsConfig;

// ── Top-level Config ────────────────────────────────────────────

pub const Config = struct {
    // Computed paths (not serialized)
    workspace_dir: []const u8,
    config_path: []const u8,

    // Top-level fields
    api_key: ?[]const u8 = null,
    api_url: ?[]const u8 = null,
    groq_api_key: ?[]const u8 = null,
    default_provider: []const u8 = "openrouter",
    default_model: ?[]const u8 = "anthropic/claude-sonnet-4",
    default_temperature: f64 = 0.7,

    // Model routing and delegate agents
    model_routes: []const ModelRouteConfig = &.{},
    agents: []const NamedAgentConfig = &.{},
    mcp_servers: []const McpServerConfig = &.{},

    // Nested sub-configs
    observability: ObservabilityConfig = .{},
    autonomy: AutonomyConfig = .{},
    runtime: RuntimeConfig = .{},
    reliability: ReliabilityConfig = .{},
    scheduler: SchedulerConfig = .{},
    agent: AgentConfig = .{},
    heartbeat: HeartbeatConfig = .{},
    cron: CronConfig = .{},
    channels: ChannelsConfig = .{},
    memory: MemoryConfig = .{},
    tunnel: TunnelConfig = .{},
    gateway: GatewayConfig = .{},
    composio: ComposioConfig = .{},
    secrets: SecretsConfig = .{},
    browser: BrowserConfig = .{},
    http_request: HttpRequestConfig = .{},
    identity: IdentityConfig = .{},
    cost: CostConfig = .{},
    peripherals: PeripheralsConfig = .{},
    hardware: HardwareConfig = .{},
    security: SecurityConfig = .{},
    tools: ToolsConfig = .{},

    // Convenience aliases for backward-compat flat access used by other modules.
    // These are set during load() to mirror nested values.
    temperature: f64 = 0.7,
    max_tokens: u32 = 4096,
    memory_backend: []const u8 = "sqlite",
    memory_auto_save: bool = true,
    heartbeat_enabled: bool = false,
    heartbeat_interval_minutes: u32 = 30,
    gateway_host: []const u8 = "127.0.0.1",
    gateway_port: u16 = 3000,
    workspace_only: bool = true,
    max_actions_per_hour: u32 = 20,

    allocator: std.mem.Allocator,

    /// Sync flat convenience fields from the nested sub-configs.
    pub fn syncFlatFields(self: *Config) void {
        self.temperature = self.default_temperature;
        self.memory_backend = self.memory.backend;
        self.memory_auto_save = self.memory.auto_save;
        self.heartbeat_enabled = self.heartbeat.enabled;
        self.heartbeat_interval_minutes = self.heartbeat.interval_minutes;
        self.gateway_host = self.gateway.host;
        self.gateway_port = self.gateway.port;
        self.workspace_only = self.autonomy.workspace_only;
        self.max_actions_per_hour = self.autonomy.max_actions_per_hour;
    }

    pub fn load(allocator: std.mem.Allocator) !Config {
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => return error.NoHomeDir,
            else => return err,
        };
        defer allocator.free(home);

        const config_dir = try std.fs.path.join(allocator, &.{ home, ".nullclaw" });
        const config_path = try std.fs.path.join(allocator, &.{ config_dir, "config.json" });
        const workspace_dir = try std.fs.path.join(allocator, &.{ config_dir, "workspace" });

        var cfg = Config{
            .workspace_dir = workspace_dir,
            .config_path = config_path,
            .allocator = allocator,
        };

        // Try to read existing config file
        if (std.fs.openFileAbsolute(config_path, .{})) |file| {
            defer file.close();
            const content = try file.readToEndAlloc(allocator, 1024 * 64);
            defer allocator.free(content);
            cfg.parseJson(content) catch {};
        } else |_| {
            // Config file doesn't exist yet — use defaults
        }

        // Environment variable overrides
        cfg.applyEnvOverrides();

        // Sync flat fields from nested structs
        cfg.syncFlatFields();

        return cfg;
    }

    /// Parse a JSON array of strings into an allocated slice.
    pub fn parseStringArray(self: *Config, arr: std.json.Array) ![]const []const u8 {
        return config_parse.parseStringArray(self.allocator, arr);
    }

    pub fn parseJson(self: *Config, content: []const u8) !void {
        return config_parse.parseJson(self, content);
    }

    /// Apply NULLCLAW_* environment variable overrides.
    pub fn applyEnvOverrides(self: *Config) void {
        // API Key
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_API_KEY")) |key| {
            self.api_key = key;
        } else |_| {}

        // Provider
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_PROVIDER")) |prov| {
            self.default_provider = prov;
        } else |_| {}

        // Model
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_MODEL")) |model| {
            self.default_model = model;
        } else |_| {}

        // Temperature
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_TEMPERATURE")) |temp_str| {
            defer self.allocator.free(temp_str);
            if (std.fmt.parseFloat(f64, temp_str)) |temp| {
                if (temp >= 0.0 and temp <= 2.0) {
                    self.default_temperature = temp;
                }
            } else |_| {}
        } else |_| {}

        // Gateway port
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_GATEWAY_PORT")) |port_str| {
            defer self.allocator.free(port_str);
            if (std.fmt.parseInt(u16, port_str, 10)) |port| {
                self.gateway.port = port;
            } else |_| {}
        } else |_| {}

        // Gateway host
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_GATEWAY_HOST")) |host| {
            self.gateway.host = host;
        } else |_| {}

        // Workspace
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_WORKSPACE")) |ws| {
            self.workspace_dir = ws;
        } else |_| {}

        // Allow public bind
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_ALLOW_PUBLIC_BIND")) |val| {
            defer self.allocator.free(val);
            self.gateway.allow_public_bind = std.mem.eql(u8, val, "1") or std.mem.eql(u8, val, "true");
        } else |_| {}

        // Base URL (maps to api_url)
        if (std.process.getEnvVarOwned(self.allocator, "NULLCLAW_BASE_URL")) |url| {
            self.api_url = url;
        } else |_| {}
    }

    /// Save config as JSON to the config_path.
    pub fn save(self: *const Config) !void {
        const dir = std.fs.path.dirname(self.config_path) orelse return error.InvalidConfigPath;

        // Ensure parent directory exists
        std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        const file = try std.fs.createFileAbsolute(self.config_path, .{});
        defer file.close();

        var buf: [8192]u8 = undefined;
        var bw = file.writer(&buf);
        const w = &bw.interface;

        try w.print("{{\n", .{});

        // Top-level fields
        if (self.api_key) |key| {
            try w.print("  \"api_key\": \"{s}\",\n", .{key});
        }
        if (self.groq_api_key) |key| {
            try w.print("  \"groq_api_key\": \"{s}\",\n", .{key});
        }
        try w.print("  \"default_provider\": \"{s}\",\n", .{self.default_provider});
        if (self.default_model) |model| {
            try w.print("  \"default_model\": \"{s}\",\n", .{model});
        }
        try w.print("  \"default_temperature\": {d:.1},\n", .{self.default_temperature});

        // Observability
        try w.print("  \"observability\": {{\n", .{});
        try w.print("    \"backend\": \"{s}\"\n", .{self.observability.backend});
        try w.print("  }},\n", .{});

        // Autonomy
        try w.print("  \"autonomy\": {{\n", .{});
        try w.print("    \"level\": \"{s}\",\n", .{@tagName(self.autonomy.level)});
        try w.print("    \"workspace_only\": {s},\n", .{if (self.autonomy.workspace_only) "true" else "false"});
        try w.print("    \"max_actions_per_hour\": {d},\n", .{self.autonomy.max_actions_per_hour});
        if (self.autonomy.allowed_paths.len > 0) {
            try w.print("    \"max_cost_per_day_cents\": {d},\n", .{self.autonomy.max_cost_per_day_cents});
            try w.print("    \"allowed_paths\": [", .{});
            for (self.autonomy.allowed_paths, 0..) |p, i| {
                if (i > 0) try w.print(", ", .{});
                try w.print("\"{s}\"", .{p});
            }
            try w.print("]\n", .{});
        } else {
            try w.print("    \"max_cost_per_day_cents\": {d}\n", .{self.autonomy.max_cost_per_day_cents});
        }
        try w.print("  }},\n", .{});

        // Heartbeat
        try w.print("  \"heartbeat\": {{\n", .{});
        try w.print("    \"enabled\": {s},\n", .{if (self.heartbeat.enabled) "true" else "false"});
        try w.print("    \"interval_minutes\": {d}\n", .{self.heartbeat.interval_minutes});
        try w.print("  }},\n", .{});

        // Memory
        try w.print("  \"memory\": {{\n", .{});
        try w.print("    \"backend\": \"{s}\",\n", .{self.memory.backend});
        try w.print("    \"auto_save\": {s},\n", .{if (self.memory.auto_save) "true" else "false"});
        try w.print("    \"hygiene_enabled\": {s},\n", .{if (self.memory.hygiene_enabled) "true" else "false"});
        try w.print("    \"archive_after_days\": {d},\n", .{self.memory.archive_after_days});
        try w.print("    \"purge_after_days\": {d},\n", .{self.memory.purge_after_days});
        try w.print("    \"conversation_retention_days\": {d}\n", .{self.memory.conversation_retention_days});
        try w.print("  }},\n", .{});

        // Gateway
        try w.print("  \"gateway\": {{\n", .{});
        try w.print("    \"port\": {d},\n", .{self.gateway.port});
        try w.print("    \"host\": \"{s}\",\n", .{self.gateway.host});
        try w.print("    \"require_pairing\": {s}\n", .{if (self.gateway.require_pairing) "true" else "false"});
        try w.print("  }},\n", .{});

        // Cost
        try w.print("  \"cost\": {{\n", .{});
        try w.print("    \"enabled\": {s},\n", .{if (self.cost.enabled) "true" else "false"});
        try w.print("    \"daily_limit_usd\": {d:.1},\n", .{self.cost.daily_limit_usd});
        try w.print("    \"monthly_limit_usd\": {d:.1}\n", .{self.cost.monthly_limit_usd});
        try w.print("  }},\n", .{});

        // Tools
        try w.print("  \"tools\": {{\n", .{});
        try w.print("    \"shell_timeout_secs\": {d},\n", .{self.tools.shell_timeout_secs});
        try w.print("    \"shell_max_output_bytes\": {d},\n", .{self.tools.shell_max_output_bytes});
        try w.print("    \"max_file_size_bytes\": {d},\n", .{self.tools.max_file_size_bytes});
        try w.print("    \"web_fetch_max_chars\": {d}\n", .{self.tools.web_fetch_max_chars});
        try w.print("  }},\n", .{});

        // Hardware
        try w.print("  \"hardware\": {{\n", .{});
        try w.print("    \"enabled\": {s},\n", .{if (self.hardware.enabled) "true" else "false"});
        try w.print("    \"transport\": \"{s}\",\n", .{@tagName(self.hardware.transport)});
        try w.print("    \"baud_rate\": {d}\n", .{self.hardware.baud_rate});
        try w.print("  }}\n", .{});

        try w.print("}}\n", .{});
        try w.flush();
    }

    pub fn ensureDirs(self: *const Config) !void {
        const dir = std.fs.path.dirname(self.config_path) orelse return;
        std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        std.fs.makeDirAbsolute(self.workspace_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    // ── Validation ──────────────────────────────────────────────

    pub const ValidationError = error{
        TemperatureOutOfRange,
        InvalidPort,
        InvalidRetryCount,
        InvalidBackoffMs,
    };

    pub fn validate(self: *const Config) ValidationError!void {
        if (self.default_temperature < 0.0 or self.default_temperature > 2.0) {
            return ValidationError.TemperatureOutOfRange;
        }
        if (self.gateway.port == 0) {
            return ValidationError.InvalidPort;
        }
        if (self.reliability.provider_retries > 100) {
            return ValidationError.InvalidRetryCount;
        }
        if (self.reliability.provider_backoff_ms > 600_000) {
            return ValidationError.InvalidBackoffMs;
        }
    }
};

// ── Tests ───────────────────────────────────────────────────────

test "json parse roundtrip" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "default_provider": "anthropic",
        \\  "default_model": "claude-opus-4",
        \\  "default_temperature": 0.5,
        \\  "api_key": "sk-test",
        \\  "heartbeat": {"enabled": true, "interval_minutes": 15},
        \\  "memory": {"backend": "markdown", "auto_save": false},
        \\  "gateway": {"port": 9090, "host": "0.0.0.0"},
        \\  "autonomy": {"level": "full", "workspace_only": false, "max_actions_per_hour": 50},
        \\  "runtime": {"kind": "docker"},
        \\  "cost": {"enabled": true, "daily_limit_usd": 25.0}
        \\}
    ;

    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    try cfg.parseJson(json);
    cfg.syncFlatFields();

    try std.testing.expectEqualStrings("anthropic", cfg.default_provider);
    try std.testing.expectEqualStrings("claude-opus-4", cfg.default_model.?);
    try std.testing.expectEqual(@as(f64, 0.5), cfg.default_temperature);
    try std.testing.expectEqual(@as(f64, 0.5), cfg.temperature);
    try std.testing.expectEqualStrings("sk-test", cfg.api_key.?);
    try std.testing.expect(cfg.heartbeat.enabled);
    try std.testing.expect(cfg.heartbeat_enabled);
    try std.testing.expectEqual(@as(u32, 15), cfg.heartbeat.interval_minutes);
    try std.testing.expectEqualStrings("markdown", cfg.memory.backend);
    try std.testing.expectEqualStrings("markdown", cfg.memory_backend);
    try std.testing.expect(!cfg.memory.auto_save);
    try std.testing.expect(!cfg.memory_auto_save);
    try std.testing.expectEqual(@as(u16, 9090), cfg.gateway.port);
    try std.testing.expectEqualStrings("0.0.0.0", cfg.gateway.host);
    try std.testing.expectEqual(AutonomyLevel.full, cfg.autonomy.level);
    try std.testing.expect(!cfg.autonomy.workspace_only);
    try std.testing.expect(!cfg.workspace_only);
    try std.testing.expectEqual(@as(u32, 50), cfg.autonomy.max_actions_per_hour);
    try std.testing.expectEqualStrings("docker", cfg.runtime.kind);
    try std.testing.expect(cfg.cost.enabled);
    try std.testing.expectEqual(@as(f64, 25.0), cfg.cost.daily_limit_usd);

    // Clean up allocated strings
    allocator.free(cfg.default_provider);
    allocator.free(cfg.default_model.?);
    allocator.free(cfg.api_key.?);
    allocator.free(cfg.memory.backend);
    allocator.free(cfg.gateway.host);
    allocator.free(cfg.runtime.kind);
}

test "validation rejects bad temperature" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_temperature = 5.0,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectError(Config.ValidationError.TemperatureOutOfRange, cfg.validate());
}

test "validation rejects zero port" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.gateway.port = 0;
    try std.testing.expectError(Config.ValidationError.InvalidPort, cfg.validate());
}

test "validation passes for defaults" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    try cfg.validate();
}

test "syncFlatFields propagates nested values" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.default_temperature = 1.5;
    cfg.memory.backend = "lucid";
    cfg.memory.auto_save = false;
    cfg.heartbeat.enabled = true;
    cfg.heartbeat.interval_minutes = 10;
    cfg.gateway.host = "0.0.0.0";
    cfg.gateway.port = 9999;
    cfg.autonomy.workspace_only = false;
    cfg.autonomy.max_actions_per_hour = 999;

    cfg.syncFlatFields();

    try std.testing.expectEqual(@as(f64, 1.5), cfg.temperature);
    try std.testing.expectEqualStrings("lucid", cfg.memory_backend);
    try std.testing.expect(!cfg.memory_auto_save);
    try std.testing.expect(cfg.heartbeat_enabled);
    try std.testing.expectEqual(@as(u32, 10), cfg.heartbeat_interval_minutes);
    try std.testing.expectEqualStrings("0.0.0.0", cfg.gateway_host);
    try std.testing.expectEqual(@as(u16, 9999), cfg.gateway_port);
    try std.testing.expect(!cfg.workspace_only);
    try std.testing.expectEqual(@as(u32, 999), cfg.max_actions_per_hour);
}

// ── Security-critical defaults ───────────────────────────────────

test "gateway config requires pairing by default" {
    const g = GatewayConfig{};
    try std.testing.expect(g.require_pairing);
}

test "gateway config blocks public bind by default" {
    const g = GatewayConfig{};
    try std.testing.expect(!g.allow_public_bind);
}

test "secrets config default encrypts" {
    const s = SecretsConfig{};
    try std.testing.expect(s.encrypt);
}

// ── Validation edge cases ───────────────────────────────────────

test "validation rejects negative temperature" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_temperature = -1.0,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectError(Config.ValidationError.TemperatureOutOfRange, cfg.validate());
}

test "validation accepts boundary temperatures" {
    const cfg_zero = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_temperature = 0.0,
        .allocator = std.testing.allocator,
    };
    try cfg_zero.validate();

    const cfg_two = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .default_temperature = 2.0,
        .allocator = std.testing.allocator,
    };
    try cfg_two.validate();
}

test "validation rejects excessive retries" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_retries = 101;
    try std.testing.expectError(Config.ValidationError.InvalidRetryCount, cfg.validate());
}

test "validation rejects excessive backoff" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_backoff_ms = 700_000;
    try std.testing.expectError(Config.ValidationError.InvalidBackoffMs, cfg.validate());
}

test "validation accepts max boundary retries" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_retries = 100;
    try cfg.validate();
}

test "validation accepts max boundary backoff" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.reliability.provider_backoff_ms = 600_000;
    try cfg.validate();
}

// ── JSON parse: sub-config sections ─────────────────────────────

test "json parse observability section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"observability": {"backend": "otel", "otel_endpoint": "http://localhost:4318", "otel_service_name": "yc"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("otel", cfg.observability.backend);
    try std.testing.expectEqualStrings("http://localhost:4318", cfg.observability.otel_endpoint.?);
    try std.testing.expectEqualStrings("yc", cfg.observability.otel_service_name.?);
    allocator.free(cfg.observability.backend);
    allocator.free(cfg.observability.otel_endpoint.?);
    allocator.free(cfg.observability.otel_service_name.?);
}

test "json parse scheduler section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"scheduler": {"enabled": false, "max_tasks": 128, "max_concurrent": 8}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(!cfg.scheduler.enabled);
    try std.testing.expectEqual(@as(u32, 128), cfg.scheduler.max_tasks);
    try std.testing.expectEqual(@as(u32, 8), cfg.scheduler.max_concurrent);
}

test "json parse agent section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agent": {"compact_context": true, "max_tool_iterations": 20, "max_history_messages": 80, "parallel_tools": true, "tool_dispatcher": "xml"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.agent.compact_context);
    try std.testing.expectEqual(@as(u32, 20), cfg.agent.max_tool_iterations);
    try std.testing.expectEqual(@as(u32, 80), cfg.agent.max_history_messages);
    try std.testing.expect(cfg.agent.parallel_tools);
    try std.testing.expectEqualStrings("xml", cfg.agent.tool_dispatcher);
    allocator.free(cfg.agent.tool_dispatcher);
}

test "json parse composio section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"composio": {"enabled": true, "api_key": "comp-key", "entity_id": "user1"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.composio.enabled);
    try std.testing.expectEqualStrings("comp-key", cfg.composio.api_key.?);
    try std.testing.expectEqualStrings("user1", cfg.composio.entity_id);
    allocator.free(cfg.composio.api_key.?);
    allocator.free(cfg.composio.entity_id);
}

test "json parse secrets section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"secrets": {"encrypt": false}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(!cfg.secrets.encrypt);
}

test "json parse identity section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"identity": {"format": "aieos", "aieos_path": "id.json"}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("aieos", cfg.identity.format);
    try std.testing.expectEqualStrings("id.json", cfg.identity.aieos_path.?);
    allocator.free(cfg.identity.format);
    allocator.free(cfg.identity.aieos_path.?);
}

test "json parse hardware section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"hardware": {"enabled": true, "transport": "serial", "serial_port": "/dev/ttyACM0", "baud_rate": 9600}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.hardware.enabled);
    try std.testing.expectEqual(HardwareTransport.serial, cfg.hardware.transport);
    try std.testing.expectEqualStrings("/dev/ttyACM0", cfg.hardware.serial_port.?);
    try std.testing.expectEqual(@as(u32, 9600), cfg.hardware.baud_rate);
    allocator.free(cfg.hardware.serial_port.?);
}

test "json parse security section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"security": {"sandbox": {"enabled": true, "backend": "firejail"}, "resources": {"max_memory_mb": 1024, "max_cpu_time_seconds": 120}, "audit": {"enabled": false, "log_path": "custom.log"}}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.security.sandbox.enabled.?);
    try std.testing.expectEqual(SandboxBackend.firejail, cfg.security.sandbox.backend);
    try std.testing.expectEqual(@as(u32, 1024), cfg.security.resources.max_memory_mb);
    try std.testing.expectEqual(@as(u64, 120), cfg.security.resources.max_cpu_time_seconds);
    try std.testing.expect(!cfg.security.audit.enabled);
    try std.testing.expectEqualStrings("custom.log", cfg.security.audit.log_path);
    allocator.free(cfg.security.audit.log_path);
}

test "json parse browser section" {
    const allocator = std.testing.allocator;
    const json =
        \\{"browser": {"enabled": true, "backend": "auto", "native_headless": false}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.browser.enabled);
    try std.testing.expectEqualStrings("auto", cfg.browser.backend);
    try std.testing.expect(!cfg.browser.native_headless);
    allocator.free(cfg.browser.backend);
}

test "json parse empty object uses defaults" {
    const allocator = std.testing.allocator;
    const json = "{}";
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("openrouter", cfg.default_provider);
    try std.testing.expectEqual(@as(f64, 0.7), cfg.default_temperature);
    try std.testing.expect(cfg.secrets.encrypt);
}

test "json parse integer temperature coerced to float" {
    const allocator = std.testing.allocator;
    const json =
        \\{"default_temperature": 1}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(f64, 1.0), cfg.default_temperature);
}

test "json parse autonomy allowed commands and forbidden paths" {
    const allocator = std.testing.allocator;
    const json =
        \\{"autonomy": {"allowed_commands": ["ls", "cat", "git status"], "forbidden_paths": ["/etc/shadow", "/root/.ssh"]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 3), cfg.autonomy.allowed_commands.len);
    try std.testing.expectEqualStrings("ls", cfg.autonomy.allowed_commands[0]);
    try std.testing.expectEqualStrings("cat", cfg.autonomy.allowed_commands[1]);
    try std.testing.expectEqualStrings("git status", cfg.autonomy.allowed_commands[2]);
    try std.testing.expectEqual(@as(usize, 2), cfg.autonomy.forbidden_paths.len);
    try std.testing.expectEqualStrings("/etc/shadow", cfg.autonomy.forbidden_paths[0]);
    try std.testing.expectEqualStrings("/root/.ssh", cfg.autonomy.forbidden_paths[1]);
    for (cfg.autonomy.allowed_commands) |cmd| allocator.free(cmd);
    allocator.free(cfg.autonomy.allowed_commands);
    for (cfg.autonomy.forbidden_paths) |p| allocator.free(p);
    allocator.free(cfg.autonomy.forbidden_paths);
}

test "json parse autonomy allowed_paths" {
    const allocator = std.testing.allocator;
    const json =
        \\{"autonomy": {"allowed_paths": ["/Users/igor/projects", "/tmp/scratch"]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.autonomy.allowed_paths.len);
    try std.testing.expectEqualStrings("/Users/igor/projects", cfg.autonomy.allowed_paths[0]);
    try std.testing.expectEqualStrings("/tmp/scratch", cfg.autonomy.allowed_paths[1]);
    for (cfg.autonomy.allowed_paths) |p| allocator.free(p);
    allocator.free(cfg.autonomy.allowed_paths);
}

test "json parse gateway paired tokens" {
    const allocator = std.testing.allocator;
    const json =
        \\{"gateway": {"paired_tokens": ["token-1", "token-2", "token-3"]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 3), cfg.gateway.paired_tokens.len);
    try std.testing.expectEqualStrings("token-1", cfg.gateway.paired_tokens[0]);
    try std.testing.expectEqualStrings("token-2", cfg.gateway.paired_tokens[1]);
    try std.testing.expectEqualStrings("token-3", cfg.gateway.paired_tokens[2]);
    for (cfg.gateway.paired_tokens) |t| allocator.free(t);
    allocator.free(cfg.gateway.paired_tokens);
}

test "json parse browser allowed domains" {
    const allocator = std.testing.allocator;
    const json =
        \\{"browser": {"enabled": true, "allowed_domains": ["github.com", "docs.rs"]}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expect(cfg.browser.enabled);
    try std.testing.expectEqual(@as(usize, 2), cfg.browser.allowed_domains.len);
    try std.testing.expectEqualStrings("github.com", cfg.browser.allowed_domains[0]);
    try std.testing.expectEqualStrings("docs.rs", cfg.browser.allowed_domains[1]);
    for (cfg.browser.allowed_domains) |d| allocator.free(d);
    allocator.free(cfg.browser.allowed_domains);
}

test "json parse model routes" {
    const allocator = std.testing.allocator;
    const json =
        \\{"model_routes": [
        \\  {"hint": "reasoning", "provider": "openrouter", "model": "anthropic/claude-opus-4"},
        \\  {"hint": "fast", "provider": "groq", "model": "llama-3.3-70b", "api_key": "gsk_test"}
        \\]}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.model_routes.len);
    try std.testing.expectEqualStrings("reasoning", cfg.model_routes[0].hint);
    try std.testing.expectEqualStrings("openrouter", cfg.model_routes[0].provider);
    try std.testing.expectEqualStrings("anthropic/claude-opus-4", cfg.model_routes[0].model);
    try std.testing.expect(cfg.model_routes[0].api_key == null);
    try std.testing.expectEqualStrings("fast", cfg.model_routes[1].hint);
    try std.testing.expectEqualStrings("groq", cfg.model_routes[1].provider);
    try std.testing.expectEqualStrings("llama-3.3-70b", cfg.model_routes[1].model);
    try std.testing.expectEqualStrings("gsk_test", cfg.model_routes[1].api_key.?);
    // Cleanup
    for (cfg.model_routes) |r| {
        allocator.free(r.hint);
        allocator.free(r.provider);
        allocator.free(r.model);
        if (r.api_key) |k| allocator.free(k);
    }
    allocator.free(cfg.model_routes);
}

test "json parse model routes skips invalid entries" {
    const allocator = std.testing.allocator;
    const json =
        \\{"model_routes": [
        \\  {"hint": "ok", "provider": "p", "model": "m"},
        \\  {"hint": "missing_model", "provider": "p"},
        \\  {"invalid": true}
        \\]}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.model_routes.len);
    try std.testing.expectEqualStrings("ok", cfg.model_routes[0].hint);
    allocator.free(cfg.model_routes[0].hint);
    allocator.free(cfg.model_routes[0].provider);
    allocator.free(cfg.model_routes[0].model);
    allocator.free(cfg.model_routes);
}

test "json parse agents" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": [
        \\  {"name": "researcher", "provider": "anthropic", "model": "claude-sonnet-4", "system_prompt": "Research things", "max_depth": 5},
        \\  {"name": "coder", "provider": "openai", "model": "gpt-4o", "api_key": "sk-test", "temperature": 0.3}
        \\]}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.agents.len);
    try std.testing.expectEqualStrings("researcher", cfg.agents[0].name);
    try std.testing.expectEqualStrings("anthropic", cfg.agents[0].provider);
    try std.testing.expectEqualStrings("claude-sonnet-4", cfg.agents[0].model);
    try std.testing.expectEqualStrings("Research things", cfg.agents[0].system_prompt.?);
    try std.testing.expectEqual(@as(u32, 5), cfg.agents[0].max_depth);
    try std.testing.expect(cfg.agents[0].api_key == null);
    try std.testing.expectEqualStrings("coder", cfg.agents[1].name);
    try std.testing.expectEqualStrings("openai", cfg.agents[1].provider);
    try std.testing.expectEqualStrings("gpt-4o", cfg.agents[1].model);
    try std.testing.expectEqualStrings("sk-test", cfg.agents[1].api_key.?);
    try std.testing.expectEqual(@as(f64, 0.3), cfg.agents[1].temperature.?);
    try std.testing.expectEqual(@as(u32, 3), cfg.agents[1].max_depth);
    // Cleanup
    for (cfg.agents) |a| {
        allocator.free(a.name);
        allocator.free(a.provider);
        allocator.free(a.model);
        if (a.system_prompt) |sp| allocator.free(sp);
        if (a.api_key) |k| allocator.free(k);
    }
    allocator.free(cfg.agents);
}

test "json parse agents skips invalid entries" {
    const allocator = std.testing.allocator;
    const json =
        \\{"agents": [
        \\  {"name": "ok", "provider": "p", "model": "m"},
        \\  {"name": "missing_model", "provider": "p"},
        \\  42
        \\]}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("ok", cfg.agents[0].name);
    allocator.free(cfg.agents[0].name);
    allocator.free(cfg.agents[0].provider);
    allocator.free(cfg.agents[0].model);
    allocator.free(cfg.agents);
}

// ── Combined: all new fields in one JSON ────────────────────────

test "json parse all new fields together" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "model_routes": [{"hint": "fast", "provider": "groq", "model": "llama-3.3-70b"}],
        \\  "agents": [{"name": "helper", "provider": "anthropic", "model": "claude-haiku-3.5"}],
        \\  "autonomy": {"allowed_commands": ["ls"], "forbidden_paths": ["/root"]},
        \\  "gateway": {"paired_tokens": ["tok-1"]},
        \\  "browser": {"allowed_domains": ["example.com"]}
        \\}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.model_routes.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.autonomy.allowed_commands.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.autonomy.forbidden_paths.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.gateway.paired_tokens.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.browser.allowed_domains.len);
    // Cleanup
    allocator.free(cfg.model_routes[0].hint);
    allocator.free(cfg.model_routes[0].provider);
    allocator.free(cfg.model_routes[0].model);
    allocator.free(cfg.model_routes);
    allocator.free(cfg.agents[0].name);
    allocator.free(cfg.agents[0].provider);
    allocator.free(cfg.agents[0].model);
    allocator.free(cfg.agents);
    allocator.free(cfg.autonomy.allowed_commands[0]);
    allocator.free(cfg.autonomy.allowed_commands);
    allocator.free(cfg.autonomy.forbidden_paths[0]);
    allocator.free(cfg.autonomy.forbidden_paths);
    allocator.free(cfg.gateway.paired_tokens[0]);
    allocator.free(cfg.gateway.paired_tokens);
    allocator.free(cfg.browser.allowed_domains[0]);
    allocator.free(cfg.browser.allowed_domains);
}

test "json parse api_url" {
    const allocator = std.testing.allocator;
    const json =
        \\{"api_url": "http://10.0.0.1:11434"}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("http://10.0.0.1:11434", cfg.api_url.?);
    allocator.free(cfg.api_url.?);
}

// ── Environment variable override tests ─────────────────────────

test "applyEnvOverrides does not crash on default config" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    // Should not crash even when no NULLCLAW_* env vars are set
    cfg.applyEnvOverrides();
    // Default values should remain intact
    try std.testing.expectEqualStrings("openrouter", cfg.default_provider);
    try std.testing.expectEqualStrings("anthropic/claude-sonnet-4", cfg.default_model.?);
    try std.testing.expect(cfg.api_key == null);
    try std.testing.expect(cfg.api_url == null);
}

test "json parse mcp_servers" {
    const allocator = std.testing.allocator;
    const json =
        \\{"mcp_servers": {
        \\  "filesystem": {
        \\    "command": "npx",
        \\    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        \\  },
        \\  "git": {
        \\    "command": "mcp-server-git"
        \\  }
        \\}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 2), cfg.mcp_servers.len);
    // Find filesystem entry (order may vary due to hash map)
    var found_fs = false;
    var found_git = false;
    for (cfg.mcp_servers) |s| {
        if (std.mem.eql(u8, s.name, "filesystem")) {
            found_fs = true;
            try std.testing.expectEqualStrings("npx", s.command);
            try std.testing.expectEqual(@as(usize, 3), s.args.len);
            try std.testing.expectEqualStrings("-y", s.args[0]);
        }
        if (std.mem.eql(u8, s.name, "git")) {
            found_git = true;
            try std.testing.expectEqualStrings("mcp-server-git", s.command);
            try std.testing.expectEqual(@as(usize, 0), s.args.len);
        }
    }
    try std.testing.expect(found_fs);
    try std.testing.expect(found_git);
    // Cleanup
    for (cfg.mcp_servers) |s| {
        allocator.free(s.name);
        allocator.free(s.command);
        for (s.args) |a| allocator.free(a);
        allocator.free(s.args);
    }
    allocator.free(cfg.mcp_servers);
}

test "json parse mcp_servers with env" {
    const allocator = std.testing.allocator;
    const json =
        \\{"mcp_servers": {
        \\  "myserver": {
        \\    "command": "/usr/bin/server",
        \\    "args": ["--verbose"],
        \\    "env": {"NODE_ENV": "production", "DEBUG": "true"}
        \\  }
        \\}}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqual(@as(usize, 1), cfg.mcp_servers.len);
    const s = cfg.mcp_servers[0];
    try std.testing.expectEqualStrings("myserver", s.name);
    try std.testing.expectEqualStrings("/usr/bin/server", s.command);
    try std.testing.expectEqual(@as(usize, 1), s.args.len);
    try std.testing.expectEqual(@as(usize, 2), s.env.len);
    // Find env entries (order may vary)
    var found_node = false;
    var found_debug = false;
    for (s.env) |e| {
        if (std.mem.eql(u8, e.key, "NODE_ENV")) {
            found_node = true;
            try std.testing.expectEqualStrings("production", e.value);
        }
        if (std.mem.eql(u8, e.key, "DEBUG")) {
            found_debug = true;
            try std.testing.expectEqualStrings("true", e.value);
        }
    }
    try std.testing.expect(found_node);
    try std.testing.expect(found_debug);
    // Cleanup
    allocator.free(s.name);
    allocator.free(s.command);
    for (s.args) |a| allocator.free(a);
    allocator.free(s.args);
    for (s.env) |e| {
        allocator.free(e.key);
        allocator.free(e.value);
    }
    allocator.free(s.env);
    allocator.free(cfg.mcp_servers);
}

test "json parse groq_api_key" {
    const allocator = std.testing.allocator;
    const json =
        \\{"groq_api_key": "gsk_test_abc123"}
    ;
    var cfg = Config{ .workspace_dir = "/tmp/yc", .config_path = "/tmp/yc/config.json", .allocator = allocator };
    try cfg.parseJson(json);
    try std.testing.expectEqualStrings("gsk_test_abc123", cfg.groq_api_key.?);
    allocator.free(cfg.groq_api_key.?);
}

test "groq_api_key defaults to null" {
    const cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    try std.testing.expect(cfg.groq_api_key == null);
}
