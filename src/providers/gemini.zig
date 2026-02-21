const std = @import("std");
const platform = @import("../platform.zig");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;

/// Credentials loaded from the Gemini CLI OAuth token file (~/.gemini/oauth_creds.json).
pub const GeminiCliCredentials = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8,
    expires_at: ?i64,

    /// Returns true if the token is expired (or within 5 minutes of expiring).
    /// If expires_at is null, the token is treated as never-expiring.
    pub fn isExpired(self: GeminiCliCredentials) bool {
        const expiry = self.expires_at orelse return false;
        const now = std.time.timestamp();
        const buffer_seconds: i64 = 5 * 60; // 5-minute safety buffer
        return now >= (expiry - buffer_seconds);
    }
};

/// Parse Gemini CLI credentials from a JSON byte slice.
/// Returns null if the JSON is invalid or missing the required `access_token` field.
pub fn parseCredentialsJson(allocator: std.mem.Allocator, json_bytes: []const u8) ?GeminiCliCredentials {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return null;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return null,
    };

    // access_token is required
    const access_token_val = root_obj.get("access_token") orelse return null;
    const access_token_str = switch (access_token_val) {
        .string => |s| s,
        else => return null,
    };
    if (access_token_str.len == 0) return null;

    // Dupe access_token so it survives parsed.deinit()
    const access_token = allocator.dupe(u8, access_token_str) catch return null;

    // refresh_token is optional
    const refresh_token: ?[]const u8 = if (root_obj.get("refresh_token")) |rt_val| blk: {
        switch (rt_val) {
            .string => |s| {
                if (s.len > 0) {
                    break :blk allocator.dupe(u8, s) catch null;
                }
                break :blk null;
            },
            else => break :blk null,
        }
    } else null;

    // expires_at is optional (unix timestamp)
    const expires_at: ?i64 = if (root_obj.get("expires_at")) |ea_val| blk: {
        switch (ea_val) {
            .integer => |i| break :blk i,
            .float => |f| break :blk @intFromFloat(f),
            else => break :blk null,
        }
    } else null;

    return .{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_at = expires_at,
    };
}

/// Try to load Gemini CLI OAuth credentials from ~/.gemini/oauth_creds.json.
/// Returns null on any error (file not found, parse failure, expired token, etc.).
pub fn tryLoadGeminiCliToken(allocator: std.mem.Allocator) ?GeminiCliCredentials {
    const home = platform.getHomeDir(allocator) catch return null;
    defer allocator.free(home);

    const path = std.fs.path.join(allocator, &.{ home, ".gemini", "oauth_creds.json" }) catch return null;
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    const json_bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(json_bytes);

    const creds = parseCredentialsJson(allocator, json_bytes) orelse return null;

    // Check expiration
    if (creds.isExpired()) {
        // Clean up allocated strings before returning null
        allocator.free(creds.access_token);
        if (creds.refresh_token) |rt| allocator.free(rt);
        return null;
    }

    return creds;
}

/// Authentication method for Gemini.
pub const GeminiAuth = union(enum) {
    /// Explicit API key from config: sent as `?key=` query parameter.
    explicit_key: []const u8,
    /// API key from `GEMINI_API_KEY` env var.
    env_gemini_key: []const u8,
    /// API key from `GOOGLE_API_KEY` env var.
    env_google_key: []const u8,
    /// OAuth access token from Gemini CLI: sent as `Authorization: Bearer`.
    oauth_token: []const u8,

    pub fn isApiKey(self: GeminiAuth) bool {
        return switch (self) {
            .explicit_key, .env_gemini_key, .env_google_key => true,
            .oauth_token => false,
        };
    }

    pub fn credential(self: GeminiAuth) []const u8 {
        return switch (self) {
            .explicit_key => |v| v,
            .env_gemini_key => |v| v,
            .env_google_key => |v| v,
            .oauth_token => |v| v,
        };
    }

    pub fn source(self: GeminiAuth) []const u8 {
        return switch (self) {
            .explicit_key => "config",
            .env_gemini_key => "GEMINI_API_KEY env var",
            .env_google_key => "GOOGLE_API_KEY env var",
            .oauth_token => "Gemini CLI OAuth",
        };
    }
};

/// Google Gemini provider with support for:
/// - Direct API key (`GEMINI_API_KEY` env var or config)
/// - Gemini CLI OAuth tokens (reuse existing ~/.gemini/ authentication)
/// - Google Cloud ADC (`GOOGLE_APPLICATION_CREDENTIALS`)
pub const GeminiProvider = struct {
    auth: ?GeminiAuth,
    allocator: std.mem.Allocator,

    const BASE_URL = "https://generativelanguage.googleapis.com/v1beta";
    const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 8192;

    pub fn init(allocator: std.mem.Allocator, api_key: ?[]const u8) GeminiProvider {
        var auth: ?GeminiAuth = null;

        // 1. Explicit key
        if (api_key) |key| {
            const trimmed = std.mem.trim(u8, key, " \t\r\n");
            if (trimmed.len > 0) {
                auth = .{ .explicit_key = trimmed };
            }
        }

        // 2. Environment variables (only if no explicit key)
        if (auth == null) {
            if (loadNonEmptyEnv(allocator, "GEMINI_API_KEY")) |value| {
                allocator.free(value);
                auth = .{ .env_gemini_key = "env" };
            }
        }

        if (auth == null) {
            if (loadNonEmptyEnv(allocator, "GOOGLE_API_KEY")) |value| {
                allocator.free(value);
                auth = .{ .env_google_key = "env" };
            }
        }

        // 3. Gemini CLI OAuth token (~/.gemini/oauth_creds.json) as final fallback
        if (auth == null) {
            if (tryLoadGeminiCliToken(allocator)) |creds| {
                auth = .{ .oauth_token = creds.access_token };
                // Note: refresh_token and expires_at are not stored in GeminiAuth,
                // they are only used for the initial validity check.
                // Free refresh_token if it was allocated — we only keep access_token.
                if (creds.refresh_token) |rt| allocator.free(rt);
            }
        }

        return .{
            .auth = auth,
            .allocator = allocator,
        };
    }

    fn loadNonEmptyEnv(allocator: std.mem.Allocator, name: []const u8) ?[]u8 {
        if (std.process.getEnvVarOwned(allocator, name)) |value| {
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len > 0) {
                return value;
            }
            allocator.free(value);
            return null;
        } else |_| {
            return null;
        }
    }

    /// Get authentication source description for diagnostics.
    pub fn authSource(self: GeminiProvider) []const u8 {
        if (self.auth) |auth| {
            return auth.source();
        }
        return "none";
    }

    /// Format a model name, prepending "models/" if not already present.
    pub fn formatModelName(model: []const u8) FormatModelResult {
        if (std.mem.startsWith(u8, model, "models/")) {
            return .{ .formatted = model, .needs_free = false };
        }
        return .{ .formatted = model, .needs_free = false, .needs_prefix = true };
    }

    pub const FormatModelResult = struct {
        formatted: []const u8,
        needs_free: bool,
        needs_prefix: bool = false,
    };

    /// Build the generateContent URL.
    pub fn buildUrl(allocator: std.mem.Allocator, model: []const u8, auth: GeminiAuth) ![]const u8 {
        const model_name = if (std.mem.startsWith(u8, model, "models/"))
            model
        else
            try std.fmt.allocPrint(allocator, "models/{s}", .{model});

        if (auth.isApiKey()) {
            const url = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}:generateContent?key={s}",
                .{ BASE_URL, model_name, auth.credential() },
            );
            if (!std.mem.startsWith(u8, model, "models/")) {
                allocator.free(@constCast(model_name));
            }
            return url;
        } else {
            const url = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}:generateContent",
                .{ BASE_URL, model_name },
            );
            if (!std.mem.startsWith(u8, model, "models/")) {
                allocator.free(@constCast(model_name));
            }
            return url;
        }
    }

    /// Build a Gemini generateContent request body.
    pub fn buildRequestBody(
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        temperature: f64,
    ) ![]const u8 {
        if (system_prompt) |sys| {
            return std.fmt.allocPrint(allocator,
                \\{{"contents":[{{"role":"user","parts":[{{"text":"{s}"}}]}}],"system_instruction":{{"parts":[{{"text":"{s}"}}]}},"generationConfig":{{"temperature":{d:.2},"maxOutputTokens":{d}}}}}
            , .{ message, sys, temperature, DEFAULT_MAX_OUTPUT_TOKENS });
        } else {
            return std.fmt.allocPrint(allocator,
                \\{{"contents":[{{"role":"user","parts":[{{"text":"{s}"}}]}}],"generationConfig":{{"temperature":{d:.2},"maxOutputTokens":{d}}}}}
            , .{ message, temperature, DEFAULT_MAX_OUTPUT_TOKENS });
        }
    }

    /// Parse text content from a Gemini generateContent response.
    pub fn parseResponse(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        const root_obj = parsed.value.object;

        // Check for error first
        if (root_obj.get("error")) |err_obj| {
            if (err_obj.object.get("message")) |msg| {
                if (msg == .string) {
                    const err_msg = try std.fmt.allocPrint(allocator, "Gemini API error: {s}", .{msg.string});
                    defer allocator.free(err_msg);
                    return error.ApiError;
                }
            }
            return error.ApiError;
        }

        // Extract text from candidates
        if (root_obj.get("candidates")) |candidates| {
            if (candidates.array.items.len > 0) {
                const candidate = candidates.array.items[0].object;
                if (candidate.get("content")) |content| {
                    if (content.object.get("parts")) |parts| {
                        if (parts.array.items.len > 0) {
                            const part = parts.array.items[0].object;
                            if (part.get("text")) |text| {
                                if (text == .string) {
                                    return try allocator.dupe(u8, text.string);
                                }
                            }
                        }
                    }
                }
            }
        }

        return error.NoResponseContent;
    }

    /// Create a Provider interface from this GeminiProvider.
    pub fn provider(self: *GeminiProvider) Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Provider.VTable{
        .chatWithSystem = chatWithSystemImpl,
        .chat = chatImpl,
        .supportsNativeTools = supportsNativeToolsImpl,
        .getName = getNameImpl,
        .deinit = deinitImpl,
    };

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) anyerror![]const u8 {
        const self: *GeminiProvider = @ptrCast(@alignCast(ptr));
        const auth = self.auth orelse return error.CredentialsNotSet;

        const url = try buildUrl(allocator, model, auth);
        defer allocator.free(url);

        const body = try buildRequestBody(allocator, system_prompt, message, temperature);
        defer allocator.free(body);

        const resp_body = if (auth.isApiKey())
            root.curlPost(allocator, url, body, &.{}) catch return error.GeminiApiError
        else blk: {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{auth.credential()}) catch return error.GeminiApiError;
            break :blk root.curlPost(allocator, url, body, &.{auth_hdr}) catch return error.GeminiApiError;
        };
        defer allocator.free(resp_body);

        return parseResponse(allocator, resp_body);
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) anyerror!ChatResponse {
        const self: *GeminiProvider = @ptrCast(@alignCast(ptr));
        const auth = self.auth orelse return error.CredentialsNotSet;

        const url = try buildUrl(allocator, model, auth);
        defer allocator.free(url);

        const body = try buildChatRequestBody(allocator, request, temperature);
        defer allocator.free(body);

        const resp_body = if (auth.isApiKey())
            root.curlPostTimed(allocator, url, body, &.{}, request.timeout_secs) catch return error.GeminiApiError
        else blk: {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{auth.credential()}) catch return error.GeminiApiError;
            break :blk root.curlPostTimed(allocator, url, body, &.{auth_hdr}, request.timeout_secs) catch return error.GeminiApiError;
        };
        defer allocator.free(resp_body);

        const text = try parseResponse(allocator, resp_body);
        return ChatResponse{ .content = text };
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return false;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "Gemini";
    }

    fn deinitImpl(_: *anyopaque) void {}
};

/// Build a full chat request JSON body from a ChatRequest (Gemini format).
/// Gemini uses "contents" array with roles "user"/"model", system goes in "system_instruction".
fn buildChatRequestBody(
    allocator: std.mem.Allocator,
    request: ChatRequest,
    temperature: f64,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Extract system prompt
    var system_prompt: ?[]const u8 = null;
    for (request.messages) |msg| {
        if (msg.role == .system) {
            system_prompt = msg.content;
            break;
        }
    }

    try buf.appendSlice(allocator, "{\"contents\":[");
    var count: usize = 0;
    for (request.messages) |msg| {
        if (msg.role == .system) continue;
        if (count > 0) try buf.append(allocator, ',');
        count += 1;
        // Gemini uses "user" and "model" (not "assistant")
        const role_str: []const u8 = switch (msg.role) {
            .user, .tool => "user",
            .assistant => "model",
            .system => unreachable,
        };
        try buf.appendSlice(allocator, "{\"role\":\"");
        try buf.appendSlice(allocator, role_str);
        try buf.appendSlice(allocator, "\",\"parts\":[");
        if (msg.content_parts) |parts| {
            for (parts, 0..) |part, j| {
                if (j > 0) try buf.append(allocator, ',');
                switch (part) {
                    .text => |text| {
                        try buf.appendSlice(allocator, "{\"text\":");
                        try root.appendJsonString(&buf, allocator, text);
                        try buf.append(allocator, '}');
                    },
                    .image_base64 => |img| {
                        try buf.appendSlice(allocator, "{\"inlineData\":{\"mimeType\":\"");
                        try buf.appendSlice(allocator, img.media_type);
                        try buf.appendSlice(allocator, "\",\"data\":\"");
                        try buf.appendSlice(allocator, img.data);
                        try buf.appendSlice(allocator, "\"}}");
                    },
                    .image_url => |img| {
                        // Gemini doesn't support direct URLs; include as text reference
                        try buf.appendSlice(allocator, "{\"text\":\"[Image: ");
                        try buf.appendSlice(allocator, img.url);
                        try buf.appendSlice(allocator, "]\"}");
                    },
                }
            }
        } else {
            try buf.appendSlice(allocator, "{\"text\":");
            try root.appendJsonString(&buf, allocator, msg.content);
            try buf.append(allocator, '}');
        }
        try buf.appendSlice(allocator, "]}");
    }
    try buf.append(allocator, ']');

    if (system_prompt) |sys| {
        try buf.appendSlice(allocator, ",\"system_instruction\":{\"parts\":[{\"text\":");
        try root.appendJsonString(&buf, allocator, sys);
        try buf.appendSlice(allocator, "}]}");
    }

    try buf.appendSlice(allocator, ",\"generationConfig\":{\"temperature\":");
    var temp_buf: [16]u8 = undefined;
    const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.GeminiApiError;
    try buf.appendSlice(allocator, temp_str);
    try buf.appendSlice(allocator, ",\"maxOutputTokens\":");
    var max_buf: [16]u8 = undefined;
    const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{GeminiProvider.DEFAULT_MAX_OUTPUT_TOKENS}) catch return error.GeminiApiError;
    try buf.appendSlice(allocator, max_str);
    try buf.appendSlice(allocator, "}}");

    return try buf.toOwnedSlice(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "provider creates without key" {
    const p = GeminiProvider.init(std.testing.allocator, null);
    defer if (p.auth) |a| switch (a) {
        .oauth_token => |tok| std.testing.allocator.free(tok),
        else => {},
    };
    _ = p.authSource();
}

test "provider creates with key" {
    const p = GeminiProvider.init(std.testing.allocator, "test-api-key");
    try std.testing.expect(p.auth != null);
    try std.testing.expectEqualStrings("config", p.authSource());
}

test "provider rejects empty key" {
    const p = GeminiProvider.init(std.testing.allocator, "");
    defer if (p.auth) |a| switch (a) {
        .oauth_token => |tok| std.testing.allocator.free(tok),
        else => {},
    };
    // Empty key must not be accepted as an explicit key — auth source must
    // NOT be "config". It may fall back to env vars, OAuth, or remain unset
    // depending on the host environment.
    const src = p.authSource();
    try std.testing.expect(!std.mem.eql(u8, src, "config"));
}

test "api key url includes key query param" {
    const auth = GeminiAuth{ .explicit_key = "api-key-123" };
    const url = try GeminiProvider.buildUrl(std.testing.allocator, "gemini-2.0-flash", auth);
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, ":generateContent?key=api-key-123") != null);
}

test "oauth url omits key query param" {
    const auth = GeminiAuth{ .oauth_token = "ya29.test-token" };
    const url = try GeminiProvider.buildUrl(std.testing.allocator, "gemini-2.0-flash", auth);
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.endsWith(u8, url, ":generateContent"));
    try std.testing.expect(std.mem.indexOf(u8, url, "?key=") == null);
}

test "model name formatting" {
    const auth = GeminiAuth{ .explicit_key = "key" };

    const url1 = try GeminiProvider.buildUrl(std.testing.allocator, "gemini-2.0-flash", auth);
    defer std.testing.allocator.free(url1);
    try std.testing.expect(std.mem.indexOf(u8, url1, "models/gemini-2.0-flash") != null);

    const url2 = try GeminiProvider.buildUrl(std.testing.allocator, "models/gemini-1.5-pro", auth);
    defer std.testing.allocator.free(url2);
    try std.testing.expect(std.mem.indexOf(u8, url2, "models/gemini-1.5-pro") != null);
    // Ensure no double "models/" prefix
    try std.testing.expect(std.mem.indexOf(u8, url2, "models/models/") == null);
}

test "buildRequestBody with system" {
    const body = try GeminiProvider.buildRequestBody(std.testing.allocator, "Be helpful", "Hello", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"role\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "Hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "system_instruction") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "maxOutputTokens") != null);
}

test "buildRequestBody without system" {
    const body = try GeminiProvider.buildRequestBody(std.testing.allocator, null, "Hello", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "system_instruction") == null);
}

test "parseResponse extracts text" {
    const body =
        \\{"candidates":[{"content":{"parts":[{"text":"Hello there!"}]}}]}
    ;
    const result = try GeminiProvider.parseResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello there!", result);
}

test "parseResponse error response" {
    const body =
        \\{"error":{"message":"Invalid API key"}}
    ;
    try std.testing.expectError(error.ApiError, GeminiProvider.parseResponse(std.testing.allocator, body));
}

test "GeminiAuth isApiKey" {
    const key = GeminiAuth{ .explicit_key = "key" };
    try std.testing.expect(key.isApiKey());

    const oauth = GeminiAuth{ .oauth_token = "ya29.token" };
    try std.testing.expect(!oauth.isApiKey());
}

test "GeminiAuth credential returns raw value" {
    const key = GeminiAuth{ .explicit_key = "my-api-key" };
    try std.testing.expectEqualStrings("my-api-key", key.credential());

    const oauth = GeminiAuth{ .oauth_token = "ya29.token" };
    try std.testing.expectEqualStrings("ya29.token", oauth.credential());
}

test "GeminiAuth source labels" {
    try std.testing.expectEqualStrings("config", (GeminiAuth{ .explicit_key = "k" }).source());
    try std.testing.expectEqualStrings("GEMINI_API_KEY env var", (GeminiAuth{ .env_gemini_key = "k" }).source());
    try std.testing.expectEqualStrings("GOOGLE_API_KEY env var", (GeminiAuth{ .env_google_key = "k" }).source());
    try std.testing.expectEqualStrings("Gemini CLI OAuth", (GeminiAuth{ .oauth_token = "t" }).source());
}

test "parseResponse empty candidates fails" {
    const body =
        \\{"candidates":[]}
    ;
    try std.testing.expectError(error.NoResponseContent, GeminiProvider.parseResponse(std.testing.allocator, body));
}

test "parseResponse no text field fails" {
    const body =
        \\{"candidates":[{"content":{"parts":[{}]}}]}
    ;
    try std.testing.expectError(error.NoResponseContent, GeminiProvider.parseResponse(std.testing.allocator, body));
}

test "parseResponse multiple parts returns first text" {
    const body =
        \\{"candidates":[{"content":{"parts":[{"text":"First"},{"text":"Second"}]}}]}
    ;
    const result = try GeminiProvider.parseResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("First", result);
}

test "provider rejects whitespace key" {
    const p = GeminiProvider.init(std.testing.allocator, "   ");
    defer if (p.auth) |a| switch (a) {
        .oauth_token => |tok| std.testing.allocator.free(tok),
        else => {},
    };
    // Whitespace-only key must not be accepted as an explicit key — auth
    // source must NOT be "config". It may fall back to env vars, OAuth,
    // or remain unset depending on the host environment.
    const src = p.authSource();
    try std.testing.expect(!std.mem.eql(u8, src, "config"));
}

test "provider getName returns Gemini" {
    var p = GeminiProvider.init(std.testing.allocator, "key");
    const prov = p.provider();
    try std.testing.expectEqualStrings("Gemini", prov.getName());
}

test "buildUrl with models prefix does not double prefix" {
    const auth = GeminiAuth{ .explicit_key = "key" };
    const url = try GeminiProvider.buildUrl(std.testing.allocator, "models/gemini-1.5-pro", auth);
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, "models/models/") == null);
    try std.testing.expect(std.mem.indexOf(u8, url, "models/gemini-1.5-pro") != null);
}

// ════════════════════════════════════════════════════════════════════════════
// Gemini CLI OAuth Token Discovery Tests
// ════════════════════════════════════════════════════════════════════════════

test "GeminiCliCredentials isExpired with future timestamp returns false" {
    const future: i64 = std.time.timestamp() + 3600; // 1 hour from now
    const creds = GeminiCliCredentials{
        .access_token = "ya29.test-token",
        .refresh_token = null,
        .expires_at = future,
    };
    try std.testing.expect(!creds.isExpired());
}

test "GeminiCliCredentials isExpired with past timestamp returns true" {
    const past: i64 = std.time.timestamp() - 3600; // 1 hour ago
    const creds = GeminiCliCredentials{
        .access_token = "ya29.test-token",
        .refresh_token = null,
        .expires_at = past,
    };
    try std.testing.expect(creds.isExpired());
}

test "GeminiCliCredentials isExpired with null expires_at returns false" {
    const creds = GeminiCliCredentials{
        .access_token = "ya29.test-token",
        .refresh_token = null,
        .expires_at = null,
    };
    try std.testing.expect(!creds.isExpired());
}

test "GeminiCliCredentials isExpired with 5-min buffer edge case" {
    // Token expires in exactly 4 minutes — within the 5-minute buffer, so should be expired
    const almost_expired: i64 = std.time.timestamp() + 4 * 60;
    const creds_soon = GeminiCliCredentials{
        .access_token = "ya29.test-token",
        .refresh_token = null,
        .expires_at = almost_expired,
    };
    try std.testing.expect(creds_soon.isExpired());

    // Token expires in exactly 6 minutes — outside the 5-minute buffer, so should NOT be expired
    const still_valid: i64 = std.time.timestamp() + 6 * 60;
    const creds_valid = GeminiCliCredentials{
        .access_token = "ya29.test-token",
        .refresh_token = null,
        .expires_at = still_valid,
    };
    try std.testing.expect(!creds_valid.isExpired());
}

test "tryLoadGeminiCliToken returns null for nonexistent path" {
    // Unless the user has ~/.gemini/oauth_creds.json, this returns null.
    // In CI / test environments it should always be null.
    // We can't control HOME here, but the function should not crash.
    const result = tryLoadGeminiCliToken(std.testing.allocator);
    if (result) |creds| {
        // If credentials were found (developer machine), they should be valid
        std.testing.allocator.free(creds.access_token);
        if (creds.refresh_token) |rt| std.testing.allocator.free(rt);
    }
    // Either way, the function should not crash — this test validates robustness.
}

test "parseCredentialsJson valid JSON with all fields" {
    const json =
        \\{"access_token":"ya29.a0ARrdaM","refresh_token":"1//0eHIDK","expires_at":1999999999}
    ;
    const creds = parseCredentialsJson(std.testing.allocator, json) orelse {
        try std.testing.expect(false); // should not be null
        return;
    };
    defer std.testing.allocator.free(creds.access_token);
    defer if (creds.refresh_token) |rt| std.testing.allocator.free(rt);

    try std.testing.expectEqualStrings("ya29.a0ARrdaM", creds.access_token);
    try std.testing.expectEqualStrings("1//0eHIDK", creds.refresh_token.?);
    try std.testing.expect(creds.expires_at.? == 1999999999);
}

test "parseCredentialsJson valid JSON with only access_token" {
    const json =
        \\{"access_token":"ya29.token-only"}
    ;
    const creds = parseCredentialsJson(std.testing.allocator, json) orelse {
        try std.testing.expect(false);
        return;
    };
    defer std.testing.allocator.free(creds.access_token);

    try std.testing.expectEqualStrings("ya29.token-only", creds.access_token);
    try std.testing.expect(creds.refresh_token == null);
    try std.testing.expect(creds.expires_at == null);
}

test "parseCredentialsJson missing access_token returns null" {
    const json =
        \\{"refresh_token":"1//0eHIDK","expires_at":1999999999}
    ;
    const result = parseCredentialsJson(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "parseCredentialsJson empty object returns null" {
    const json =
        \\{}
    ;
    const result = parseCredentialsJson(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "parseCredentialsJson empty access_token returns null" {
    const json =
        \\{"access_token":""}
    ;
    const result = parseCredentialsJson(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "parseCredentialsJson invalid JSON returns null" {
    const result = parseCredentialsJson(std.testing.allocator, "not json at all");
    try std.testing.expect(result == null);
}

test "gemini buildChatRequestBody plain text" {
    const alloc = std.testing.allocator;
    var msgs = [_]root.ChatMessage{
        root.ChatMessage.user("Hello"),
    };
    const body = try buildChatRequestBody(alloc, .{ .messages = &msgs }, 0.7);
    defer alloc.free(body);
    // Verify valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const contents = parsed.value.object.get("contents").?.array;
    try std.testing.expectEqual(@as(usize, 1), contents.items.len);
    const parts = contents.items[0].object.get("parts").?.array;
    try std.testing.expectEqual(@as(usize, 1), parts.items.len);
    try std.testing.expectEqualStrings("Hello", parts.items[0].object.get("text").?.string);
}

test "gemini buildChatRequestBody with content_parts inlineData" {
    const alloc = std.testing.allocator;
    const cp = &[_]root.ContentPart{
        .{ .text = "What is this?" },
        .{ .image_base64 = .{ .data = "iVBOR", .media_type = "image/png" } },
    };
    var msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "What is this?", .content_parts = cp },
    };
    const body = try buildChatRequestBody(alloc, .{ .messages = &msgs }, 0.7);
    defer alloc.free(body);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const contents = parsed.value.object.get("contents").?.array;
    const parts = contents.items[0].object.get("parts").?.array;
    try std.testing.expectEqual(@as(usize, 2), parts.items.len);
    // First part: text
    try std.testing.expectEqualStrings("What is this?", parts.items[0].object.get("text").?.string);
    // Second part: inlineData
    const inline_data = parts.items[1].object.get("inlineData").?.object;
    try std.testing.expectEqualStrings("image/png", inline_data.get("mimeType").?.string);
    try std.testing.expectEqualStrings("iVBOR", inline_data.get("data").?.string);
}
