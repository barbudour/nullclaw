//! Agent Routing — OpenClaw-compatible agent bindings routing system.
//!
//! Routes incoming messages to the correct agent based on a tiered matching
//! system. Bindings are checked against the input in priority order:
//!   1. peer        — exact peer (kind + id) match
//!   2. parent_peer — peer matches the parent (e.g. thread starter)
//!   3. guild_roles — guild_id + at least one matching role
//!   4. guild       — guild_id only (no roles)
//!   5. team        — team_id match
//!   6. account     — channel + account_id only
//!   7. channel_only— channel only (no account_id/peer/guild/team/roles)
//!
//! If no binding matches, the default agent is used (first in agents list,
//! or "main" if the list is empty).

const std = @import("std");
const config_types = @import("config_types.zig");
const NamedAgentConfig = config_types.NamedAgentConfig;

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

pub const ChatType = enum {
    direct,
    group,
    channel,
};

pub const PeerRef = struct {
    kind: ChatType,
    id: []const u8,
};

pub const BindingMatch = struct {
    channel: ?[]const u8 = null,
    account_id: ?[]const u8 = null,
    peer: ?PeerRef = null,
    guild_id: ?[]const u8 = null,
    team_id: ?[]const u8 = null,
    roles: []const []const u8 = &.{},
};

pub const AgentBinding = struct {
    agent_id: []const u8,
    comment: ?[]const u8 = null,
    match: BindingMatch = .{},
};

pub const MatchedBy = enum {
    peer,
    parent_peer,
    guild_roles,
    guild,
    team,
    account,
    channel_only,
    default,
};

pub const ResolvedRoute = struct {
    agent_id: []const u8,
    channel: []const u8,
    account_id: []const u8,
    session_key: []const u8,
    matched_by: MatchedBy,
};

pub const RouteInput = struct {
    channel: []const u8,
    account_id: []const u8,
    peer: ?PeerRef = null,
    parent_peer: ?PeerRef = null,
    guild_id: ?[]const u8 = null,
    team_id: ?[]const u8 = null,
    member_role_ids: []const []const u8 = &.{},
};

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Build a session key: `agent:{agent_id}:{channel}:{peer_kind}:{peer_id}`
/// Returns owned slice; caller must free with the same allocator.
pub fn buildSessionKey(
    allocator: std.mem.Allocator,
    agent_id: []const u8,
    channel: []const u8,
    peer: ?PeerRef,
) ![]u8 {
    if (peer) |p| {
        const kind_str = switch (p.kind) {
            .direct => "direct",
            .group => "group",
            .channel => "channel",
        };
        return std.fmt.allocPrint(allocator, "agent:{s}:{s}:{s}:{s}", .{
            agent_id, channel, kind_str, p.id,
        });
    }
    return std.fmt.allocPrint(allocator, "agent:{s}:{s}:none:none", .{
        agent_id, channel,
    });
}

/// Find the default agent from a named agents list.
/// Returns the first agent's name, or "main" if the list is empty.
pub fn findDefaultAgent(agents: []const NamedAgentConfig) []const u8 {
    if (agents.len > 0) return agents[0].name;
    return "main";
}

/// Check if two PeerRef values match (same kind and id).
pub fn peerMatches(binding_peer: ?PeerRef, input_peer: ?PeerRef) bool {
    const bp = binding_peer orelse return false;
    const ip = input_peer orelse return false;
    return bp.kind == ip.kind and std.mem.eql(u8, bp.id, ip.id);
}

/// Pre-filter: check that a binding's channel and account_id constraints
/// match the input. A null constraint means "any" (matches everything).
pub fn bindingMatchesScope(binding: AgentBinding, input: RouteInput) bool {
    if (binding.match.channel) |bc| {
        if (!std.mem.eql(u8, bc, input.channel)) return false;
    }
    if (binding.match.account_id) |ba| {
        if (!std.mem.eql(u8, ba, input.account_id)) return false;
    }
    return true;
}

/// Returns true if the binding has no peer, guild_id, team_id, or roles set
/// (only channel and/or account_id).
fn isAccountOnly(b: AgentBinding) bool {
    return b.match.peer == null and
        b.match.guild_id == null and
        b.match.team_id == null and
        b.match.roles.len == 0;
}

/// Returns true if the binding has only a channel constraint (no account_id,
/// peer, guild_id, team_id, or roles).
fn isChannelOnly(b: AgentBinding) bool {
    return b.match.account_id == null and
        b.match.peer == null and
        b.match.guild_id == null and
        b.match.team_id == null and
        b.match.roles.len == 0;
}

/// Check if any role in `binding_roles` appears in `member_roles`.
fn hasMatchingRole(binding_roles: []const []const u8, member_roles: []const []const u8) bool {
    for (binding_roles) |br| {
        for (member_roles) |mr| {
            if (std.mem.eql(u8, br, mr)) return true;
        }
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// Route resolution
// ═══════════════════════════════════════════════════════════════════════════

/// Resolve the agent route for a given input.
///
/// Walks 7 tiers of binding matches in priority order and returns the
/// first match found. Falls back to the default agent if none match.
/// The returned `session_key` is allocated; caller must free it.
pub fn resolveRoute(
    allocator: std.mem.Allocator,
    input: RouteInput,
    bindings: []const AgentBinding,
    agents: []const NamedAgentConfig,
) !ResolvedRoute {
    // Pre-filter bindings by channel + account_id scope.
    var candidates: std.ArrayListUnmanaged(AgentBinding) = .empty;
    defer candidates.deinit(allocator);

    for (bindings) |b| {
        if (bindingMatchesScope(b, input)) {
            try candidates.append(allocator, b);
        }
    }

    // Tier 1: peer match
    for (candidates.items) |b| {
        if (peerMatches(b.match.peer, input.peer)) {
            return buildRoute(allocator, b.agent_id, input, .peer);
        }
    }

    // Tier 2: parent_peer match
    for (candidates.items) |b| {
        if (peerMatches(b.match.peer, input.parent_peer)) {
            return buildRoute(allocator, b.agent_id, input, .parent_peer);
        }
    }

    // Tier 3: guild_id + roles match
    for (candidates.items) |b| {
        if (b.match.guild_id) |bg| {
            if (input.guild_id) |ig| {
                if (std.mem.eql(u8, bg, ig) and
                    b.match.roles.len > 0 and
                    hasMatchingRole(b.match.roles, input.member_role_ids))
                {
                    return buildRoute(allocator, b.agent_id, input, .guild_roles);
                }
            }
        }
    }

    // Tier 4: guild_id only (no roles on binding)
    for (candidates.items) |b| {
        if (b.match.guild_id) |bg| {
            if (input.guild_id) |ig| {
                if (std.mem.eql(u8, bg, ig) and b.match.roles.len == 0) {
                    return buildRoute(allocator, b.agent_id, input, .guild);
                }
            }
        }
    }

    // Tier 5: team_id match
    for (candidates.items) |b| {
        if (b.match.team_id) |bt| {
            if (input.team_id) |it| {
                if (std.mem.eql(u8, bt, it)) {
                    return buildRoute(allocator, b.agent_id, input, .team);
                }
            }
        }
    }

    // Tier 6: account only (channel + account_id, no peer/guild/team/roles)
    for (candidates.items) |b| {
        if (b.match.account_id != null and isAccountOnly(b)) {
            return buildRoute(allocator, b.agent_id, input, .account);
        }
    }

    // Tier 7: channel only (no account_id/peer/guild/team/roles)
    for (candidates.items) |b| {
        if (isChannelOnly(b)) {
            return buildRoute(allocator, b.agent_id, input, .channel_only);
        }
    }

    // No match — use default agent.
    const default_id = findDefaultAgent(agents);
    return buildRoute(allocator, default_id, input, .default);
}

/// Internal helper to construct a ResolvedRoute with an allocated session key.
fn buildRoute(
    allocator: std.mem.Allocator,
    agent_id: []const u8,
    input: RouteInput,
    matched_by: MatchedBy,
) !ResolvedRoute {
    const session_key = try buildSessionKey(allocator, agent_id, input.channel, input.peer);
    return .{
        .agent_id = agent_id,
        .channel = input.channel,
        .account_id = input.account_id,
        .session_key = session_key,
        .matched_by = matched_by,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test {
    std.testing.refAllDecls(@This());
}

test "resolveRoute — no bindings returns default agent" {
    const allocator = std.testing.allocator;
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
    };
    const agents = [_]NamedAgentConfig{.{
        .name = "helper",
        .provider = "openai",
        .model = "gpt-4",
    }};
    const route = try resolveRoute(allocator, input, &.{}, &agents);
    defer allocator.free(route.session_key);

    try std.testing.expectEqualStrings("helper", route.agent_id);
    try std.testing.expectEqual(MatchedBy.default, route.matched_by);
    try std.testing.expectEqualStrings("discord", route.channel);
    try std.testing.expectEqualStrings("acct1", route.account_id);
}

test "resolveRoute — peer match returns correct agent" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "support-bot",
            .match = .{
                .peer = .{ .kind = .direct, .id = "user42" },
            },
        },
        .{
            .agent_id = "general-bot",
        },
    };
    const input = RouteInput{
        .channel = "telegram",
        .account_id = "acct1",
        .peer = .{ .kind = .direct, .id = "user42" },
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);

    try std.testing.expectEqualStrings("support-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.peer, route.matched_by);
}

test "resolveRoute — guild+roles match (tier 3)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "mod-bot",
        .match = .{
            .guild_id = "guild1",
            .roles = &.{ "moderator", "admin" },
        },
    }};
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
        .guild_id = "guild1",
        .member_role_ids = &.{"moderator"},
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);

    try std.testing.expectEqualStrings("mod-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.guild_roles, route.matched_by);
}

test "resolveRoute — guild-only match (tier 4)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "guild-bot",
        .match = .{
            .guild_id = "guild1",
        },
    }};
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
        .guild_id = "guild1",
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);

    try std.testing.expectEqualStrings("guild-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.guild, route.matched_by);
}

test "resolveRoute — channel-only match (tier 7)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "catch-all",
        .match = .{
            .channel = "slack",
        },
    }};
    const input = RouteInput{
        .channel = "slack",
        .account_id = "acct99",
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);

    try std.testing.expectEqualStrings("catch-all", route.agent_id);
    try std.testing.expectEqual(MatchedBy.channel_only, route.matched_by);
}

test "resolveRoute — tier priority: peer wins over guild" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "guild-bot",
            .match = .{ .guild_id = "guild1" },
        },
        .{
            .agent_id = "peer-bot",
            .match = .{
                .peer = .{ .kind = .direct, .id = "user1" },
            },
        },
    };
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
        .peer = .{ .kind = .direct, .id = "user1" },
        .guild_id = "guild1",
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);

    try std.testing.expectEqualStrings("peer-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.peer, route.matched_by);
}

test "resolveRoute — parent_peer match (tier 2)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "thread-bot",
        .match = .{
            .peer = .{ .kind = .group, .id = "thread99" },
        },
    }};
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
        .peer = .{ .kind = .direct, .id = "user5" },
        .parent_peer = .{ .kind = .group, .id = "thread99" },
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);

    try std.testing.expectEqualStrings("thread-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.parent_peer, route.matched_by);
}

test "resolveRoute — team match (tier 5)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "team-bot",
        .match = .{ .team_id = "T123" },
    }};
    const input = RouteInput{
        .channel = "slack",
        .account_id = "acct1",
        .team_id = "T123",
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);

    try std.testing.expectEqualStrings("team-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.team, route.matched_by);
}

test "resolveRoute — account match (tier 6)" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "acct-bot",
        .match = .{
            .channel = "telegram",
            .account_id = "acct7",
        },
    }};
    const input = RouteInput{
        .channel = "telegram",
        .account_id = "acct7",
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);

    try std.testing.expectEqualStrings("acct-bot", route.agent_id);
    try std.testing.expectEqual(MatchedBy.account, route.matched_by);
}

test "resolveRoute — scope pre-filter excludes mismatched channel" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{.{
        .agent_id = "discord-only",
        .match = .{
            .channel = "discord",
            .peer = .{ .kind = .direct, .id = "user1" },
        },
    }};
    // Input is on "telegram", not "discord" — binding should be excluded.
    const input = RouteInput{
        .channel = "telegram",
        .account_id = "acct1",
        .peer = .{ .kind = .direct, .id = "user1" },
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);

    // No match — falls through to default.
    try std.testing.expectEqual(MatchedBy.default, route.matched_by);
    try std.testing.expectEqualStrings("main", route.agent_id);
}

test "resolveRoute — guild_roles no matching role falls to guild tier" {
    const allocator = std.testing.allocator;
    const bindings = [_]AgentBinding{
        .{
            .agent_id = "role-bot",
            .match = .{
                .guild_id = "guild1",
                .roles = &.{"admin"},
            },
        },
        .{
            .agent_id = "guild-fallback",
            .match = .{
                .guild_id = "guild1",
            },
        },
    };
    // User has "member" role, not "admin" — role binding should NOT match,
    // but guild-only binding should.
    const input = RouteInput{
        .channel = "discord",
        .account_id = "acct1",
        .guild_id = "guild1",
        .member_role_ids = &.{"member"},
    };
    const route = try resolveRoute(allocator, input, &bindings, &.{});
    defer allocator.free(route.session_key);

    try std.testing.expectEqualStrings("guild-fallback", route.agent_id);
    try std.testing.expectEqual(MatchedBy.guild, route.matched_by);
}

test "buildSessionKey — with peer" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKey(allocator, "bot1", "discord", .{
        .kind = .direct,
        .id = "user42",
    });
    defer allocator.free(key);

    try std.testing.expectEqualStrings("agent:bot1:discord:direct:user42", key);
}

test "buildSessionKey — without peer" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKey(allocator, "bot1", "telegram", null);
    defer allocator.free(key);

    try std.testing.expectEqualStrings("agent:bot1:telegram:none:none", key);
}

test "buildSessionKey — group peer kind" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKey(allocator, "agent-x", "slack", .{
        .kind = .group,
        .id = "G1234",
    });
    defer allocator.free(key);

    try std.testing.expectEqualStrings("agent:agent-x:slack:group:G1234", key);
}

test "buildSessionKey — channel peer kind" {
    const allocator = std.testing.allocator;
    const key = try buildSessionKey(allocator, "mybot", "irc", .{
        .kind = .channel,
        .id = "#general",
    });
    defer allocator.free(key);

    try std.testing.expectEqualStrings("agent:mybot:irc:channel:#general", key);
}

test "findDefaultAgent — empty list returns main" {
    const result = findDefaultAgent(&.{});
    try std.testing.expectEqualStrings("main", result);
}

test "findDefaultAgent — returns first agent name" {
    const agents = [_]NamedAgentConfig{
        .{ .name = "alpha", .provider = "openai", .model = "gpt-4" },
        .{ .name = "beta", .provider = "anthropic", .model = "claude-3" },
    };
    const result = findDefaultAgent(&agents);
    try std.testing.expectEqualStrings("alpha", result);
}

test "peerMatches — both present and equal" {
    try std.testing.expect(peerMatches(
        .{ .kind = .direct, .id = "u1" },
        .{ .kind = .direct, .id = "u1" },
    ));
}

test "peerMatches — different kind" {
    try std.testing.expect(!peerMatches(
        .{ .kind = .direct, .id = "u1" },
        .{ .kind = .group, .id = "u1" },
    ));
}

test "peerMatches — different id" {
    try std.testing.expect(!peerMatches(
        .{ .kind = .direct, .id = "u1" },
        .{ .kind = .direct, .id = "u2" },
    ));
}

test "peerMatches — binding null" {
    try std.testing.expect(!peerMatches(null, .{ .kind = .direct, .id = "u1" }));
}

test "peerMatches — input null" {
    try std.testing.expect(!peerMatches(.{ .kind = .direct, .id = "u1" }, null));
}

test "peerMatches — both null" {
    try std.testing.expect(!peerMatches(null, null));
}

test "bindingMatchesScope — null constraints match anything" {
    const b = AgentBinding{ .agent_id = "x" };
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    try std.testing.expect(bindingMatchesScope(b, input));
}

test "bindingMatchesScope — matching channel and account" {
    const b = AgentBinding{
        .agent_id = "x",
        .match = .{ .channel = "discord", .account_id = "acct1" },
    };
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    try std.testing.expect(bindingMatchesScope(b, input));
}

test "bindingMatchesScope — mismatched channel" {
    const b = AgentBinding{
        .agent_id = "x",
        .match = .{ .channel = "slack" },
    };
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    try std.testing.expect(!bindingMatchesScope(b, input));
}

test "bindingMatchesScope — mismatched account_id" {
    const b = AgentBinding{
        .agent_id = "x",
        .match = .{ .account_id = "acct2" },
    };
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    try std.testing.expect(!bindingMatchesScope(b, input));
}

test "bindingMatchesScope — channel matches, account null (any)" {
    const b = AgentBinding{
        .agent_id = "x",
        .match = .{ .channel = "discord" },
    };
    const input = RouteInput{ .channel = "discord", .account_id = "acct1" };
    try std.testing.expect(bindingMatchesScope(b, input));
}
