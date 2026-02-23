const std = @import("std");
const memory_mod = @import("../memory/root.zig");
const Memory = memory_mod.Memory;
const MemoryEntry = memory_mod.MemoryEntry;

// ═══════════════════════════════════════════════════════════════════════════
// Memory Loader — inject relevant memory context into user messages
// ═══════════════════════════════════════════════════════════════════════════

/// Default number of memory entries to recall per query.
const DEFAULT_RECALL_LIMIT: usize = 5;
const GLOBAL_RECALL_CANDIDATE_LIMIT: usize = 64;

fn containsKey(entries: []const MemoryEntry, key: []const u8) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return true;
    }
    return false;
}

/// Build a memory context preamble by searching stored memories.
///
/// Returns a formatted string like:
/// ```
/// [Memory context]
/// - key1: value1
/// - key2: value2
/// ```
///
/// Returns an empty owned string if no relevant memories are found.
pub fn loadContext(
    allocator: std.mem.Allocator,
    mem: Memory,
    user_message: []const u8,
    session_id: ?[]const u8,
) ![]const u8 {
    const scoped_entries = mem.recall(allocator, user_message, DEFAULT_RECALL_LIMIT, session_id) catch {
        return try allocator.dupe(u8, "");
    };
    defer memory_mod.freeEntries(allocator, scoped_entries);

    // When scoped recall is enabled, also include global (session_id = null) memory
    // so long-term facts from memory_store remain visible in session chats.
    var global_entries: ?[]MemoryEntry = null;
    if (session_id != null and scoped_entries.len < DEFAULT_RECALL_LIMIT) {
        global_entries = mem.recall(allocator, user_message, GLOBAL_RECALL_CANDIDATE_LIMIT, null) catch null;
    }
    defer if (global_entries) |entries| memory_mod.freeEntries(allocator, entries);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    var appended: usize = 0;
    var wrote_header = false;

    for (scoped_entries) |entry| {
        if (!wrote_header) {
            try w.writeAll("[Memory context]\n");
            wrote_header = true;
        }
        try std.fmt.format(w, "- {s}: {s}\n", .{ entry.key, entry.content });
        appended += 1;
        if (appended >= DEFAULT_RECALL_LIMIT) break;
    }

    if (appended < DEFAULT_RECALL_LIMIT and session_id != null) {
        if (global_entries) |entries| {
            for (entries) |entry| {
                if (entry.session_id != null) continue; // keep scoped isolation (no cross-session bleed)
                if (containsKey(scoped_entries, entry.key)) continue;

                if (!wrote_header) {
                    try w.writeAll("[Memory context]\n");
                    wrote_header = true;
                }
                try std.fmt.format(w, "- {s}: {s}\n", .{ entry.key, entry.content });
                appended += 1;
                if (appended >= DEFAULT_RECALL_LIMIT) break;
            }
        }
    }

    if (!wrote_header) {
        return try allocator.dupe(u8, "");
    }
    try w.writeAll("\n");

    return try buf.toOwnedSlice(allocator);
}

/// Enrich a user message with memory context prepended.
/// If no context is available, returns an owned dupe of the original message.
pub fn enrichMessage(
    allocator: std.mem.Allocator,
    mem: Memory,
    user_message: []const u8,
    session_id: ?[]const u8,
) ![]const u8 {
    const context = try loadContext(allocator, mem, user_message, session_id);
    if (context.len == 0) {
        allocator.free(context);
        return try allocator.dupe(u8, user_message);
    }

    defer allocator.free(context);
    return try std.fmt.allocPrint(allocator, "{s}{s}", .{ context, user_message });
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "loadContext returns empty for no-op memory" {
    const allocator = std.testing.allocator;
    var none_mem = memory_mod.NoneMemory.init();
    const mem = none_mem.memory();

    const context = try loadContext(allocator, mem, "hello", null);
    defer allocator.free(context);

    try std.testing.expectEqualStrings("", context);
}

test "enrichMessage with no context returns original" {
    const allocator = std.testing.allocator;
    var none_mem = memory_mod.NoneMemory.init();
    const mem = none_mem.memory();

    const enriched = try enrichMessage(allocator, mem, "hello", null);
    defer allocator.free(enriched);

    try std.testing.expectEqualStrings("hello", enriched);
}

test "loadContext with session_id includes global entries but not other sessions" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("sess_a_fact", "session A favorite", .core, "sess-a");
    try mem.store("global_fact", "global favorite", .core, null);
    try mem.store("sess_b_fact", "session B favorite", .core, "sess-b");

    const context = try loadContext(allocator, mem, "favorite", "sess-a");
    defer allocator.free(context);

    try std.testing.expect(std.mem.indexOf(u8, context, "sess_a_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "global_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "sess_b_fact") == null);
}
