//! Multimodal image processing — [IMAGE:] marker parsing, MIME detection,
//! base64 encoding, and ephemeral content_parts preparation for providers.
//!
//! Ported from ZeroClaw's `src/multimodal.rs`.
//! Images travel as `[IMAGE:path]` markers in content strings through the
//! entire pipeline. Conversion to `content_parts` happens ephemerally at
//! send time (arena-allocated), with no changes to session/agent signatures
//! or message history storage.

const std = @import("std");
const providers = @import("providers/root.zig");
const ChatMessage = providers.ChatMessage;
const ContentPart = providers.ContentPart;

const log = std.log.scoped(.multimodal);

// ════════════════════════════════════════════════════════════════════════════
// Configuration
// ════════════════════════════════════════════════════════════════════════════

pub const MultimodalConfig = struct {
    max_images: u32 = 4,
    max_image_size_bytes: u64 = 5_242_880, // 5 MB
};

pub const default_config = MultimodalConfig{};

// ════════════════════════════════════════════════════════════════════════════
// Image Marker Parsing
// ════════════════════════════════════════════════════════════════════════════

pub const ParseResult = struct {
    cleaned_text: []const u8,
    refs: []const []const u8,
};

/// Scan content for `[IMAGE:...]` markers. Returns the cleaned text (markers
/// removed) and an array of image references (file paths or URLs).
/// All returned slices are allocated on `allocator`.
pub fn parseImageMarkers(allocator: std.mem.Allocator, content: []const u8) !ParseResult {
    var refs: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer refs.deinit(allocator);

    var remaining: std.ArrayListUnmanaged(u8) = .empty;
    errdefer remaining.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < content.len) {
        const open_pos = std.mem.indexOfPos(u8, content, cursor, "[") orelse {
            try remaining.appendSlice(allocator, content[cursor..]);
            break;
        };

        try remaining.appendSlice(allocator, content[cursor..open_pos]);

        const close_pos = std.mem.indexOfPos(u8, content, open_pos, "]") orelse {
            try remaining.appendSlice(allocator, content[open_pos..]);
            break;
        };

        const marker = content[open_pos + 1 .. close_pos];

        if (std.mem.indexOf(u8, marker, ":")) |colon_pos| {
            const kind_str = marker[0..colon_pos];
            const target_raw = marker[colon_pos + 1 ..];
            const target = std.mem.trim(u8, target_raw, " ");

            if (target.len > 0 and isImageKind(kind_str)) {
                try refs.append(allocator, target);
                cursor = close_pos + 1;
                continue;
            }
        }

        // Not a valid [IMAGE:] marker — keep original text
        try remaining.appendSlice(allocator, content[open_pos .. close_pos + 1]);
        cursor = close_pos + 1;
    }

    const trimmed = std.mem.trim(u8, remaining.items, " \t\n\r");
    const cleaned = try allocator.dupe(u8, trimmed);
    remaining.deinit(allocator);

    return .{
        .cleaned_text = cleaned,
        .refs = try refs.toOwnedSlice(allocator),
    };
}

fn isImageKind(kind_str: []const u8) bool {
    return eqlLower(kind_str, "image") or eqlLower(kind_str, "photo") or eqlLower(kind_str, "img");
}

fn eqlLower(a: []const u8, comptime b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (std.ascii.toLower(ac) != bc) return false;
    }
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// MIME Type Detection
// ════════════════════════════════════════════════════════════════════════════

/// Detect MIME type from the first bytes of a file (magic byte sniffing).
pub fn detectMimeType(header: []const u8) ?[]const u8 {
    if (header.len < 4) return null;

    // PNG: 89 50 4E 47
    if (header[0] == 0x89 and header[1] == 'P' and header[2] == 'N' and header[3] == 'G')
        return "image/png";

    // JPEG: FF D8 FF
    if (header[0] == 0xFF and header[1] == 0xD8 and header[2] == 0xFF)
        return "image/jpeg";

    // GIF: GIF8
    if (header[0] == 'G' and header[1] == 'I' and header[2] == 'F' and header[3] == '8')
        return "image/gif";

    // BMP: BM
    if (header[0] == 'B' and header[1] == 'M')
        return "image/bmp";

    // WebP: RIFF....WEBP
    if (header.len >= 12 and
        header[0] == 'R' and header[1] == 'I' and header[2] == 'F' and header[3] == 'F' and
        header[8] == 'W' and header[9] == 'E' and header[10] == 'B' and header[11] == 'P')
        return "image/webp";

    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Local Image Reading
// ════════════════════════════════════════════════════════════════════════════

pub const ImageData = struct {
    data: []const u8,
    mime_type: []const u8,
};

/// Read a local image file, validate its size, and detect MIME type.
/// Returns raw bytes and MIME type. Caller owns the returned `data` slice.
pub fn readLocalImage(allocator: std.mem.Allocator, path: []const u8) !ImageData {
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
        // Try as relative path
        const cwd = std.fs.cwd();
        const f = cwd.openFile(path, .{}) catch return err;
        return readFromFile(allocator, f);
    };
    return readFromFile(allocator, file);
}

fn readFromFile(allocator: std.mem.Allocator, file: std.fs.File) !ImageData {
    defer file.close();

    const stat = try file.stat();
    if (stat.size > default_config.max_image_size_bytes)
        return error.ImageTooLarge;

    const data = try file.readToEndAlloc(allocator, default_config.max_image_size_bytes);
    errdefer allocator.free(data);

    const mime = detectMimeType(data) orelse return error.UnknownImageFormat;

    return .{ .data = data, .mime_type = mime };
}

// ════════════════════════════════════════════════════════════════════════════
// Base64 Encoding
// ════════════════════════════════════════════════════════════════════════════

/// Base64-encode raw bytes. Caller owns the returned slice.
pub fn encodeBase64(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const buf = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(buf, data);
    return buf;
}

// ════════════════════════════════════════════════════════════════════════════
// Message Preparation for Providers
// ════════════════════════════════════════════════════════════════════════════

/// Process messages for multimodal content: scan user messages for [IMAGE:]
/// markers, read local files, base64-encode, and build content_parts.
///
/// All allocations happen on the arena (freed after the provider call).
/// Messages without markers pass through unchanged.
pub fn prepareMessagesForProvider(
    arena: std.mem.Allocator,
    messages: []ChatMessage,
) ![]ChatMessage {
    const result = try arena.alloc(ChatMessage, messages.len);

    for (messages, 0..) |msg, i| {
        if (msg.role != .user or msg.content.len == 0) {
            result[i] = msg;
            continue;
        }

        // Check if content has any [IMAGE: marker
        if (std.mem.indexOf(u8, msg.content, "[IMAGE:") == null and
            std.mem.indexOf(u8, msg.content, "[image:") == null and
            std.mem.indexOf(u8, msg.content, "[Image:") == null and
            std.mem.indexOf(u8, msg.content, "[PHOTO:") == null and
            std.mem.indexOf(u8, msg.content, "[photo:") == null and
            std.mem.indexOf(u8, msg.content, "[IMG:") == null and
            std.mem.indexOf(u8, msg.content, "[img:") == null)
        {
            result[i] = msg;
            continue;
        }

        const parsed = try parseImageMarkers(arena, msg.content);

        if (parsed.refs.len == 0) {
            result[i] = msg;
            continue;
        }

        // Build content_parts: text part + image parts
        var parts: std.ArrayListUnmanaged(ContentPart) = .empty;

        if (parsed.cleaned_text.len > 0) {
            try parts.append(arena, .{ .text = parsed.cleaned_text });
        }

        const max_images = @min(parsed.refs.len, default_config.max_images);
        for (parsed.refs[0..max_images]) |ref| {
            if (isUrl(ref)) {
                // URL-based image — pass through as image_url
                try parts.append(arena, .{ .image_url = .{ .url = ref } });
            } else {
                // Local file — read + base64 encode
                const img = readLocalImage(arena, ref) catch |err| {
                    log.warn("failed to read image '{s}': {}", .{ ref, err });
                    // Add error note as text
                    const note = try std.fmt.allocPrint(arena, "[Failed to load image: {s}]", .{ref});
                    try parts.append(arena, .{ .text = note });
                    continue;
                };
                const b64 = try encodeBase64(arena, img.data);
                try parts.append(arena, .{ .image_base64 = .{
                    .data = b64,
                    .media_type = img.mime_type,
                } });
            }
        }

        result[i] = .{
            .role = msg.role,
            .content = if (parsed.cleaned_text.len > 0) parsed.cleaned_text else msg.content,
            .name = msg.name,
            .tool_call_id = msg.tool_call_id,
            .content_parts = try parts.toOwnedSlice(arena),
        };
    }

    return result;
}

/// Returns true if the string looks like a URL.
pub fn isUrl(s: []const u8) bool {
    return std.mem.startsWith(u8, s, "http://") or
        std.mem.startsWith(u8, s, "https://") or
        std.mem.startsWith(u8, s, "data:");
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "parseImageMarkers single marker" {
    const parsed = try parseImageMarkers(std.testing.allocator, "Look at this [IMAGE:/tmp/photo.png] please");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 1), parsed.refs.len);
    try std.testing.expectEqualStrings("/tmp/photo.png", parsed.refs[0]);
    try std.testing.expectEqualStrings("Look at this  please", parsed.cleaned_text);
}

test "parseImageMarkers multiple markers" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[IMAGE:/a.png] text [IMAGE:/b.jpg]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 2), parsed.refs.len);
    try std.testing.expectEqualStrings("/a.png", parsed.refs[0]);
    try std.testing.expectEqualStrings("/b.jpg", parsed.refs[1]);
    try std.testing.expectEqualStrings("text", parsed.cleaned_text);
}

test "parseImageMarkers no markers" {
    const parsed = try parseImageMarkers(std.testing.allocator, "No images here!");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 0), parsed.refs.len);
    try std.testing.expectEqualStrings("No images here!", parsed.cleaned_text);
}

test "parseImageMarkers empty text" {
    const parsed = try parseImageMarkers(std.testing.allocator, "");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 0), parsed.refs.len);
    try std.testing.expectEqualStrings("", parsed.cleaned_text);
}

test "parseImageMarkers case insensitive" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[image:/a.png] [Image:/b.png] [PHOTO:/c.png]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 3), parsed.refs.len);
}

test "parseImageMarkers invalid marker kept" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[UNKNOWN:/a.bin]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 0), parsed.refs.len);
    try std.testing.expectEqualStrings("[UNKNOWN:/a.bin]", parsed.cleaned_text);
}

test "parseImageMarkers empty target ignored" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[IMAGE:]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 0), parsed.refs.len);
    try std.testing.expectEqualStrings("[IMAGE:]", parsed.cleaned_text);
}

test "parseImageMarkers unclosed bracket" {
    const parsed = try parseImageMarkers(std.testing.allocator, "text [IMAGE:/a.png");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 0), parsed.refs.len);
    try std.testing.expectEqualStrings("text [IMAGE:/a.png", parsed.cleaned_text);
}

test "parseImageMarkers URL target" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[IMAGE:https://example.com/cat.jpg]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 1), parsed.refs.len);
    try std.testing.expectEqualStrings("https://example.com/cat.jpg", parsed.refs[0]);
}

test "parseImageMarkers IMG alias" {
    const parsed = try parseImageMarkers(std.testing.allocator, "[IMG:/tmp/a.png]");
    defer {
        std.testing.allocator.free(parsed.cleaned_text);
        std.testing.allocator.free(parsed.refs);
    }
    try std.testing.expectEqual(@as(usize, 1), parsed.refs.len);
}

test "detectMimeType PNG" {
    const header = [_]u8{ 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
    try std.testing.expectEqualStrings("image/png", detectMimeType(&header).?);
}

test "detectMimeType JPEG" {
    const header = [_]u8{ 0xFF, 0xD8, 0xFF, 0xE0 };
    try std.testing.expectEqualStrings("image/jpeg", detectMimeType(&header).?);
}

test "detectMimeType GIF" {
    const header = [_]u8{ 'G', 'I', 'F', '8', '9', 'a' };
    try std.testing.expectEqualStrings("image/gif", detectMimeType(&header).?);
}

test "detectMimeType BMP" {
    const header = [_]u8{ 'B', 'M', 0x00, 0x00 };
    try std.testing.expectEqualStrings("image/bmp", detectMimeType(&header).?);
}

test "detectMimeType WebP" {
    const header = [_]u8{ 'R', 'I', 'F', 'F', 0, 0, 0, 0, 'W', 'E', 'B', 'P' };
    try std.testing.expectEqualStrings("image/webp", detectMimeType(&header).?);
}

test "detectMimeType unknown" {
    const header = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expect(detectMimeType(&header) == null);
}

test "detectMimeType too short" {
    const header = [_]u8{ 0x89, 'P' };
    try std.testing.expect(detectMimeType(&header) == null);
}

test "encodeBase64 simple" {
    const encoded = try encodeBase64(std.testing.allocator, "Hello");
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("SGVsbG8=", encoded);
}

test "encodeBase64 empty" {
    const encoded = try encodeBase64(std.testing.allocator, "");
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("", encoded);
}

test "encodeBase64 binary data" {
    const data = [_]u8{ 0x89, 0x50, 0x4E, 0x47 };
    const encoded = try encodeBase64(std.testing.allocator, &data);
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("iVBORw==", encoded);
}

test "isUrl http" {
    try std.testing.expect(isUrl("http://example.com/a.png"));
}

test "isUrl https" {
    try std.testing.expect(isUrl("https://example.com/a.png"));
}

test "isUrl data" {
    try std.testing.expect(isUrl("data:image/png;base64,iVBOR"));
}

test "isUrl local path" {
    try std.testing.expect(!isUrl("/tmp/photo.png"));
}

test "isUrl relative path" {
    try std.testing.expect(!isUrl("photos/cat.jpg"));
}

test "MultimodalConfig defaults" {
    const cfg = MultimodalConfig{};
    try std.testing.expectEqual(@as(u32, 4), cfg.max_images);
    try std.testing.expectEqual(@as(u64, 5_242_880), cfg.max_image_size_bytes);
}

test "prepareMessagesForProvider no markers passes through" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.system("Be helpful"),
        ChatMessage.user("Hello, no images"),
        ChatMessage.assistant("Hi there"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs);
    try std.testing.expectEqual(@as(usize, 3), result.len);
    // All should pass through unchanged
    try std.testing.expect(result[0].content_parts == null);
    try std.testing.expect(result[1].content_parts == null);
    try std.testing.expect(result[2].content_parts == null);
}

test "prepareMessagesForProvider with URL marker creates content_parts" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.user("Check this [IMAGE:https://example.com/cat.jpg] out"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs);
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expect(result[0].content_parts != null);
    const parts = result[0].content_parts.?;
    try std.testing.expectEqual(@as(usize, 2), parts.len);
    // First part: text
    try std.testing.expect(parts[0] == .text);
    try std.testing.expectEqualStrings("Check this  out", parts[0].text);
    // Second part: image_url
    try std.testing.expect(parts[1] == .image_url);
    try std.testing.expectEqualStrings("https://example.com/cat.jpg", parts[1].image_url.url);
}

test "prepareMessagesForProvider skips assistant messages" {
    const arena_impl = std.heap.ArenaAllocator.init(std.testing.allocator);
    var arena_mut = arena_impl;
    defer arena_mut.deinit();
    const arena = arena_mut.allocator();

    var msgs = [_]ChatMessage{
        ChatMessage.assistant("Here is [IMAGE:/tmp/a.png]"),
    };

    const result = try prepareMessagesForProvider(arena, &msgs);
    try std.testing.expect(result[0].content_parts == null);
}
