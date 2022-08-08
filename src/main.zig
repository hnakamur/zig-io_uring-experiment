const std = @import("std");
const builtin = @import("builtin");
const IO_Uring = std.os.linux.IO_Uring;
const os = std.os;
const linux = os.linux;

const testing = std.testing;

fn testReadWithTimeoutRepro(read_fd: os.fd_t, read_err: os.E, timeout_err: os.E) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(4, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    var buffer = [_]u8{0} ** 20;
    var read_buffer = IO_Uring.ReadBuffer{ .buffer = buffer[0..] };
    const read_user_data = 8;

    // Enqueue a read request.
    var read_sqe = try ring.read(read_user_data, read_fd, read_buffer, 0);
    // var read_sqe = try ring.read(read_user_data, pipe_fds[0], read_buffer, 0);
    // Mark it as linked to the next request, which will be a timeout.
    read_sqe.flags |= linux.IOSQE_IO_LINK;

    const ts = os.linux.kernel_timespec{ .tv_sec = 1, .tv_nsec = 0 };
    const timeout_user_data = 9;
    // Enqueue a timeout request.
    _ = try ring.link_timeout(timeout_user_data, &ts, 0);

    // Submit both.
    const num_submitted = try ring.submit();
    try std.testing.expectEqual(num_submitted, 2);

    var cqes: [256]linux.io_uring_cqe = undefined;
    // Wait for both to return.
    const num_ready_cqes = try ring.copy_cqes(cqes[0..], num_submitted);

    try std.testing.expectEqual(num_ready_cqes, num_submitted);

    for (cqes[0..num_ready_cqes]) |cqe| {
        if (cqe.user_data == read_user_data) {
            try std.testing.expectEqual(@intCast(i32, @enumToInt(read_err)), -cqe.res);
        } else if (cqe.user_data == timeout_user_data) {
            try std.testing.expectEqual(@intCast(i32, @enumToInt(timeout_err)), -cqe.res);
        } else {
            unreachable;
        }
    }
}

test "read with timeout repro for stdin" {
    // testing.log_level = .debug;

    const ver = try LinuxKernelVersion.init();

    // TODO: Verify the version 5.15 is the correct turning point.
    const ver_gte_5_15 = ver.compare(.gte, .{ .major = 5, .patchlevel = 15 });
    std.log.debug("ver={}, ver_gte_5_15={}\n", .{ ver, ver_gte_5_15 });

    const read_err: os.E = .INVAL;
    const timeout_err: os.E = if (ver_gte_5_15) .CANCELED else .BADF;
    try testReadWithTimeoutRepro(std.io.getStdIn().handle, read_err, timeout_err);
}

test "read with timeout repro for pipe" {
    const ver = try LinuxKernelVersion.init();

    // TODO: Verify the version 5.15 is the correct turning point.
    const ver_gte_5_15 = ver.compare(.gte, .{ .major = 5, .patchlevel = 15 });
    std.log.debug("ver={}, ver_gte_5_15={}\n", .{ ver, ver_gte_5_15 });

    var pipe_fds = try os.pipe();
    defer os.close(pipe_fds[0]);
    defer os.close(pipe_fds[1]);

    const read_err: os.E = if (ver_gte_5_15) .INTR else .INVAL;
    const timeout_err: os.E = if (ver_gte_5_15) .ALREADY else .BADF;
    try testReadWithTimeoutRepro(pipe_fds[0], read_err, timeout_err);
}

pub const LinuxKernelVersion = struct {
    // https://github.com/torvalds/linux/blob/v5.19/Makefile#L1243-L1247
    //	echo '#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) +  \
    //	((c) > 255 ? 255 : (c)))';                                       \
    //	echo \#define LINUX_VERSION_MAJOR $(VERSION);                    \
    //	echo \#define LINUX_VERSION_PATCHLEVEL $(PATCHLEVEL);            \
    //	echo \#define LINUX_VERSION_SUBLEVEL $(SUBLEVEL)

    major: u8,
    patchlevel: u8,
    sublevel: u8 = 0,

    pub fn init() error{InvalidLinuxKernelVersion}!LinuxKernelVersion {
        const uts = std.os.uname();
        const end = std.mem.indexOfSentinel(u8, 0, uts.release[0..]);
        return try parse(uts.release[0..end]);
    }

    pub fn parse(release: []const u8) error{InvalidLinuxKernelVersion}!LinuxKernelVersion {
        // Expected format of release:
        // major.patchlevel or
        // major.patchlevel-extraversion or
        // major.patchlevel.sublevel or
        // major.patchlevel.sublevel-extraversion
        if (std.mem.indexOfScalar(u8, release, '.')) |major_end| {
            const patchlevel_end = if (std.mem.indexOfAnyPos(u8, release, major_end + 1, ".-")) |pos| pos else release.len;
            var ver = LinuxKernelVersion{
                .major = std.fmt.parseInt(u8, release[0..major_end], 10) catch return error.InvalidLinuxKernelVersion,
                .patchlevel = std.fmt.parseInt(u8, release[major_end + 1 .. patchlevel_end], 10) catch return error.InvalidLinuxKernelVersion,
            };
            if (patchlevel_end < release.len) {
                if (release[patchlevel_end] == '.') {
                    const sublevel_end = if (std.mem.indexOfScalarPos(u8, release, patchlevel_end + 1, '-')) |pos| pos else release.len;
                    ver.sublevel = std.fmt.parseInt(u8, release[patchlevel_end + 1 .. sublevel_end], 10) catch return error.InvalidLinuxKernelVersion;
                } else if (patchlevel_end + 1 == release.len) { // ends with '-'
                    return error.InvalidLinuxKernelVersion;
                }
            }
            return ver;
        }
        return error.InvalidLinuxKernelVersion;
    }

    pub fn order(self: LinuxKernelVersion, other: LinuxKernelVersion) std.math.Order {
        var o = std.math.order(self.major, other.major);
        if (o != .eq) {
            return o;
        }
        o = std.math.order(self.patchlevel, other.patchlevel);
        if (o != .eq) {
            return o;
        }
        return std.math.order(self.sublevel, other.sublevel);
    }

    pub fn compare(self: LinuxKernelVersion, op: std.math.CompareOperator, other: LinuxKernelVersion) bool {
        return self.order(other).compare(op);
    }
};

test "LinuxKernelVersion.parse" {
    try testing.expectEqual(std.math.Order.eq, (try LinuxKernelVersion.parse("5.19")).order(.{ .major = 5, .patchlevel = 19 }));
    try testing.expectEqual(std.math.Order.eq, (try LinuxKernelVersion.parse("5.19-rc0")).order(.{ .major = 5, .patchlevel = 19 }));
    try testing.expectEqual(std.math.Order.eq, (try LinuxKernelVersion.parse("5.15.1")).order(.{ .major = 5, .patchlevel = 15, .sublevel = 1 }));
    try testing.expectEqual(std.math.Order.eq, (try LinuxKernelVersion.parse("5.15.0-43-generic")).order(.{ .major = 5, .patchlevel = 15 }));

    try testing.expectError(error.InvalidLinuxKernelVersion, LinuxKernelVersion.parse("5"));
    try testing.expectError(error.InvalidLinuxKernelVersion, LinuxKernelVersion.parse("X"));
    try testing.expectError(error.InvalidLinuxKernelVersion, LinuxKernelVersion.parse("5-3"));
    try testing.expectError(error.InvalidLinuxKernelVersion, LinuxKernelVersion.parse("5.3-"));
    try testing.expectError(error.InvalidLinuxKernelVersion, LinuxKernelVersion.parse("5.3.-"));
}

test "LinuxKernelVersion.compare" {
    try testing.expect((LinuxKernelVersion{ .major = 5, .patchlevel = 15 }).compare(.gte, LinuxKernelVersion{ .major = 5, .patchlevel = 15 }));
    try testing.expect((LinuxKernelVersion{ .major = 5, .patchlevel = 15 }).compare(.gte, LinuxKernelVersion{ .major = 5, .patchlevel = 4 }));
    try testing.expect(!(LinuxKernelVersion{ .major = 5, .patchlevel = 15 }).compare(.gte, LinuxKernelVersion{ .major = 5, .patchlevel = 15, .sublevel = 1 }));
}
