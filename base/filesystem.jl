# This file is a part of Julia. License is MIT: https://julialang.org/license

## File Operations (Libuv-based) ##

module Filesystem

const S_IFDIR  = 0o040000  # directory
const S_IFCHR  = 0o020000  # character device
const S_IFBLK  = 0o060000  # block device
const S_IFREG  = 0o100000  # regular file
const S_IFIFO  = 0o010000  # fifo (named pipe)
const S_IFLNK  = 0o120000  # symbolic link
const S_IFSOCK = 0o140000  # socket file
const S_IFMT   = 0o170000

const S_ISUID = 0o4000  # set UID bit
const S_ISGID = 0o2000  # set GID bit
const S_ENFMT = S_ISGID # file locking enforcement
const S_ISVTX = 0o1000  # sticky bit

const S_IRUSR = 0o0400  # read by owner
const S_IWUSR = 0o0200  # write by owner
const S_IXUSR = 0o0100  # execute by owner
const S_IRWXU = 0o0700  # mask for owner permissions
const S_IRGRP = 0o0040  # read by group
const S_IWGRP = 0o0020  # write by group
const S_IXGRP = 0o0010  # execute by group
const S_IRWXG = 0o0070  # mask for group permissions
const S_IROTH = 0o0004  # read by other
const S_IWOTH = 0o0002  # write by other
const S_IXOTH = 0o0001  # execute by other
const S_IRWXO = 0o0007  # mask for other permissions

export File,
       StatStruct,
       # open,
       futime,
       write,
       JL_O_WRONLY,
       JL_O_RDONLY,
       JL_O_RDWR,
       JL_O_APPEND,
       JL_O_CREAT,
       JL_O_EXCL,
       JL_O_TRUNC,
       JL_O_TEMPORARY,
       JL_O_SHORT_LIVED,
       JL_O_SEQUENTIAL,
       JL_O_RANDOM,
       JL_O_NOCTTY,
       JL_O_NOCTTY,
       JL_O_NONBLOCK,
       JL_O_NDELAY,
       JL_O_SYNC,
       JL_O_FSYNC,
       JL_O_ASYNC,
       JL_O_LARGEFILE,
       JL_O_DIRECTORY,
       JL_O_NOFOLLOW,
       JL_O_CLOEXEC,
       JL_O_DIRECT,
       JL_O_NOATIME,
       JL_O_PATH,
       JL_O_TMPFILE,
       JL_O_DSYNC,
       JL_O_RSYNC,
       S_IRUSR, S_IWUSR, S_IXUSR, S_IRWXU,
       S_IRGRP, S_IWGRP, S_IXGRP, S_IRWXG,
       S_IROTH, S_IWOTH, S_IXOTH, S_IRWXO

import .Base:
    IOError, _UVError, _sizeof_uv_fs, check_open, close, eof, eventloop, fd, isopen,
    bytesavailable, position, read, read!, readavailable, seek, seekend, show,
    skip, stat, unsafe_read, unsafe_write, write, transcode, uv_error,
    setup_stdio, rawhandle, OS_HANDLE, INVALID_OS_HANDLE, windowserror, filesize

import .Base.RefValue

if Sys.iswindows()
    import .Base: cwstring
end

# Average buffer size including null terminator for several filesystem operations.
# On Windows we use the MAX_PATH = 260 value on Win32.
const AVG_PATH = Sys.iswindows() ? 260 : 512

# helper function to clean up libuv request
uv_fs_req_cleanup(req) = ccall(:uv_fs_req_cleanup, Cvoid, (Ptr{Cvoid},), req)

include("path.jl")
include("stat.jl")
include("file.jl")
include(string(length(Core.ARGS) >= 2 ? Core.ARGS[2] : "", "file_constants.jl"))  # include($BUILDROOT/base/file_constants.jl)

## Operations with File (fd) objects ##

abstract type AbstractFile <: IO end

mutable struct File <: AbstractFile
    open::Bool
    handle::OS_HANDLE
    File(fd::OS_HANDLE) = new(true, fd)
end
if OS_HANDLE !== RawFD
    File(fd::RawFD) = File(Libc._get_osfhandle(fd)) # TODO: calling close would now destroy the wrong handle
end

rawhandle(file::File) = file.handle
setup_stdio(file::File, ::Bool) = (file, false)

# Filesystem.open, not Base.open
function open(path::AbstractString, flags::Integer, mode::Integer=0)
    req = Libc.malloc(_sizeof_uv_fs)
    local handle
    try
        ret = ccall(:uv_fs_open, Int32,
                    (Ptr{Cvoid}, Ptr{Cvoid}, Cstring, Int32, Int32, Ptr{Cvoid}),
                    C_NULL, req, path, flags, mode, C_NULL)
        handle = ccall(:uv_fs_get_result, Cssize_t, (Ptr{Cvoid},), req)
        uv_fs_req_cleanup(req)
        ret < 0 && uv_error("open($(repr(path)), $flags, $mode)", ret)
    finally # conversion to Cstring could cause an exception
        Libc.free(req)
    end
    return File(OS_HANDLE(@static Sys.iswindows() ? Ptr{Cvoid}(handle) : Cint(handle)))
end

isopen(f::File) = f.open

function check_open(f::File)
    if !isopen(f)
        throw(ArgumentError("file is closed"))
    end
end

function close(f::File)
    if isopen(f)
        f.open = false
        err = ccall(:jl_fs_close, Int32, (OS_HANDLE,), f.handle)
        f.handle = INVALID_OS_HANDLE
        uv_error("close", err)
    end
    nothing
end

@static if Sys.iswindows()
    struct Overlapped
        internal::UInt
        internal_high::UInt
        offset::UInt32
        offset_high::UInt32
        event::Ptr{Cvoid}
    end
    # Windows locks are mandatory, so a lock on the file's data would make reads by other
    # processes fail. Locking one byte far beyond the end keeps it advisory, as on Unix.
    const LOCKFILE_OVERLAPPED = Overlapped(0, 0, 0xfffffffe, 0x7fffffff, C_NULL)
    const LOCKFILE_FAIL_IMMEDIATELY = 0x1
    const LOCKFILE_EXCLUSIVE_LOCK = 0x2
    const ERROR_LOCK_VIOLATION = 0x21
    const ERROR_NOT_LOCKED = 0x9e
else
    const LOCK_SH = Cint(1)
    const LOCK_EX = Cint(2)
    const LOCK_NB = Cint(4)
    const LOCK_UN = Cint(8)
end

"""
    trylockfile(f::File; shared::Bool=false)::Bool

Try to take a lock on the file `f`, opened with `Base.Filesystem.open(path, flags)`, without
waiting, and return whether it was taken.

The lock is advisory: it only decides whether other attempts to lock the same file succeed. On
local file systems it does not stop any process from opening, reading, writing, renaming or
deleting the file, so it only coordinates processes that all take it. Network file systems may
behave differently.

Any number of shared locks can be held at once, while an exclusive lock (`shared=false`)
excludes every other lock. Each `File` holds its own lock, so two `File`s opened on the same path
conflict even within one process. A `File` should hold at most one lock at a time: taking a
second lock on the same `File`, including to change a shared lock to an exclusive one, behaves
differently across platforms. Call [`unlockfile`](@ref) first.

The lock is released by `unlockfile`, or when `f` is closed or the process exits. On Windows the
release on close or exit can be delayed, so call `unlockfile` first when another process may be
waiting for the lock. Processes started with `run` do not inherit the lock.

Throws a `SystemError` if the file cannot be locked, for example because the file system does not
support locks. On some network file systems a lock is only seen by processes on the same machine,
and on Linux NFS an exclusive lock needs `f` to be open for writing.

Fleet backport of JuliaLang/julia#63613; internal on Julia 1.10.
"""
function trylockfile(f::File; shared::Bool=false)
    check_open(f)
    @static if Sys.iswindows()
        flags = shared ? LOCKFILE_FAIL_IMMEDIATELY : LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK
        ok = ccall(:LockFileEx, stdcall, Cint, (OS_HANDLE, UInt32, UInt32, UInt32, UInt32, Ref{Overlapped}),
                   f.handle, flags, 0, 1, 0, LOCKFILE_OVERLAPPED) != 0
        ok && return true
        code = Libc.GetLastError()
        code == ERROR_LOCK_VIOLATION && return false
        windowserror("trylockfile", code)
    else
        ccall(:flock, Cint, (OS_HANDLE, Cint), f.handle, (shared ? LOCK_SH : LOCK_EX) | LOCK_NB) == 0 && return true
        # a lock held elsewhere is reported as EWOULDBLOCK, the same value as EAGAIN
        Libc.errno() == Libc.EAGAIN && return false
        systemerror("trylockfile")
    end
end

"""
    unlockfile(f::File)

Release the lock that `f` holds through [`trylockfile`](@ref). Does nothing if `f` holds no lock.

Fleet backport of JuliaLang/julia#63613; internal on Julia 1.10.
"""
function unlockfile(f::File)
    check_open(f)
    @static if Sys.iswindows()
        ok = ccall(:UnlockFileEx, stdcall, Cint, (OS_HANDLE, UInt32, UInt32, UInt32, Ref{Overlapped}),
                   f.handle, 0, 1, 0, LOCKFILE_OVERLAPPED) != 0
        ok || (code = Libc.GetLastError()) == ERROR_NOT_LOCKED || windowserror("unlockfile", code)
    else
        systemerror("unlockfile", ccall(:flock, Cint, (OS_HANDLE, Cint), f.handle, LOCK_UN) != 0)
    end
    return nothing
end


# sendfile is the most efficient way to copy from a file descriptor
function sendfile(dst::File, src::File, src_offset::Int64, bytes::Int)
    check_open(dst)
    check_open(src)
    while true
        result = ccall(:jl_fs_sendfile, Int32, (OS_HANDLE, OS_HANDLE, Int64, Csize_t),
                       src.handle, dst.handle, src_offset, bytes)
        uv_error("sendfile", result)
        nsent = result
        bytes -= nsent
        src_offset += nsent
        bytes <= 0 && break
    end
    nothing
end

function unsafe_write(f::File, buf::Ptr{UInt8}, len::UInt, offset::Int64=Int64(-1))
    check_open(f)
    err = ccall(:jl_fs_write, Int32, (OS_HANDLE, Ptr{UInt8}, Csize_t, Int64),
                f.handle, buf, len, offset)
    uv_error("write", err)
    return len
end

write(f::File, c::UInt8) = write(f, Ref{UInt8}(c))

function truncate(f::File, n::Integer)
    check_open(f)
    req = Libc.malloc(_sizeof_uv_fs)
    err = ccall(:uv_fs_ftruncate, Int32,
                (Ptr{Cvoid}, Ptr{Cvoid}, OS_HANDLE, Int64, Ptr{Cvoid}),
                C_NULL, req, f.handle, n, C_NULL)
    Libc.free(req)
    uv_error("ftruncate", err)
    return f
end

function futime(f::File, atime::Float64, mtime::Float64)
    check_open(f)
    req = Libc.malloc(_sizeof_uv_fs)
    err = ccall(:uv_fs_futime, Int32,
                (Ptr{Cvoid}, Ptr{Cvoid}, OS_HANDLE, Float64, Float64, Ptr{Cvoid}),
                C_NULL, req, f.handle, atime, mtime, C_NULL)
    Libc.free(req)
    uv_error("futime", err)
    return f
end

function read(f::File, ::Type{UInt8})
    check_open(f)
    ret = ccall(:jl_fs_read_byte, Int32, (OS_HANDLE,), f.handle)
    uv_error("read", ret)
    return ret % UInt8
end

function read(f::File, ::Type{Char})
    b0 = read(f, UInt8)
    l = 0x08 * (0x04 - UInt8(leading_ones(b0)))
    c = UInt32(b0) << 24
    if l ≤ 0x10
        s = 16
        while s ≥ l && !eof(f)
            # this works around lack of peek(::File)
            p = position(f)
            b = read(f, UInt8)
            if b & 0xc0 != 0x80
                seek(f, p)
                break
            end
            c |= UInt32(b) << s
            s -= 8
        end
    end
    return reinterpret(Char, c)
end

read(f::File, ::Type{T}) where {T<:AbstractChar} = T(read(f, Char)) # fallback

function unsafe_read(f::File, p::Ptr{UInt8}, nel::UInt)
    check_open(f)
    ret = ccall(:jl_fs_read, Int32, (OS_HANDLE, Ptr{Cvoid}, Csize_t),
                f.handle, p, nel)
    uv_error("read", ret)
    ret == nel || throw(EOFError())
    nothing
end

bytesavailable(f::File) = max(0, filesize(f) - position(f)) # position can be > filesize

eof(f::File) = bytesavailable(f) == 0

function readbytes!(f::File, b::Array{UInt8}, nb=length(b))
    nr = min(nb, bytesavailable(f))
    if length(b) < nr
        resize!(b, nr)
    end
    ret = ccall(:jl_fs_read, Int32, (OS_HANDLE, Ptr{Cvoid}, Csize_t),
                f.handle, b, nr)
    uv_error("read", ret)
    return ret
end
read(io::File) = read!(io, Base.StringVector(bytesavailable(io)))
readavailable(io::File) = read(io)
read(io::File, nb::Integer) = read!(io, Base.StringVector(min(nb, bytesavailable(io))))

const SEEK_SET = Int32(0)
const SEEK_CUR = Int32(1)
const SEEK_END = Int32(2)

function seek(f::File, n::Integer)
    ret = ccall(:jl_lseek, Int64, (OS_HANDLE, Int64, Int32), f.handle, n, SEEK_SET)
    ret == -1 && (@static Sys.iswindows() ? windowserror : systemerror)("seek")
    return f
end

function seekend(f::File)
    ret = ccall(:jl_lseek, Int64, (OS_HANDLE, Int64, Int32), f.handle, 0, SEEK_END)
    ret == -1 && (@static Sys.iswindows() ? windowserror : systemerror)("seekend")
    return f
end

function skip(f::File, n::Integer)
    ret = ccall(:jl_lseek, Int64, (OS_HANDLE, Int64, Int32), f.handle, n, SEEK_CUR)
    ret == -1 && (@static Sys.iswindows() ? windowserror : systemerror)("skip")
    return f
end

function position(f::File)
    check_open(f)
    ret = ccall(:jl_lseek, Int64, (OS_HANDLE, Int64, Int32), f.handle, 0, SEEK_CUR)
    ret == -1 && (@static Sys.iswindows() ? windowserror : systemerror)("lseek")
    return ret
end

fd(f::File) = f.handle
stat(f::File) = stat(f.handle)

function touch(f::File)
    @static if Sys.isunix()
        ret = ccall(:futimes, Cint, (Cint, Ptr{Cvoid}), fd(f), C_NULL)
        systemerror(:futimes, ret != 0)
    else
        t = time()
        futime(f, t, t)
    end
    f
end


end
