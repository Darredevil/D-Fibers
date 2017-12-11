import std.stdio;
import core.sys.posix.unistd : write, _exit;
import core.sys.posix.sys.types;
import std.socket;
import core.stdc.errno;
import core.sys.posix.sys.socket;
import core.sys.posix.fcntl;
import core.thread;
import core.sys.posix.stdlib: abort;
import dfio;

void check(int code) {
    if(code < 0)
        abort();
}

// if this writes say 100 bytes total
void writerReader(int fd1, int fd2) {
    logf("<started writerReader, fd1 = %d, fd2 = %d>", fd1, fd2);
    auto s = "simple read write\n";
    write(fd1, s.ptr, s.length).checked;

    logf("<midway writerReader, fd1 = %d, fd2 = %d>", fd1, fd2);

    char[100] buf2;
    ssize_t total = 17;
    ssize_t bytes = 0;
    while(bytes < total) {
        ssize_t resp = read(fd2, buf2.ptr + bytes, total - bytes).checked;
        logf("read1 resp = %s", resp);
        bytes += resp;
    }

    logf("<finished writerReader>");
}

// it must read the exact same amount (in total) that would be 100 bytes
void readerWriter(int fd1, int fd2) {
    logf("<started readerWriter, fd1 = %d, fd2 = %d>", fd1, fd2);
    char[100] buf;
    ssize_t total = 17;
    ssize_t bytes = 0;
    while(bytes < total) {
        ssize_t resp = read(fd1, buf.ptr + bytes, total - bytes).checked;
        logf("read2 resp = %s", resp);
        bytes += resp;
    }

    logf("<midway readerWriter, fd1 = %d, fd2 = %d>", fd1, fd2);

    auto s = "simple read write\n";
    char[] buf2 = s.dup;
    write(fd2, s.ptr, s.length).checked;
    logf("<finished readerWriter>");
}

void main() {
    // C: int[20][4] x;......  x[19][3]... x[3][19]
    int[2][20] socks;
    startloop();
    for(int i = 0; i < 2; i++) {
        //pragma(msg, typeof(socks[i]));
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, socks[i]));
        logf("socks[%d] = %s, length = %d", i, socks[i], socks[i].length);

    }
    writefln("socks = %s", socks);
    // spawn a thread to run I/O loop
    // spawn thread to write stuff
    Thread[] wrs;
    for(int i = 0; i < 2; i+=2) {
        //writefln("i = %d, i+1 = %d", i, i+1);
        //writefln("socks[i] = %s, socks[%d][1] = %d", socks[i], i, socks[i][1]);
        auto wr = new Thread(() => writerReader(socks[i][0], socks[i+1][0]));
        wr.start();
        wrs ~= wr;
    }

    // spawn fiber to read stuff
    for(int i = 0; i < 2; i+=2) {
        pragma(msg, typeof(socks));
        pragma(msg, typeof(socks[i]));
        pragma(msg, typeof(socks[0][i]));
        writefln("i = %d, i+1 = %d", i, i+1);
        writefln("socks[i] = %s, socks[%d][1] = %d", socks[i], i, socks[i][1]);
        spawn(() => readerWriter(
            socks[i][1],
            socks[i+1][1]));
    }
    runUntilCompletion();
    //
    for(int i = 0; i < 10; i++) {
        wrs[i].join();
    }
}
