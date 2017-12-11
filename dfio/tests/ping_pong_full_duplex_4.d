import std.stdio;
import core.sys.posix.unistd : write, _exit;
import core.sys.posix.sys.types;
import std.socket;
import core.stdc.errno;
import core.stdc.string;
import std.string;
import core.sys.posix.sys.socket;
import core.sys.posix.fcntl;
import core.thread;
import core.sys.posix.stdlib: abort;
import std.conv : to;
import dfio;

void check(int code) {
    if(code < 0)
        abort();
}

// if this writes say 100 bytes total
//void writerReader(int fd1, int fd2) {
void writerReader(int fd1, int fd2, string toSend, string toRecv) {
    logf("<started writerReader, fd1 = %d, fd2 = %d>", fd1, fd2);
    auto s = "simple read write\n";
    //write(fd1, s.ptr, s.length).checked;
    write(fd1, toSend.ptr, toSend.length).checked;

    logf("<midway writerReader, fd1 = %d, fd2 = %d>", fd1, fd2);

    char[100] buf2 = 0;
    //ssize_t total = 17;
    ssize_t total = toRecv.length;
    ssize_t bytes = 0;
    while(bytes < total) {
        ssize_t resp = read(fd2, buf2.ptr + bytes, total - bytes).checked;
        logf("read1 resp = %s", resp);
        bytes += resp;
    }

    writefln("<<<<<<<<<<<<<<writerReader buff = <%s>, toRecv = <%s>", buf2, toRecv);
    assert(cmp(fromStringz(buf2.ptr), toRecv) == 0);

    logf("<finished writerReader, fd1 = %d, fd2 = %d>", fd1, fd2);
}

// it must read the exact same amount (in total) that would be 100 bytes
void readerWriter(int fd1, int fd2, string toSend, string toRecv) {
//void readerWriter(int fd1, int fd2) {
    logf("<started readerWriter, fd1 = %d, fd2 = %d>", fd1, fd2);
    char[100] buf = 0;
    ssize_t total = toRecv.length; //17;
    ssize_t bytes = 0;
    while(bytes < total) {
        ssize_t resp = read(fd1, buf.ptr + bytes, total - bytes).checked;
        logf("read2 resp = %s", resp);
        bytes += resp;
    }

    writefln("buff = <%s>, toRecv = <%s>", buf, toRecv);
    assert(cmp(fromStringz(buf.ptr), toRecv) == 0);

    logf("<midway readerWriter, fd1 = %d, fd2 = %d>", fd1, fd2);

    auto s = "simple read write\n";
    char[] buf2 = s.dup;
    write(fd2, toSend.ptr, toSend.length).checked;
    logf("<finished readerWriter, fd1 = %d, fd2 = %d>", fd1, fd2);
}

void main() {
    int[2] socks1, socks2, socks3, socks4;
    string s1 = "first read write\n";
    string s2 = "second read write\n";
    string toRecv = "simple read write\n";
    startloop();
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, socks1));
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, socks2));
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, socks3));
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, socks4));
    logf("socks1 = %s", socks1);
    logf("socks2 = %s", socks2);
    logf("socks3 = %s", socks3);
    logf("socks4 = %s", socks4);
    // spawn a thread to run I/O loop
    // spawn thread to write stuff
    //auto wr1 = new Thread(() => writerReader(socks1[0], socks2[0]));
    auto wr1 = new Thread(() => writerReader(socks1[0], socks2[0], s2, s1));
    //auto wr2 = new Thread(() => writerReader(socks3[0], socks4[0]));
    auto wr2 = new Thread(() => writerReader(socks3[0], socks4[0], s1, s2));
    wr1.start();
    wr2.start();

    // spawn fiber to read stuff
    //spawn(() => readerWriter(socks1[1], socks2[1]));
    //spawn(() => readerWriter(socks3[1], socks4[1]));
    spawn(() => readerWriter(socks1[1], socks2[1], s1, s2));
    spawn(() => readerWriter(socks3[1], socks4[1], s2, s1));
    runUntilCompletion();
    //
    wr1.join();
    wr2.join();
}
