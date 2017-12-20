import std.stdio;
import core.sys.posix.unistd : write, _exit;
import core.sys.posix.sys.types;
import core.memory;
import std.socket;
import core.stdc.errno;
import core.stdc.string;
import std.string;
import std.getopt;
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
void writerReader(int fd1, int fd2, string toSend, string toRecv) {
    logf("<started writerReader, fd1 = %d, fd2 = %d>", fd1, fd2);
    auto s = "simple read write\n";
    write(fd1, toSend.ptr, toSend.length).checked;

    logf("<midway writerReader, fd1 = %d, fd2 = %d>", fd1, fd2);

    char[100] buf2 = 0;
    ssize_t total = toRecv.length;
    ssize_t bytes = 0;
    while(bytes < total) {
        ssize_t resp = read(fd2, buf2.ptr + bytes, total - bytes).checked;
        logf("read1 resp = %s", resp);
        bytes += resp;
    }

    assert(cmp(fromStringz(buf2.ptr), toRecv) == 0);

    logf("<finished writerReader, fd1 = %d, fd2 = %d>", fd1, fd2);
}

// it must read the exact same amount (in total) that would be 100 bytes
void readerWriter(int fd1, int fd2, string toSend, string toRecv) {
    logf("Fiber = %s", cast(void*)currentFiber);
    logf("<started readerWriter, fd1 = %d, fd2 = %d>", fd1, fd2);
    char[100] buf = 0;
    ssize_t total = toRecv.length;
    ssize_t bytes = 0;
    while(bytes < total) {
        ssize_t resp = read(fd1, buf.ptr + bytes, total - bytes).checked;
        logf("read2 resp = %s", resp);
        bytes += resp;
    }

    assert(cmp(fromStringz(buf.ptr), toRecv) == 0);
    logf("<midway readerWriter, fd1 = %d, fd2 = %d>", fd1, fd2);

    auto s = "simple read write\n";
    char[] buf2 = s.dup;
    write(fd2, toSend.ptr, toSend.length).checked;
    logf("<finished readerWriter, fd1 = %d, fd2 = %d>", fd1, fd2);
}

void fiberPongPing(int fd1, int fd2, string toSend, string toRecv){
    spawn(() => readerWriter(fd1, fd2, toSend, toRecv));
}

void main(string[] args) {
    int NR;

    getopt(args,
        "count", &NR);
    NR *= 2;
    int[][] socks = new int[][](NR, 2);
    string s1 = "first read write\n";
    string s2 = "second read write\n";
    startloop();
    for(int i = 0; i < NR; i++) {
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, socks[i].ptr));
        //logf("socks[i] = %s", i, socks[i]);
    }

    logf("socks = %s", socks);


    // spawn a thread to run I/O loop
    // spawn thread to write stuff
    Thread[] wrs;
    for(int i = 0; i < NR; i += 2) {
        auto a1 = socks[i][0];
        auto a2 = socks[i+1][0];
        //auto wr = new Thread(() => writerReader(socks[i][0], socks[i+1][0], s2, s1));
        auto wr = new Thread({
            logf("In writer lambda %s, %s", a1, a2);
            writerReader(a1, a2, s2, s1);
        }); // BUG: must use temp vars a1,a2 else it crashes
        logf("wr = %s", cast(void*)wr);
        wr.start();
        wrs ~= wr;
    }

    // spawn fiber to read stuff
    for(int i = 0; i < NR; i += 2) {
        logf("socks[i][1] = %d, socks[i][1+1] = %d", socks[i][1], socks[i+1][1]);
        auto a1 = socks[i][1];
        auto a2 = socks[i+1][1];
        fiberPongPing(a1, a2, s1, s2);
        //BUG: cross-talk in lambdas in the same function
        /*spawn({ 
            logf("In reader lambda %s, %s", a1, a2);
            readerWriter( // BUG: must use temp vars a1,a2 else it crashes
            //socks[i][1],
            a1,
            //socks[qi+1][1],
            a2,
            s1, s2);
        });*/
    }
    runUntilCompletion();
    //
    foreach(w; wrs) {
        w.join();
    }
}
