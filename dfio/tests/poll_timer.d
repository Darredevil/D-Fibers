module poll_test;
import std.stdio;
import core.sys.posix.sys.socket;
import core.sys.posix.unistd : write, _exit;
import core.sys.posix.sys.types;
import core.stdc.errno;
import core.sys.posix.sys.socket;
import core.thread;
import core.sys.posix.stdlib: abort;
import core.sys.posix.poll;
import std.socket;
import core.sys.posix.fcntl;
import dfio;

shared int idx = 0;

void check(int code) {
    if(code < 0)
        abort();
}

void writer(int fd) {
    logf("<started writer, fd = %d>", fd);
    auto s = "wait and write\n";
    for (int i = 0; i <  30; ++i) {
        logf("writer idx = %d", i);
        idx = i;
        ssize_t rc = write(fd, s.ptr, s.length);
        logf("write rc = %d", rc);
        Thread.sleep(1.seconds);
    }
    logf("<finished writer>");
}

void reader(int fd) {
    logf("<started reader, fd = %d>", fd);
    char[100] buf;
    ssize_t total = 15;
    int timeout = 2 * 1000; // 2 seconds
    bool finished = false;
    pollfd fds;
    fds.fd = fd;
    fds.events = POLLIN;
    fds.revents = 0;
    do {
        int rc = poll(&fds, 1, timeout).checked;
        logf("rc = %d", rc);
        if (idx == 29) finished = true;
        //logf("preparing to read");
        ssize_t resp = sys_read(fds.fd, buf.ptr, total).checked("read fail");
        logf("read resp = %s", resp);
    } while(!finished);
    logf(" <finished reader>");
}

void main(){
   int[2] socks;

   startloop();
   socketpair(AF_UNIX, SOCK_STREAM, 0, socks).checked;
   logf("socks = %s", socks);
   auto wr = new Thread(() => writer(socks[0]));
   wr.start();

   spawn(() => reader(socks[1]));
   runFibers();

   wr.join();
}
