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

// http://man7.org/linux/man-pages/man2/socketpair.2.html

extern(C) ssize_t read(int fd, void *buf, size_t count);

void check(int code) {
    if(code < 0)
        abort();
}

// if this writes say 100 bytes total
void writer(int fd) {
    writefln("<started writer, fd = %d>", fd);
    auto s = "simple read write\n";
    char[] buf = s.dup;
    write(fd, s.ptr, s.length);
    writefln("<finished writer>");
}

// it must read the exact same amount (in total) that would be 100 bytes
void reader(int fd) {
    writefln("<started reader, fd = %d>", fd);
    char[100] buf;
    ssize_t total = 17;
    ssize_t bytes = 0;
    while(bytes < total) {
        ssize_t resp = read(fd, buf.ptr + bytes, total - bytes).checked;
        writefln("read resp = %s", resp);
        bytes += resp;
    }
    writefln("<finished reader>");
}

void main() {
   int[2] socks;
   check(socketpair(AF_UNIX, SOCK_STREAM, 0, socks));
   writeln(socks);
   fcntl(socks[1], F_SETFL, O_NONBLOCK);
   // spawn a thread to run I/O loop
   startloop();
   // spawn thread to write stuff
   auto wr = new Thread(() => writer(socks[0]));
   wr.start();

   // spawn fiber to read stuff
   spawn(() => reader(socks[1]));
   runUntilCompletion();
   //
   wr.join();
}
