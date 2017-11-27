import std.stdio;
import core.sys.posix.unistd : write, _exit;
import core.sys.posix.sys.types;
import std.socket;
import core.stdc.errno;
import core.sys.posix.sys.socket;
import core.thread;
import dfio;

// http://man7.org/linux/man-pages/man2/socketpair.2.html

extern(C) ssize_t read(int fd, void *buf, size_t count);

void check(int code) {
    if(code < 0)
        //abort();
        _exit(-1337);
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
    read(fd, buf.ptr, 17);
    writefln("read buf = <%s>", buf);
    writefln("<finished reader>");
}

void main() {
   int[2] socks;
   check(socketpair(AF_UNIX, SOCK_STREAM /*| SOCK_NONBLOCK*/, 0, socks));
   writeln(socks);
   // spawn a thread to run I/O loop
   auto io = new Thread(&startloop);
   io.isDaemon = true;
   io.start();
   // spawn thread to write stuff
   auto wr = new Thread(() => writer(socks[0]));
   wr.start();

   // spawn fiber to read stuff
   spawn(() => reader(socks[1]));
   runUntilCompletion();
   //
   wr.join();
}
