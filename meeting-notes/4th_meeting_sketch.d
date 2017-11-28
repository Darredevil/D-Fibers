// Okay copy-paste our main ?

import std.stdio;
import core.thread;

import dfio;

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

// read-write-example
void main() {
   int[2] socks;
   check(socketpair(AF_UNIX, SOCK_STREAM, 0, socks));
   writeln(socks);
   fcntl(socks[1], F_SETFL, O_NONBLOCK);
   // spawn a thread to run I/O loop
   startloop(socks);
   // spawn thread to write stuff
   auto wr = new Thread(() => writer(socks[0]));
   wr.start();

   // spawn fiber to read stuff
   spawn(() => reader(socks[1]));
   runUntilCompletion();
   //
   wr.join();
}


//So ideally user code would be like
//
void main() {
   int[2] socks;
   check(socketpair(AF_UNIX, SOCK_STREAM, 0, socks));
   auto wr = new Thread(() => writer(socks[0]));
   wr.start();
   // spawn fiber to read stuff
   spawn(() => reader(socks[1]));
   runUntilCompletion(); // this we should get rid off eventually too
   //
   wr.join();
}

// Even better there shouldn't be incentive to spawn normal threads
// That's where we want to be roughly
void main() {
   int[2] socks;
   check(socketpair(AF_UNIX, SOCK_STREAM, 0, socks));
   spawn(() => writer(socks[0]));
   spawn(() => reader(socks[1]));
   runUntilCompletion(); // this we should get rid off eventually too
}

// The last problem is managing multiple threads with Fibers
// But we'll get to it
// Something like that at the moment
// we may wrap these patterns in something more nice

void server(){
    bind(...);
    listen(...);
    while(true) {
        int sock = accept(..., REUSE_PORT); // some such flag to shard the listen socket
        spawn(() => worker(sock));
    }
}

void main(){
    foreach(_; 0..8)
        new Thread(() => {
            spawn(server);
            runUntilCompletion();
        }).start();
}
