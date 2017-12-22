import dfio;

// http://man7.org/linux/man-pages/man2/socketpair.2.html

void check(int code) {
    if(code < 0) abort();
}

// if this writes say 100 bytes total
void writer(int fd) {
    write(...);
    printf("...");
}

// it must read the exact same amount (in total) that would be 100 bytes
void reader(int fd) {
    read(...);
    printf("...");
}

void main() {
   int[2] socks;
   check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, socks.ptr));
   // spawn a thread to run I/O loop
   auto io = new Thread(&startloop);
   io.isDaemon = true;
   io.start();
   // spawn thread to write stuff
   auto wr = new Thread(() => writer(socks[0]));
   wr.start();

   // spawn fiber to read stuff
   spawn(() => reader(socks[1]);
   runFibers();
   //
   wr.join();
}
