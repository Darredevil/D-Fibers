#include <sys/types.h>
//import std.stdio;
//import std.string;
//import std.format;
//import std.exception;
//import std.conv;
//import std.array;
//import core.thread;

//import core.sys.posix.sys.types; // for ssize_t, uid_t, gid_t, off_t, pid_t, useconds_t
//import core.sys.posix.unistd;

//extern (C) ssize_t read(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count);

int main()
{
    char buf[20];
    size_t nbytes;
    ssize_t bytes_read;
    int fd;

    //writeln("D Fibers experiment 001");

    nbytes = 20;
    bytes_read = read(0/*fd*/, buf, nbytes);

    if (bytes_read == -1)
        //writef("Error while trying to read.\n");
        return -1;
    else
        //writef("Read: <%s>\n", buf);
        return 0;


}