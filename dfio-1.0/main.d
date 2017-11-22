import std.stdio;
import std.string;
import std.format;
import std.exception;
import std.conv;
import std.array;
import core.thread;
import std.container.dlist;
import core.sys.posix.sys.types; // for ssize_t, uid_t, gid_t, off_t, pid_t, useconds_t
import core.sys.posix.unistd;
import core.sys.linux.epoll;
import core.sync.mutex;
import core.stdc.errno;
import core.atomic;
import dfio : runUntilCompletion;

// This would start User's task on I/O scheduler
//void spawn(void function() func);

// run fibers until all of them terminate
//void runUntilCompletion();

void main()
{
    auto t1 = new Thread(() {
       //...
       runUntilCompletion();
    });
    auto t2 = new Thread(() {
       //...
       runUntilCompletion();
    });
    t1.start(); t2.start();
    t1.join();
    t2.join();
}
