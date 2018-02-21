import std.stdio;
import core.thread;

import dfio;

// run fibers until all of them terminate
// void runFibers();

void main()
{
    core.sys.posix.unistd.read(0,null,0uL); //test hook works

    auto t1 = new Thread(() {
       //...
       runFibers();
    });
    auto t2 = new Thread(() {
       //...
       runFibers();
    });
    t1.start(); t2.start();
    t1.join();
    t2.join();
}
