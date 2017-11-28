module dfio;

import std.stdio;
import std.string;
import std.format;
import std.exception;
import std.conv;
import std.array;
import core.thread;
import std.container.dlist;
import core.sys.posix.sys.types;
import core.sys.posix.unistd;
import core.sys.linux.epoll;
import core.sync.mutex;
import core.stdc.errno;
import core.atomic;
import BlockingQueue : BlockingQueue, unshared;
import core.sys.posix.stdlib: abort;
import core.sys.posix.fcntl;

Fiber currentFiber; // this is TLS per user thread

shared int alive; // count of non-terminated Fibers
shared BlockingQueue!Fiber queue;

shared Mutex mtx;

// https://syscalls.kernelgrok.com/ --------------------------------------------> x86 syscall table
// http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/ ----------> x64 syscall table
// https://github.com/kubo39/syscall-d/blob/master/source/syscalld/arch/syscall_x86.d

enum int TIMEOUT = 100, MAX_EVENTS = 100;

int checked(int value, const char* msg="unknown place") {
    if (value < 0) {
        perror(msg);
        _exit(value);
    }
    return value;
}

ssize_t checked(ssize_t value, const char* msg="unknown place") {
    if (value < 0) {
        perror(msg);
        abort();
    }
    return value;
}

version (X86) {
    int syscall(int ident, int n, int arg1, int arg2)
    {
        int ret;

        synchronized asm
        {
            mov EAX, ident;
            mov EBX, n[EBP];
            mov ECX, arg1[EBP];
            mov EDX, arg2[EBP];
            int 0x80;
            mov ret, EAX;
        }
        return ret;
    }
} else version (X86_64) {
    size_t syscall(size_t ident, size_t n, size_t arg1, size_t arg2)
    {
        size_t ret;

        synchronized asm
        {
            mov RAX, ident;
            mov RDI, n[RBP];
            mov RSI, arg1[RBP];
            mov RDX, arg2[RBP];
            syscall;
            mov ret, RAX;
        }
        return ret;
    }
}

extern(C) ssize_t read(int fd, void *buf, size_t count)
{
    writeln("HOOKED WITH MY LIB!"); // TODO: temporary for easy check, remove later

    int flags = fcntl(fd, F_GETFL, 0);
    if (!(flags & O_NONBLOCK)) {
        perror("WARNING: Socket not set in O_NONBLOCK mode!");
        //abort(); //TODO: enforce abort?
    }
    for(;;) {
        version (X86) {
            ssize_t resp = syscall(0x3, fd, cast(ssize_t) buf, cast(ssize_t) count);
        } else version (X86_64) {
            ssize_t resp = syscall(0x0, fd, cast(ssize_t) buf, cast(ssize_t) count);
        }
        if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
            add_await(fd, currentFiber, EPOLLIN);
            currentFiber = queue.pop();
            Fiber.yield();
            continue;
        } else return resp;
    }
    // This should never be reached
    return -1337;
}

void runUntilCompletion()
{
    while (alive > 0) {
        //currentFiber = take(queue); // TODO implement take

        currentFiber = queue.pop();
        writefln("Fiber %x started", cast(void*)currentFiber);
        currentFiber.call();
        if (currentFiber.state == Fiber.State.TERM) {
            writefln("Fiber %s terminated", cast(void*)currentFiber);
            core.atomic.atomicOp!"-="(alive, 1);
        }
    }
}

void spawn(void delegate() func) {
    auto f = new Fiber(func);
    queue = new shared BlockingQueue!Fiber;
    queue.push(f);
    core.atomic.atomicOp!"+="(alive, 1);
}

shared DescriptorState[] descriptors;
shared int event_loop_fd;

struct AwaitingFiber {
    Fiber fiber;
    int op; // EPOLLIN if reading or EPOLLOUT if writing
}

// list of awaiting fibers
struct DescriptorState {
    AwaitingFiber[] waiters;  // can optimize for 1-element case, more on that later
}

void add_await(int fd, Fiber fiber, int op) {
    mtx.lock();
    (cast(DescriptorState[])descriptors)[fd].waiters ~= AwaitingFiber(currentFiber, EPOLLIN);
    mtx.unlock();
}

/*
   typedef union epoll_data {
       void        *ptr;
       int          fd;
       uint32_t     u32;
       uint64_t     u64;
   } epoll_data_t;

   struct epoll_event {
       uint32_t     events;
       epoll_data_t data;
   };

*/
void event_add_fd(int fd) { // register new FD
    epoll_event event;
    event.events = EPOLLIN | EPOLLOUT; // TODO: most events that make sense to watch for
    event.data.fd = fd;
    epoll_ctl(event_loop_fd, EPOLL_CTL_ADD, fd, &event).checked("ERROR: failed epoll_ctl add!");
}

void event_remove_fd(int fd) { // on LibC's close
    epoll_ctl(event_loop_fd, EPOLL_CTL_DEL, fd, null).checked("ERROR: failed epoll_ctl delete!");
}

void startloop()
{
    mtx = cast(shared)new Mutex();
    event_loop_fd = cast(int)epoll_create1(0).checked("ERROR: Failed to create event-loop!");
    ssize_t fds = sysconf(_SC_OPEN_MAX).checked;
    descriptors = cast(shared)new DescriptorState[fds];
    auto io = new Thread(&eventloop);
    io.isDaemon = true;
    io.start();
}

/*
       EPOLLIN
              The associated file is available for read(2) operations.

       EPOLLOUT
              The associated file is available for write(2) operations.

       EPOLLRDHUP
              Stream socket peer closed connection, or shut down writing
              half of connection.

       EPOLLPRI
              There is an exceptional condition on the file descriptor.

       EPOLLERR
              Error condition happened on the associated file descriptor.
       EPOLLHUP
              Hang up happened on the associated file descriptor.
              epoll_wait(2) will always wait for this event; it is not nec‐
              essary to set it in events.
*/

void eventloop()
{
    epoll_event[MAX_EVENTS] events;
    while(1) { // TODO: infinite loop for now, revisit later
        // 1. call epoll
        int r = epoll_wait(event_loop_fd, events.ptr, MAX_EVENTS, TIMEOUT)
            .checked("ERROR: failed epoll_wait");
        // 2. move waiters ---> queue
        for (int n = 0; n < r; n++) {
            writefln("Event %s on fd=%s", events[n].events, events[n].data);
            int fd = events[n].data.fd;
            auto w = descriptors[fd].waiters;   // <-- TODO: locking
            //TODO: remove the ones from the waiting list
            foreach(a; w) {
                // 3. the tick is read and write are separate, and then there are TODO: exceptions (errors)
                if ((a.op & events[fd].events) != 0) {
                    queue.push(cast(Fiber)(a.fiber));
                }
            }
        }
    }
}
