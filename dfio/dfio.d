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

shared int managedThreads = 0;
shared int alive; // count of non-terminated Fibers
shared bool completed = false;
shared BlockingQueue!Fiber queue;
shared Mutex mtx;

enum int TIMEOUT = 1, MAX_EVENTS = 100;

void logf(string file = __FILE__, int line = __LINE__, T...)(string msg, T args)
{
    stderr.writefln("%s:%s:\t%s", file, line, format(msg, args));
}

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
    enum int SYS_READ = 0x3, SYS_SOCKETPAIR = 0x168; //TODO test on x86
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

    int syscall(int ident, int n, int arg1, int arg2, int arg3)
    {
        int ret;

        asm
        {
            mov EAX, ident;
            mov EBX, n[EBP];
            mov ECX, arg1[EBP];
            mov EDX, arg2[EBP];
            mov ESI, arg3[EBP];
            int 0x80;
            mov ret, EAX;
        }
        return ret;
    }

    int syscall(int ident, int n, int arg1, int arg2, int arg3, int arg4)
    {
        int ret;

        asm
        {
            mov EAX, ident;
            mov EBX, n[EBP];
            mov ECX, arg1[EBP];
            mov EDX, arg2[EBP];
            mov ESI, arg3[EBP];
            mov EDI, arg4[EBP];
            int 0x80;
            mov ret, EAX;
        }
        return ret;
    }
} else version (X86_64) {
    enum int SYS_READ = 0x0, SYS_SOCKETPAIR = 0x35;
    size_t syscall(size_t ident, size_t n, size_t arg1, size_t arg2)
    {
        size_t ret;

        asm
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

    size_t syscall(size_t ident, size_t n, size_t arg1, size_t arg2, size_t arg3)
    {
        size_t ret;

        asm
        {
            mov RAX, ident;
            mov RDI, n[RBP];
            mov RSI, arg1[RBP];
            mov RDX, arg2[RBP];
            mov R10, arg3[RBP];
            syscall;
            mov ret, RAX;
        }
        return ret;
    }

    size_t syscall(size_t ident, size_t n, size_t arg1, size_t arg2, size_t arg3, size_t arg4)
    {
        size_t ret;

        asm
        {
            mov RAX, ident;
            mov RDI, n[RBP];
            mov RSI, arg1[RBP];
            mov RDX, arg2[RBP];
            mov R10, arg3[RBP];
            mov R8, arg4[RBP];
            syscall;
            mov ret, RAX;
        }
        return ret;
    }
}

extern(C) ssize_t read(int fd, void *buf, size_t count)
{
    if (currentFiber is null) {
        logf("READ PASSTHROUGH!");
        return syscall(SYS_READ, fd, cast(ssize_t) buf, cast(ssize_t) count);
    }
    else {
        logf("HOOKED READ WITH MY LIB!"); // TODO: temporary for easy check, remove later
        if (descriptors[fd].firstUse) {
            fcntl(fd, F_SETFL, O_NONBLOCK).checked;
            event_add_fd(fd);
            descriptors[fd].firstUse = false;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (!(flags & O_NONBLOCK)) {
            logf("WARNING: Socket (%d) not set in O_NONBLOCK mode!", fd);
            //abort(); //TODO: enforce abort?
        }
        for(;;) {
            ssize_t resp = syscall(SYS_READ, fd, cast(ssize_t) buf, cast(ssize_t) count);
            if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                logf("READ GOT DELAYED - FD %d, resp = %d", fd, resp);
                add_await(fd, currentFiber, EPOLLIN);
                Fiber.yield();
                continue;
            } else return resp;
        }
        assert(0);
    }
}

extern(C) int socketpair(int domain, int type, int protocol, int* sv)
{
    logf("HOOKED SOCKETPAIR WITH MY LIB!"); // TODO: temporary for easy check, remove later

    ssize_t ret = syscall(SYS_SOCKETPAIR, domain, type, protocol, cast(size_t) sv);
    if (ret < 0)
        abort();
    return cast(int) ret;
}

void runUntilCompletion()
{
    atomicOp!"+="(managedThreads, 1);
    while (alive > 0) {
        //currentFiber = take(queue); // TODO implement take

        currentFiber = queue.pop();
        logf("Fiber %x started", cast(void*)currentFiber);
        currentFiber.call();
        if (currentFiber.state == Fiber.State.TERM) {
            logf("Fiber %s terminated", cast(void*)currentFiber);
            atomicOp!"-="(alive, 1);
        }
    }
    atomicOp!"-="(managedThreads, 1);
    completed = true;
}

void spawn(void delegate() func) {
    auto f = new Fiber(func);
    queue = new shared BlockingQueue!Fiber;
    queue.push(f);
    atomicOp!"+="(alive, 1);
}

shared DescriptorState[] descriptors;
shared int event_loop_fd;

struct AwaitingFiber {
    Fiber fiber;
    int op; // EPOLLIN = reading & EPOLLOUT = writing
}

// list of awaiting fibers
struct DescriptorState {
    AwaitingFiber[] waiters;  // can optimize for 1-element case, more on that later
    bool firstUse = true;
}

void add_await(int fd, Fiber fiber, int op) {
    mtx.lock();
    (cast(DescriptorState[])descriptors)[fd].waiters ~= AwaitingFiber(currentFiber, op);
    mtx.unlock();
}

void event_add_fd(int fd) { // register new FD
    epoll_event event;
    event.events = EPOLLIN | EPOLLOUT; // TODO: most events that make sense to watch for
    event.data.fd = fd;
    epoll_ctl(event_loop_fd, EPOLL_CTL_ADD, fd, &event).checked("ERROR: failed epoll_ctl add!");
}

void event_remove_fd(int fd) { // TODO: on LibC's close
    epoll_ctl(event_loop_fd, EPOLL_CTL_DEL, fd, null).checked("ERROR: failed epoll_ctl delete!");
}

void startloop()
{
    mtx = cast(shared)new Mutex();
    event_loop_fd = cast(int)epoll_create1(0).checked("ERROR: Failed to create event-loop!");
    ssize_t fdMax = sysconf(_SC_OPEN_MAX).checked;
    descriptors = cast(shared)new DescriptorState[fdMax];

    auto io = new Thread(&eventloop, 64*1024);
    io.start();
}

void eventloop()
{
    epoll_event[MAX_EVENTS] events;
    while(!completed || managedThreads > 0) {
        int r = epoll_wait(event_loop_fd, events.ptr, MAX_EVENTS, TIMEOUT)
            .checked("ERROR: failed epoll_wait");
        //debug stderr.writefln("Passed epoll_wait, r = %d", r);

        for (int n = 0; n < r; n++) {
            int fd = events[n].data.fd;
            mtx.lock();
            auto w = descriptors[fd].waiters;

            //TODO: remove the ones from the waiting list
            size_t j = 0;
            for (size_t i = 0; i<w.length;) {
                auto a = w[i];
                //stderr.writefln("Event %s on fd=%s op=%s waiter=%s", events[n].events, events[n].data.fd, a.op, cast(void*)a.fiber);
                // 3. the trick is read and write are separate, and then there are TODO: exceptions (errors)
                if ((a.op & events[n].events) != 0) {
                    logf("EVENT ON %d", fd);
                    queue.push(cast(Fiber)(a.fiber));
                    i++;
                }
                else {
                    w[j] = w[i];
                    j++;
                    i++;
                }
            }
            descriptors[fd].waiters = w[0..j];
            mtx.unlock();
            Thread.yield();
        }
    }
    logf("Exited event loop!");
}
