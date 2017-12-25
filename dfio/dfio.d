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
import core.sys.posix.sys.socket;
import core.sys.posix.netinet.in_;
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

enum int TIMEOUT = 1, MAX_EVENTS = 100;

enum int MSG_DONTWAIT = 0x40;

void logf(string file = __FILE__, int line = __LINE__, T...)(string msg, T args)
{
    stderr.writefln("%s:%s:[LWP:%s]\t%s", file, line, Thread.getThis.id, format(msg, args));
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
    enum int
        SYS_READ = 0x0,
        SYS_WRITE = 0x1,
        SYS_CLOSE = 3,
        SYS_SOCKETPAIR = 0x35,
        SYS_ACCEPT = 0x2b,
        SYS_ACCEPT4 = 0x120,
        SYS_CONNECT = 0x2a,
        SYS_SENDTO = 0x2c,
        SYS_RECVFROM = 45;

    size_t syscall(size_t ident, size_t n)
    {
        size_t ret;

        asm
        {
            mov RAX, ident;
            mov RDI, n[RBP];
            syscall;
            mov ret, RAX;
        }
        return ret;
    }

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

    size_t syscall(size_t ident, size_t n, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5)
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
            mov R9, arg5[RBP];
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
        interceptFd(fd);
        for(;;) {
            ssize_t resp = syscall(SYS_READ, fd, cast(ssize_t) buf, cast(ssize_t) count);
            if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                logf("READ GOT DELAYED - FD %d, resp = %d", fd, resp);
                reschedule(fd, currentFiber, EPOLLIN);
                continue;
            }
            else if(resp < 0) {
                errno = cast(int)-resp;
                return -1;
            }
            else {
                return resp;
            }
        }
        assert(0);
    }
}

extern(C) ssize_t write(int fd, const void *buf, size_t count)
{
    logf("HOOKED WRITE WITH MY LIB!"); // TODO: temporary for easy check, remove later

    ssize_t ret = syscall(SYS_WRITE, fd, cast(size_t) buf, count);
    if (ret < 0)
        abort();
    return cast(int) ret;
}

extern(C) int accept(int sockfd, sockaddr *addr, socklen_t *addrlen)
{
    if (currentFiber is null) {
        logf("ACCEPT PASSTHROUGH!");
        return cast(int)syscall(SYS_ACCEPT, sockfd, cast(size_t) addr, cast(size_t) addrlen);
    }
    else {
        logf("HOOKED ACCEPT WITH MY LIB!"); // TODO: temporary for easy check, remove later
        interceptFd(sockfd);
        for(;;) {
            ssize_t resp = syscall(SYS_ACCEPT, sockfd, cast(size_t) addr, cast(size_t) addrlen);
            if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                logf("ACCEPT GOT DELAYED - sockfd %d, resp = %d", sockfd, resp);
                reschedule(sockfd, currentFiber, EPOLLIN);
                continue;
            }
            else if(resp < 0) {
                errno = cast(int)-resp;
                return -1;
            }
            else {
                return cast(int)resp;
            }
        }
        assert(0);
    }
}

extern(C) int accept4(int sockfd, sockaddr *addr, socklen_t *addrlen, int flags)
{
    logf("HOOKED ACCEPT4 WITH MY LIB!"); // TODO: temporary for easy check, remove later

    ssize_t ret = syscall(SYS_ACCEPT4, sockfd, cast(size_t) addr, cast(size_t) addrlen, flags);
    if (ret < 0)
        abort();
    return cast(int) ret;
}

extern(C) int connect(int sockfd, const sockaddr *addr, socklen_t addrlen)
{
    if (currentFiber is null) {
        logf("CONNECT PASSTHROUGH!");
        return cast(int)syscall(SYS_CONNECT, sockfd, cast(size_t) addr, cast(size_t) addrlen);
    }
    else {
        logf("HOOKED CONNECT WITH MY LIB!"); // TODO: temporary for easy check, remove later
        interceptFd(sockfd);
        for(;;) {
            ssize_t resp = syscall(SYS_CONNECT, sockfd, cast(size_t) addr, cast(size_t) addrlen);
            if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                logf("CONNECT GOT DELAYED - sockfd %d, resp = %d", sockfd, resp);
                reschedule(sockfd, currentFiber, EPOLLIN);
                continue;
            }
            else if(resp < 0) {
                errno = cast(int)-resp;
                return -1;
            }
            else {
                return cast(int)resp;
            }
        }
        assert(0);
    }
}

extern(C) ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                      const sockaddr *dest_addr, socklen_t addrlen)
{
    if (currentFiber is null) {
        logf("SENDTO PASSTHROUGH!");
        return cast(int)syscall(SYS_SENDTO, sockfd, cast(size_t) dest_addr, cast(size_t) addrlen);
    }
    else {
        logf("HOOKED SENDTO WITH MY LIB!"); // TODO: temporary for easy check, remove later
        interceptFdNoFcntl(sockfd);
        for(;;) {
            ssize_t resp = syscall(SYS_SENDTO, sockfd, cast(size_t) buf, len, MSG_DONTWAIT | flags,
                cast(size_t) dest_addr, addrlen);
            if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                logf("SENDTO GOT DELAYED - sockfd %d, resp = %d", sockfd, resp);
                reschedule(sockfd, currentFiber, EPOLLIN);
                continue;
            }
            else if(resp < 0) {
                errno = cast(int)-resp;
                return -1;
            }
            else {
                return resp;
            }
        }
        assert(0);
    }
}

extern(C) ssize_t recv(int sockfd, const void *buf, size_t len, int flags)
{
    sockaddr_in src_addr;
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = 0;
    src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    size_t addrlen = sockaddr_in.sizeof;
    if (currentFiber is null) {
        logf("RECV PASSTHROUGH!");
        return cast(int)syscall(SYS_RECVFROM, sockfd,  cast(size_t) buf, len, flags,
            cast(size_t) &src_addr, cast(size_t)&addrlen);
    }
    else {
        logf("HOOKED RECV WITH MY LIB!"); // TODO: temporary for easy check, remove later
        interceptFdNoFcntl(sockfd);
        for(;;) {
            ssize_t resp = syscall(SYS_RECVFROM, sockfd, cast(size_t) buf, len, MSG_DONTWAIT | flags,
                cast(size_t) &src_addr, cast(size_t)&addrlen);
            if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                logf("RECV GOT DELAYED - sockfd %d, resp = %d", sockfd, resp);
                reschedule(sockfd, currentFiber, EPOLLIN);
                continue;
            }
            else if(resp < 0) {
                errno = cast(int)-resp;
                return -1;
            }
            else {
                return resp;
            }
        }
        assert(0);
    }
}

extern(C) ssize_t recvfrom(int sockfd, const void *buf, size_t len, int flags,
                      const sockaddr *src_addr, socklen_t addrlen)
{
    if (currentFiber is null) {
        logf("RECEIVEFROM PASSTHROUGH!");
        return cast(int)syscall(SYS_RECVFROM, sockfd,  cast(size_t) buf, len, flags,
                cast(size_t) src_addr, addrlen);
    }
    else {
        logf("HOOKED RECEIVEFROM WITH MY LIB!"); // TODO: temporary for easy check, remove later
        interceptFdNoFcntl(sockfd);
        for(;;) {
            ssize_t resp = syscall(SYS_RECVFROM, sockfd, cast(size_t) buf, len, MSG_DONTWAIT | flags,
                cast(size_t) src_addr, addrlen);
            if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                logf("RECEIVEFROM GOT DELAYED - sockfd %d, resp = %d", sockfd, resp);
                reschedule(sockfd, currentFiber, EPOLLIN);
                continue;
            }
            else if(resp < 0) {
                errno = cast(int)-resp;
                return -1;
            }
            else {
                return resp;
            }
        }
        assert(0);
    }
}

extern(C) ssize_t close(int fd)
{
    logf("HOOKED CLOSE!");
    deregisterFd(fd);
    return cast(int)syscall(SYS_CLOSE, fd);
}

void runFibers()
{
    int counter = 0;
    while (alive > 0) {
        //currentFiber = take(queue); // TODO implement take
        if (queue.tryPop(currentFiber)) {
            logf("Fiber %x started", cast(void*)currentFiber);
            currentFiber.call();
            if (currentFiber.state == Fiber.State.TERM) {
                logf("Fiber %s terminated", cast(void*)currentFiber);
                atomicOp!"-="(alive, 1);
            }
        }
        else {
             // TODO: only one thread should process events at the same time
             // should use tryLock pattern of sorts
            if (processEvents() == 0) {
                // TODO: wouldn't need to progressively sleep once we do edge-triggered eventloop
                if (counter < 10) {
                    counter += 1;
                    Thread.yield();
                }
                else {
                    Thread.sleep(1.msecs);
                }
            }
            else {
                counter = 0; 
            }
        }
    }
}

void spawn(void delegate() func) {
    auto f = new Fiber(func);
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

// intercept - a filter for file descriptor, changes flags and register on first use
void interceptFd(int fd) {
    if (fd < 0 || fd >= descriptors.length) return;
    if (descriptors[fd].firstUse) {
        logf("First use, registering fd = %d", fd);
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK).checked;
        epoll_event event;
        event.events = EPOLLIN | EPOLLOUT; // TODO: most events that make sense to watch for
        event.data.fd = fd;
        epoll_ctl(event_loop_fd, EPOLL_CTL_ADD, fd, &event).checked("ERROR: failed epoll_ctl add!");
        descriptors[fd].firstUse = false;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (!(flags & O_NONBLOCK)) {
        logf("WARNING: Socket (%d) not set in O_NONBLOCK mode!", fd);
        //abort(); //TODO: enforce abort?
    }
}

void interceptFdNoFcntl(int fd) {
    if (fd < 0 || fd >= descriptors.length) return;
    if (descriptors[fd].firstUse) {
        epoll_event event;
        event.events = EPOLLIN | EPOLLOUT; // TODO: most events that make sense to watch for
        event.data.fd = fd;
        epoll_ctl(event_loop_fd, EPOLL_CTL_ADD, fd, &event).checked("ERROR: failed epoll_ctl add!");
        descriptors[fd].firstUse = false;
    }
}

void deregisterFd(int fd) {
    if(fd >= 0 && fd < descriptors.length) descriptors[fd].firstUse = true;
}

// reschedule - put fiber in a wait list, and get back to scheduling loop
void reschedule(int fd, Fiber fiber, int op) {
    mtx.lock();
    (cast(DescriptorState[])descriptors)[fd].waiters ~= AwaitingFiber(currentFiber, op);
    mtx.unlock();
    Fiber.yield();
}

void startloop()
{
    mtx = cast(shared)new Mutex();
    event_loop_fd = cast(int)epoll_create1(0).checked("ERROR: Failed to create event-loop!");
    ssize_t fdMax = sysconf(_SC_OPEN_MAX).checked;
    descriptors = cast(shared)new DescriptorState[fdMax];
    queue = new shared BlockingQueue!Fiber;
}

size_t processEvents()
{
    epoll_event[MAX_EVENTS] events;
    int r = epoll_wait(event_loop_fd, events.ptr, MAX_EVENTS, TIMEOUT)
        .checked("ERROR: failed epoll_wait");
    //debug stderr.writefln("Passed epoll_wait, r = %d", r);
    size_t unblocked = 0;
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
                unblocked += 1;
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
    }
    return unblocked;
}