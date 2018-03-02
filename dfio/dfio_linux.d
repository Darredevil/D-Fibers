module dfio_linux;
version(linux):
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
import core.sys.posix.poll;
import core.sys.posix.netinet.in_;
import core.sys.posix.unistd;
import core.sys.linux.epoll;
import core.sys.linux.timerfd;
import core.sync.mutex;
import core.stdc.errno;
import core.atomic;
import BlockingQueue;
import ObjectPool : ObjectPool, TimerFD;
import core.sys.posix.stdlib: abort;
import core.sys.posix.fcntl;
import core.memory;
import core.sys.posix.sys.mman;
import core.sys.posix.pthread;
import core.sys.posix.aio;
import core.sys.linux.sys.signalfd;
import core.stdc.string : memset;

class FiberExt : Fiber { 
    FiberExt next;

    enum PAGESIZE = 4096;
    
    this(void function() fn, size_t sz = PAGESIZE*4, size_t guardPageSize = PAGESIZE ) nothrow {
        super(fn, sz, guardPageSize);
    }

    this(void delegate() dg, size_t sz = PAGESIZE*4, size_t guardPageSize = PAGESIZE ) nothrow {
        super(dg, sz, guardPageSize);
    }
}

FiberExt currentFiber; // this is TLS per user thread

shared int alive; // count of non-terminated Fibers

shared IntrusiveQueue!FiberExt queue;
shared ObjectPool!TimerFD timerFdPool;
shared Mutex mtx;
shared int[int] timerfd_cache;

enum int TIMEOUT = 1, MAX_EVENTS = 100;
enum int SIGNAL = 42; // the range should be 32-64
//enum int SIGNAL = SIGRTMIN + 1;

enum int MSG_DONTWAIT = 0x40;

void logf(string file = __FILE__, int line = __LINE__, T...)(string msg, T args)
{
    debug stderr.writefln(msg, args);
    debug stderr.writefln("\tat %s:%s:[LWP:%s]", file, line, pthread_self());
}

ssize_t sys_read(int fd, void *buf, size_t count) {
    logf("Old school read");
    return syscall(SYS_READ, fd, cast(ssize_t) buf, cast(ssize_t) count).withErrorno;
}

ssize_t sys_write(int fd, const void *buf, size_t count)
{
    logf("Old school write");
    return syscall(SYS_WRITE, fd, cast(size_t) buf, count).withErrorno;
}

int sys_poll(pollfd *fds, nfds_t nfds, int timeout)
{
    logf("Old school poll");
    return cast(int)    syscall(SYS_POLL, cast(size_t)fds, cast(size_t) nfds, timeout).withErrorno;
}

int checked(int value, const char* msg="unknown place") {
    if (value < 0) {
        perror(msg);
        _exit(value);
    }
    return value;
}

ssize_t withErrorno(ssize_t resp){
    if(resp < 0) {
        //logf("Syscall ret %d", resp);
        errno = cast(int)-resp;
        return -1;
    }
    else {
        return resp;
    }
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
        SYS_POLL = 7,
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
            mov RDI, n;
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
            mov RDI, n;
            mov RSI, arg1;
            mov RDX, arg2;
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
            mov RDI, n;
            mov RSI, arg1;
            mov RDX, arg2;
            mov R10, arg3;
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
            mov RDI, n;
            mov RSI, arg1;
            mov RDX, arg2;
            mov R10, arg3;
            mov R8, arg4;
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
            mov RDI, n;
            mov RSI, arg1;
            mov RDX, arg2;
            mov R10, arg3;
            mov R8, arg4;
            mov R9, arg5;
            syscall;
            mov ret, RAX;
        }
        return ret;
    }
}

extern(C) private ssize_t read(int fd, void *buf, size_t count)
{
    if (currentFiber is null) {
        logf("READ PASSTHROUGH!");
        return syscall(SYS_READ, fd, cast(ssize_t) buf, cast(ssize_t) count).withErrorno;
    }
    else {
        logf("HOOKED READ WITH MY LIB fd=%d!", fd); // TODO: temporary for easy check, remove later
        interceptFd(fd);
        if(descriptors[fd].isSocket) { // socket
            for(;;) {
                ssize_t resp = syscall(SYS_READ, fd, cast(ssize_t) buf, cast(ssize_t) count);
                if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                    logf("READ GOT DELAYED - FD %d, resp = %d", fd, resp);
                    reschedule(fd, currentFiber, EPOLLIN);
                    continue;
                }
                else
                    return withErrorno(resp);
            }
        } else { // file
            aiocb myaiocb;
            myaiocb.aio_fildes = fd;
            myaiocb.aio_buf = buf;
            myaiocb.aio_nbytes = count;
            myaiocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
            myaiocb.aio_sigevent.sigev_signo = SIGNAL;
            //myaiocb.aio_sigevent.sigev_value = cast(sigval)fd;
            sigval tmp;
            tmp.sival_ptr = cast(void*)currentFiber;
            myaiocb.aio_sigevent.sigev_value = tmp;
            ssize_t r = aio_read(&myaiocb).checked;
            //reschedule(fd, currentFiber, EPOLLIN);
            currentFiber.yield();
            logf("aio_read resp = %d", r);
            ssize_t resp = aio_return(&myaiocb);
            return resp;
        }
        assert(0);
    }
}

extern(C) private ssize_t write(int fd, const void *buf, size_t count)
{
    if (currentFiber is null) {
        logf("WRITE PASSTHROUGH!");
        return syscall(SYS_WRITE, fd, cast(size_t) buf, count).withErrorno;
    }
    else {
        logf("HOOKED WRITE FD=%d!", fd);
        interceptFd(fd);
        if(descriptors[fd].isSocket) { // socket
            logf("Socket path");
            for(;;) {
                ssize_t resp = syscall(SYS_WRITE, fd, cast(ssize_t) buf, cast(ssize_t) count);
                if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                    logf("WRITE GOT DELAYED - FD %d, resp = %d", fd, resp);
                    reschedule(fd, currentFiber, EPOLLOUT/* | EPOLLIN*/);
                    continue;
                }
                else
                    return withErrorno(resp);
            }
        } else { // file
            logf("File path");
            aiocb myaiocb;
            myaiocb.aio_fildes = fd;
            myaiocb.aio_buf = cast(void*)buf;
            myaiocb.aio_nbytes = count;
            myaiocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
            myaiocb.aio_sigevent.sigev_signo = SIGNAL;
            //myaiocb.aio_sigevent.sigev_value = cast(sigval)fd;
            sigval tmp;
            tmp.sival_ptr = cast(void*)currentFiber;
            myaiocb.aio_sigevent.sigev_value = tmp;
            //myaiocb.aio_sigevent.sigev_value = cast(sigval)(cast(void*)currentFiber);
            ssize_t r = aio_write(&myaiocb).checked;
            //reschedule(fd, currentFiber, EPOLLOUT/* | EPOLLIN*/);
            currentFiber.yield();
            logf("aio_write resp = %d", r);
            ssize_t resp = aio_return(&myaiocb);
            return resp;
        }
        assert(0);
    }
}

extern(C) private int accept(int sockfd, sockaddr *addr, socklen_t *addrlen)
{
    if (currentFiber is null) {
        logf("ACCEPT PASSTHROUGH FD=%d", sockfd);
        ssize_t resp = cast(int)syscall(SYS_ACCEPT, sockfd, cast(size_t) addr, cast(size_t) addrlen);
        return cast(int)withErrorno(resp);
    }
    else {
        logf("HOOKED ACCEPT FD=%d", sockfd); // TODO: temporary for easy check, remove later
        interceptFd(sockfd);
        for(;;) {
            ssize_t resp = syscall(SYS_ACCEPT, sockfd, cast(size_t) addr, cast(size_t) addrlen);
            if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                logf("ACCEPT GOT DELAYED - sockfd %d, resp = %d", sockfd, resp);
                reschedule(sockfd, currentFiber, EPOLLIN);
                continue;
            }
            return cast(int)withErrorno(resp);
        }
        assert(0);
    }
}

extern(C) private int accept4(int sockfd, sockaddr *addr, socklen_t *addrlen, int flags)
{
    logf("HOOKED ACCEPT4 WITH MY LIB!"); // TODO: temporary for easy check, remove later

    ssize_t ret = syscall(SYS_ACCEPT4, sockfd, cast(size_t) addr, cast(size_t) addrlen, flags);
    return cast(int) withErrorno(ret);
}

extern(C) private int connect(int sockfd, const sockaddr *addr, socklen_t *addrlen)
{
    if (currentFiber is null) {
        logf("CONNECT PASSTHROUGH!");
        return cast(int)syscall(SYS_CONNECT, sockfd, cast(size_t) addr, cast(size_t) addrlen).withErrorno;
    }
    else {
        logf("HOOKED CONNECT WITH MY LIB!"); // TODO: temporary for easy check, remove later
        interceptFd(sockfd);
        for(;;) {
            ssize_t resp = syscall(SYS_CONNECT, sockfd, cast(size_t) addr, cast(size_t) addrlen);
            if (resp == -EINPROGRESS || resp == -EAGAIN) {
                logf("CONNECT GOT DELAYED - sockfd %d, resp = %d", sockfd, resp);
                reschedule(sockfd, currentFiber, EPOLLIN);
                continue;
            }
            else
                return cast(int)withErrorno(resp);
        }
        assert(0);
    }
}

extern(C) private ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                      const sockaddr *dest_addr, socklen_t addrlen)
{
    if (currentFiber is null) {
        logf("SENDTO PASSTHROUGH!");
        return cast(int)syscall(SYS_SENDTO, sockfd, cast(size_t) dest_addr, cast(size_t) addrlen).withErrorno;
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
            else
                return withErrorno(resp);
        }
        assert(0);
    }
}

extern(C) private ssize_t recv(int sockfd, const void *buf, size_t len, int flags)
{
    sockaddr_in src_addr;
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = 0;
    src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    size_t addrlen = sockaddr_in.sizeof;
    if (currentFiber is null) {
        logf("RECV PASSTHROUGH FD=%d !", sockfd);
        return cast(int)syscall(SYS_RECVFROM, sockfd,  cast(size_t) buf, len, flags,
            cast(size_t) &src_addr, cast(size_t)&addrlen).withErrorno;
    }
    else {
        logf("HOOKED RECV FD=%d", sockfd);
        interceptFdNoFcntl(sockfd);
        for(;;) {
            ssize_t resp = syscall(SYS_RECVFROM, sockfd, cast(size_t) buf, len, MSG_DONTWAIT | flags,
                cast(size_t) &src_addr, cast(size_t)&addrlen);
            if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                logf("RECV GOT DELAYED - sockfd %d, resp = %d", sockfd, resp);
                reschedule(sockfd, currentFiber, EPOLLIN);
                continue;
            }
            else
                return withErrorno(resp);
        }
        assert(0);
    }
}

extern(C) private ssize_t recvfrom(int sockfd, const void *buf, size_t len, int flags,
                      const sockaddr *src_addr, ssize_t* addrlen)
{
    if (currentFiber is null) {
        logf("RECEIVEFROM PASSTHROUGH!");
        return cast(int)syscall(SYS_RECVFROM, sockfd,  cast(size_t) buf, len, flags,
                cast(size_t) src_addr, cast(size_t)addrlen).withErrorno;
    }
    else {
        logf("HOOKED RECEIVEFROM WITH MY LIB!"); // TODO: temporary for easy check, remove later
        interceptFdNoFcntl(sockfd);
        for(;;) {
            ssize_t resp = syscall(SYS_RECVFROM, sockfd, cast(size_t) buf, len, MSG_DONTWAIT | flags,
                cast(size_t) src_addr, cast(size_t)addrlen);
            if (resp == -EWOULDBLOCK || resp == -EAGAIN) {
                logf("RECEIVEFROM GOT DELAYED - sockfd %d, resp = %d", sockfd, resp);
                reschedule(sockfd, currentFiber, EPOLLIN);
                continue;
            }
            else
                return withErrorno(resp);
        }
        assert(0);
    }
}

extern(C) private ssize_t close(int fd)
{
    logf("HOOKED CLOSE!");
    deregisterFd(fd);
    return cast(int)withErrorno(syscall(SYS_CLOSE, fd));
}

extern(C) private int poll(pollfd *fds, nfds_t nfds, int timeout)
{
    if (currentFiber is null) {
        logf("POLL PASSTHROUGH!");
        return cast(int)syscall(SYS_POLL, cast(size_t)fds, cast(size_t)nfds, timeout).withErrorno;
    }
    else {
        logf("HOOKED POLL");
        if (timeout <= 0) return sys_poll(fds, nfds, timeout);

        foreach (ref fd; fds[0..nfds]) {
            interceptFd(fd.fd);
            descriptors[fd.fd].unshared.blockFiber(currentFiber, fd.events);
        }
        TimerFD tfd = timerFdPool.getObject();
        int timerfd = tfd.getFD();
        tfd.armTimer(timeout);
        interceptFd(timerfd);
        descriptors[timerfd].unshared.blockFiber(currentFiber, EPOLLIN);
        Fiber.yield();

        timerFdPool.releaseObject(tfd);
        foreach (ref fd; fds[0..nfds]) {
            descriptors[fd.fd].unshared.removeFiber(currentFiber);
        }

        return sys_poll(fds, nfds, 0);
    }
}

void runFibers()
{
    int counter = 0;
    while (alive > 0) {
        //logf("while alive(%d) > 0", alive);
        //currentFiber = take(queue); // TODO implement take
        if (queue.tryPop(currentFiber)) {
            logf("FiberExt %x started", cast(void*)currentFiber);
            if (currentFiber is null) abort();
            currentFiber.call();
            if (currentFiber.state == FiberExt.State.TERM) {
                logf("FiberExt %s terminated", cast(void*)currentFiber);
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
    auto f = new FiberExt(func);
    queue.push(f);
    atomicOp!"+="(alive, 1);
}

shared DescriptorState[] descriptors;
shared int event_loop_fd;
shared int signal_loop_fd;

struct AwaitingFiber {
    FiberExt fiber;
    int op; // EPOLLIN = reading & EPOLLOUT = writing
}

// list of awaiting fibers
struct DescriptorState {
    union
    {
        AwaitingFiber[] waiters;
        AwaitingFiber single;
    }
    uint size;
    bool intercepted = false;
    bool isSocket = false;

    void removeFiber(FiberExt f)
    {
        if (size == 0) return;
        else if (size == 1) size = 0;
        else {
            size_t j = 0;
            for (size_t i = 0; i<waiters.length;) {
                auto a = waiters[i];
                // TODO: exceptions (errors)
                if (a.fiber == f) {
                    i++;
                }
                else {
                    waiters[j] = waiters[i];
                    j++;
                    i++;
                }
            }
            waiters = waiters[0..j];
            size = cast(uint)j;
            if (size == 1) {
                single = waiters[0];
                waiters = null;
            }
            else
                waiters.assumeSafeAppend();
        }
    }

    void blockFiber(FiberExt f, int op)
    {
        if (size == 0)
            single = AwaitingFiber(currentFiber, op);
        else if (size == 1)
            waiters = [single, AwaitingFiber(currentFiber, op)];
        else
            waiters ~= AwaitingFiber(currentFiber, op);
        size += 1;
    }

    uint unblockFibers(int event) {
        if(size == 0) return 0;
        uint unblocked;
        if (size == 1) {
            if ((single.op & event) != 0) {
                queue.push(cast(FiberExt)(single.fiber));
                size = 0;
                unblocked += 1;
            }
        }
        else {
            size_t j = 0;
            for (size_t i = 0; i<waiters.length;) {
                auto a = waiters[i];
                // TODO: exceptions (errors)
                if ((a.op & event) != 0) {
                    queue.push(cast(FiberExt)(a.fiber));
                    unblocked += 1;
                    i++;
                }
                else {
                    waiters[j] = waiters[i];
                    j++;
                    i++;
                }
            }
            waiters = waiters[0..j];
            size = cast(uint)j;
            if (size == 1) {
                single = waiters[0];
                waiters = null;
            }
            else
                waiters.assumeSafeAppend();
        }
        return unblocked;
    }
}

// intercept - a filter for file descriptor, changes flags and register on first use
void interceptFd(int fd) {
    logf("Hit interceptFD");
    if (fd < 0 || fd >= descriptors.length) return;
    if (!descriptors[fd].intercepted) {
        logf("First use, registering fd = %d", fd);
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK).checked;
        epoll_event event;
        event.events = EPOLLIN | EPOLLOUT; // TODO: most events that make sense to watch for
        event.data.fd = fd;
        if (epoll_ctl(event_loop_fd, EPOLL_CTL_ADD, fd, &event) < 0 && errno == EPERM) {
            logf("Detected real file FD, switching from epoll to aio");
            descriptors[fd].isSocket = false;
        }
        else {
            logf("isSocket = true");
            descriptors[fd].isSocket = true;
        }
        descriptors[fd].intercepted = true;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (!(flags & O_NONBLOCK)) {
        logf("WARNING: Socket (%d) not set in O_NONBLOCK mode!", fd);
        //abort(); //TODO: enforce abort?
    }
}

void interceptFdNoFcntl(int fd) {
    logf("Hit interceptFdNoFcntl");
    if (fd < 0 || fd >= descriptors.length) return;
    if (!descriptors[fd].intercepted) {
        logf("First use, registering fd = %d", fd);
        epoll_event event;
        event.events = EPOLLIN | EPOLLOUT; // TODO: most events that make sense to watch for
        event.data.fd = fd;
        if (epoll_ctl(event_loop_fd, EPOLL_CTL_ADD, fd, &event) < 0 && errno == EPERM) {
            logf("Detected real file FD, switching from epoll to aio");
            descriptors[fd].isSocket = false;
        }
        else {
            logf("isSocket = true");
            descriptors[fd].isSocket = true;
        }
        descriptors[fd].intercepted = true;
    }
}

void deregisterFd(int fd) {
    if(fd >= 0 && fd < descriptors.length) descriptors[fd].intercepted = false;
}

// reschedule - put fiber in a wait list, and get back to scheduling loop
void reschedule(int fd, FiberExt fiber, int op) {
    mtx.lock();
    descriptors[fd].unshared.blockFiber(currentFiber, op);
    mtx.unlock();
    FiberExt.yield();
}

extern(C) void myhandle(int mysignal, siginfo_t *si, void* arg) {
    printf("Signale intercepted, doing nothing\n");
}

void startloop()
{
    mtx = cast(shared)new Mutex();
    event_loop_fd = cast(int)epoll_create1(0).checked("ERROR: Failed to create event-loop!");

    // use RT signals, disable default termination on signal received
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset (&mask, SIGNAL);
    pthread_sigmask(SIG_BLOCK, &mask, null).checked;
    signal_loop_fd = cast(int)signalfd(-1, &mask, 0).checked("ERROR: Failed to create signalfd!");

    epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = signal_loop_fd;
    epoll_ctl(event_loop_fd, EPOLL_CTL_ADD, signal_loop_fd, &event).checked;

    ssize_t fdMax = sysconf(_SC_OPEN_MAX).checked;
    descriptors = (cast(shared(DescriptorState*)) mmap(null, fdMax * DescriptorState.sizeof, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0))[0..fdMax];
    timerFdPool = new shared ObjectPool!TimerFD;
}

size_t processEvents()
{
    epoll_event[MAX_EVENTS] events;
    signalfd_siginfo[20] fdsi;
    int r = epoll_wait(event_loop_fd, events.ptr, MAX_EVENTS, TIMEOUT)
        .checked("ERROR: failed epoll_wait");
    //logf("epoll_wait resp = %d", r);
    //debug stderr.writefln("Passed epoll_wait, r = %d", r);
    size_t unblocked = 0;
    for (int n = 0; n < r; n++) {
        int fd = events[n].data.fd;
        //logf("fd = %d, signalfd = %d", fd, signal_loop_fd);
        mtx.lock();
        if (fd == signal_loop_fd) {
            logf("Intercepted our aio SIGNAL");
            ssize_t r2 = sys_read(signal_loop_fd, &fdsi, fdsi.sizeof);
            logf("aio events = %d", r2 / signalfd_siginfo.sizeof);
            if (r2 % signalfd_siginfo.sizeof != 0)
                checked(r2, "ERROR: failed read on signalfd");

            for(int i = 0; i < r2 / signalfd_siginfo.sizeof; i++) { //TODO: stress test multiple signals
                logf("Processing aio event idx = %d", i);
                if (fdsi[i].ssi_signo == SIGNAL) {
                    logf("HIT our SIGNAL");
                    //int fd2 = fdsi[i].ssi_int;
                    //unblocked += descriptors[fd2].unshared.unblockFibers(events[n].events);
                    queue.push(cast(FiberExt)(cast(void*)fdsi[i].ssi_ptr));
                    unblocked += 1;
                    logf("unblocked = %d", unblocked);
                }
            }
        } else {
            unblocked += descriptors[fd].unshared.unblockFibers(events[n].events);
        }
        mtx.unlock();
    }

    return unblocked;
}
