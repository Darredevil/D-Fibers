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
import core.sys.linux.sys.signalfd;
import core.sys.linux.sched;

extern(C) int eventfd(uint initial, int flags) nothrow;

shared struct Event {
nothrow:
    this(int init) {
        fd = eventfd(init, 0);
    }

    void waitAndReset() {
        ubyte[8] bytes = void;
        ssize_t r;
        do {
            r = sys_read(fd, bytes.ptr, 8);
        } while(r < 0 && errno == EINTR);
        r.checked("event reset");
    }
    
    void trigger() { 
        union U {
            ulong cnt;
            ubyte[8] bytes;
        }
        U value;
        value.cnt = 1;
        ssize_t r;
        do {
            r = sys_write(fd, value.bytes.ptr, 8);
        } while(r < 0 && errno == EINTR);
        r.checked("event trigger");
    }
    
    int fd;
}

class FiberExt : Fiber { 
    FiberExt next;
    uint numScheduler;

    enum PAGESIZE = 4096;
    
    this(void function() fn, uint numSched) nothrow {
        super(fn);
        numScheduler = numSched;
    }

    this(void delegate() dg, uint numSched) nothrow {
        super(dg);
        numScheduler = numSched;
    }

    void schedule() nothrow
    {
        scheds[numScheduler].queue.push(this);
    }
}

FiberExt currentFiber; // this is TLS per user thread
shared Event termination; // termination event, triggered once last fiber exits
shared pthread_t eventLoop; // event loop, runs outside of D runtime
shared int alive; // count of non-terminated Fibers

struct SchedulerBlock {
    shared IntrusiveQueue!(FiberExt, Event) queue;
    shared uint assigned;
    size_t[2] padding;
}

static assert(SchedulerBlock.sizeof == 64);

shared SchedulerBlock[] scheds;
shared ObjectPool!TimerFD timerFdPool;

enum int MAX_EVENTS = 500;
enum int SIGNAL = 42; // the range should be 32-64
//enum int SIGNAL = SIGRTMIN + 1;

enum int MSG_DONTWAIT = 0x40;

void logf(string file = __FILE__, int line = __LINE__, T...)(string msg, T args)
{
    version(none) debug stderr.writefln(msg, args);
    version(none) debug stderr.writefln("\tat %s:%s:[LWP:%s]", file, line, pthread_self());
}

ssize_t sys_read(int fd, void *buf, size_t count) nothrow {
    logf("Old school read");
    return syscall(SYS_READ, fd, cast(ssize_t) buf, cast(ssize_t) count).withErrorno;
}

ssize_t sys_write(int fd, const void *buf, size_t count) nothrow
{
    logf("Old school write");
    return syscall(SYS_WRITE, fd, cast(size_t) buf, count).withErrorno;
}

int sys_poll(pollfd *fds, nfds_t nfds, int timeout)
{
    logf("Old school poll");
    return cast(int)    syscall(SYS_POLL, cast(size_t)fds, cast(size_t) nfds, timeout).withErrorno;
}

int checked(int value, const char* msg="unknown place") nothrow {
    if (value < 0) {
        perror(msg);
        _exit(value);
    }
    return value;
}

ssize_t withErrorno(ssize_t resp) nothrow {
    if(resp < 0) {
        //logf("Syscall ret %d", resp);
        errno = cast(int)-resp;
        return -1;
    }
    else {
        return resp;
    }
}

ssize_t checked(ssize_t value, const char* msg="unknown place") nothrow {
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

        asm nothrow
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

        asm nothrow
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

        asm nothrow
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
        SYS_GETTID = 186,
        SYS_SOCKETPAIR = 0x35,
        SYS_ACCEPT = 0x2b,
        SYS_ACCEPT4 = 0x120,
        SYS_CONNECT = 0x2a,
        SYS_SENDTO = 0x2c,
        SYS_RECVFROM = 45;

    size_t syscall(size_t ident) nothrow
    {
        size_t ret;

        asm nothrow
        {
            mov RAX, ident;
            syscall;
            mov ret, RAX;
        }
        return ret;
    }

    size_t syscall(size_t ident, size_t n) nothrow
    {
        size_t ret;

        asm nothrow
        {
            mov RAX, ident;
            mov RDI, n;
            syscall;
            mov ret, RAX;
        }
        return ret;
    }

    size_t syscall(size_t ident, size_t n, size_t arg1, size_t arg2) nothrow
    {
        size_t ret;

        asm nothrow
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

    size_t syscall(size_t ident, size_t n, size_t arg1, size_t arg2, size_t arg3) nothrow
    {
        size_t ret;

        asm nothrow
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

    size_t syscall(size_t ident, size_t n, size_t arg1, size_t arg2, size_t arg3, size_t arg4) nothrow
    {
        size_t ret;

        asm nothrow
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

    size_t syscall(size_t ident, size_t n, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5) nothrow
    {
        size_t ret;

        asm nothrow
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

extern(C) private ssize_t read(int fd, void *buf, size_t count) nothrow
{
    return universalSyscall!(SYS_READ, "READ", SyscallKind.read, Fcntl.yes, EWOULDBLOCK)
        (fd, cast(size_t)buf, count);
}

extern(C) private ssize_t write(int fd, const void *buf, size_t count)
{
    return universalSyscall!(SYS_WRITE, "WRITE", SyscallKind.write, Fcntl.yes, EWOULDBLOCK)
        (fd, cast(size_t)buf, count);
}

extern(C) private ssize_t accept(int sockfd, sockaddr *addr, socklen_t *addrlen)
{
    return universalSyscall!(SYS_ACCEPT, "accept", SyscallKind.accept, Fcntl.yes, EWOULDBLOCK)
        (sockfd, cast(size_t) addr, cast(size_t) addrlen);    
}

extern(C) private ssize_t accept4(int sockfd, sockaddr *addr, socklen_t *addrlen, int flags)
{
    return universalSyscall!(SYS_ACCEPT4, "accept4", SyscallKind.accept, Fcntl.yes, EWOULDBLOCK)
        (sockfd, cast(size_t) addr, cast(size_t) addrlen, flags);
}

extern(C) private ssize_t connect(int sockfd, const sockaddr *addr, socklen_t *addrlen)
{
    return universalSyscall!(SYS_CONNECT, "connect", SyscallKind.accept, Fcntl.yes, EINPROGRESS)
        (sockfd, cast(size_t) addr, cast(size_t) addrlen);
}

extern(C) private ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                      const sockaddr *dest_addr, socklen_t addrlen)
{
    return universalSyscall!(SYS_SENDTO, "sendto", SyscallKind.read, Fcntl.no, EWOULDBLOCK)
        (sockfd, cast(size_t) buf, len, flags, cast(size_t) dest_addr, cast(size_t) addrlen);
}

extern(C) private ssize_t recv(int sockfd, void *buf, size_t len, int flags) nothrow {
    sockaddr_in src_addr;
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = 0;
    src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ssize_t addrlen = sockaddr_in.sizeof;
    return recvfrom(sockfd, buf, len, flags, cast(sockaddr*)&src_addr, &addrlen);   
}

ssize_t universalSyscall(size_t ident, string name, SyscallKind kind, Fcntl needsFcntl, ssize_t ERR, T...)
                        (int fd, T args) nothrow {
    if (currentFiber is null) {
        logf("%s PASSTHROUGH FD=%s", name, fd);
        return syscall(ident, fd, args).withErrorno;
    }
    else {
        logf("HOOKED %s FD=%d", name, fd);
        interceptFd!(needsFcntl)(fd);
        shared(Descriptor)* descriptor = descriptors.ptr + fd;
    L_start:
        static if(kind == SyscallKind.accept || kind == SyscallKind.read) {
            auto state = descriptor.readerState;
            logf("%s syscall state is %d", name, state);
            final switch (state) with (ReaderState) {
            case EMPTY:
                auto head = descriptor.readWaiters;
                if (!descriptor.enqueueReader(head, cast(shared)currentFiber)) goto L_start;
                // changed state to e.g. READY or UNCERTAIN in meantime, may need to reschedule
                if (descriptor.readerState != EMPTY) descriptor.scheduleReaders();
                FiberExt.yield();
                goto L_start;
            case UNCERTAIN:
                descriptor.changeReader(UNCERTAIN, READING); // may became READY or READING
                goto case READING;
            case READY:
                descriptor.changeReader(READY, READING); // always succeeds if 1 fiber reads
                goto case READING;
            case READING:
                ssize_t resp = syscall(ident, fd, args);
                static if (kind == SyscallKind.accept) {
                    if (resp >= 0) // for accept we never know if we emptied the queue
                        descriptor.changeReader(READING, UNCERTAIN);
                    else if (resp == -ERR || resp == -EAGAIN) {
                        if (descriptor.changeReader(READING, EMPTY))
                            goto case EMPTY;
                        goto L_start; // became UNCERTAIN or READY in meantime
                    }
                }
                else static if (kind == SyscallKind.read) {
                    if (resp == args[1]) // length is 2nd in (buf, length, ...)
                        descriptor.changeReader(READING, UNCERTAIN);
                    else if(resp >= 0)
                        descriptor.changeReader(READING, EMPTY);
                    else if (resp == -ERR || resp == -EAGAIN) {
                        if (descriptor.changeReader(READING, EMPTY))
                            goto case EMPTY;
                        goto L_start; // became UNCERTAIN or READY in meantime
                    }
                }
                else
                    static assert(0);
                return withErrorno(resp);
            }
        }
        else static if(kind == SyscallKind.write) {
            //TODO: Handle short-write b/c of EWOULDBLOCK to apear as fully blocking
            auto state = descriptor.writerState;
            logf("%s syscall state is %d", name, state);
            final switch (state) with (WriterState) {
            case FULL:
                auto head = descriptor.writeWaiters;
                if (!descriptor.enqueueReader(head, cast(shared)currentFiber)) goto L_start;
                // changed state to e.g. READY or UNCERTAIN in meantime, may need to reschedule
                if (descriptor.writerState != FULL) descriptor.scheduleWriters();
                FiberExt.yield();
                goto L_start;
            case UNCERTAIN:
                descriptor.changeWriter(UNCERTAIN, WRITING); // may became READY or WRITING
                goto case WRITING;
            case READY:
                descriptor.changeWriter(READY, WRITING); // always succeeds if 1 fiber writes
                goto case WRITING;
            case WRITING:
                ssize_t resp = syscall(ident, fd, args);
                if (resp == args[1]) // (buf, len) args to syscall
                    descriptor.changeWriter(WRITING, UNCERTAIN);
                else if(resp >= 0)
                    descriptor.changeWriter(WRITING, FULL);
                else if (resp == -ERR || resp == -EAGAIN) {
                    if (descriptor.changeWriter(WRITING, FULL))
                        goto case FULL;
                    goto L_start; // became UNCERTAIN or READY in meantime
                }
                return withErrorno(resp);
            }
        }
        assert(0);
    }
}

extern(C) private ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                        sockaddr *src_addr, ssize_t* addrlen) nothrow
{
    return universalSyscall!(SYS_RECVFROM, "RECVFROM", SyscallKind.read, Fcntl.no, EWOULDBLOCK)
        (sockfd, cast(size_t)buf, len, flags, cast(size_t)src_addr, cast(size_t)addrlen);
}

extern(C) private ssize_t close(int fd) nothrow
{
    logf("HOOKED CLOSE!");
    deregisterFd(fd);
    return cast(int)withErrorno(syscall(SYS_CLOSE, fd));
}

extern(C) private int poll(pollfd *fds, nfds_t nfds, int timeout)
{
    /*if (currentFiber is null) {
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
    }*/
    abort();
    return 0;
}

int gettid()
{
    return cast(int)syscall(SYS_GETTID);
}

void schedulerEntry(size_t n)
{
    int tid = gettid();
    cpu_set_t mask;
    CPU_SET(n, &mask);
    sched_setaffinity(tid, mask.sizeof, &mask).checked("sched_setaffinity");
    shared SchedulerBlock* sched = scheds.ptr + n;
    while (alive > 0) {
        sched.queue.event.waitAndReset();
        for(;;) {
            FiberExt f = sched.queue.drain();
            if (f is null) break; // drained an empty queue, time to sleep
            do {
                auto next = f.next; //save next, it will be reused on scheduling
                currentFiber = f;
                logf("Fiber %x started", cast(void*)f);
                try {
                    f.call();
                }
                catch (Exception e) {
                    stderr.writeln(e);
                    atomicOp!"-="(alive, 1);
                }
                if (f.state == FiberExt.State.TERM) {
                    logf("Fiber %s terminated", cast(void*)f);
                    atomicOp!"-="(alive, 1);
                }
                f = next;
            } while(f !is null);
        }
    }
    termination.trigger();
}

void spawn(void delegate() func) {
    import std.random;
    uint a = uniform!"[)"(0, cast(uint)scheds.length);
    uint b = uniform!"[)"(0, cast(uint)scheds.length-1);
    if (a == b) b = cast(uint)scheds.length-1;
    uint loadA = scheds[a].assigned;
    uint loadB = scheds[b].assigned;
    uint choice;
    if (loadA < loadB) choice = a;
    else choice = b;
    atomicOp!"+="(scheds[choice].assigned, 1);
    atomicOp!"+="(alive, 1);
    auto f = new FiberExt(func, choice);
    f.schedule();
}

shared Descriptor[] descriptors;
shared int event_loop_fd;
shared int signal_loop_fd;

enum ReaderState: uint {
    EMPTY = 0,
    UNCERTAIN = 1,
    READING = 2,
    READY = 3
}

enum WriterState: uint {
    READY = 0,
    UNCERTAIN = 1,
    WRITING = 2,
    FULL = 3
}

// list of awaiting fibers
shared struct Descriptor {
    ReaderState _readerState;   
    FiberExt _readerWaits;
    WriterState _writerState;
    FiberExt _writerWaits;
    bool intercepted;
    bool isSocket;
nothrow:
    ReaderState readerState()() {
        return atomicLoad(_readerState);
    }

    WriterState writerState()() {
        return atomicLoad(_writerState);
    }

    // try to change state & return whatever it happend to be in the end
    bool changeReader()(ReaderState from, ReaderState to) {
        return cas(&_readerState, from, to);
    }

    // ditto for writer
    bool changeWriter()(WriterState from, WriterState to) {
        return cas(&_writerState, from, to);
    }

    //
    shared(FiberExt) readWaiters()() {
        return atomicLoad(_readerWaits);
    }

    //
    shared(FiberExt) writeWaiters()(){
        return atomicLoad(_writerWaits);
    }

    // try to enqueue reader fiber given old head
    bool enqueueReader()(shared(FiberExt) head, shared(FiberExt) fiber) {
        fiber.next = head;
        return cas(&_readerWaits, head, fiber);
    }

    // try to enqueue writer fiber given old head
    bool enqueueWriter()(shared(FiberExt) head, shared(FiberExt) fiber) {
        fiber.next = head;
        return cas(&_writerWaits, head, fiber);
    }

    // try to schedule readers - if fails - someone added a reader, it's now his job to check state
    void scheduleReaders()() {
        auto w = readWaiters;
        if (w && cas(&_readerWaits, w, cast(shared)null)) {
            auto wu = w.unshared;
            while(wu.next) {
                wu.schedule();
                wu = wu.next;
            }
            wu.schedule();
        }
    }

    // try to schedule writers, ditto
    void scheduleWriters()() {
        auto w = writeWaiters;
        if (w && cas(&_writerWaits, w, cast(shared)null)) {
            auto wu = w.unshared;
            while(wu.next) {
                wu.schedule();
                wu = wu.next;
            }
            wu.schedule();
        }
    }
}

enum Fcntl { no, yes }
enum SyscallKind { accept, read, write }

// intercept - a filter for file descriptor, changes flags and register on first use
void interceptFd(Fcntl needsFcntl)(int fd) nothrow {
    logf("Hit interceptFD");
    if (fd < 0 || fd >= descriptors.length) return;
    if (cas(&descriptors[fd].intercepted, false, true)) {
        logf("First use, registering fd = %d", fd);
        static if(needsFcntl == Fcntl.yes) {
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK).checked;
        }
        epoll_event event;
        event.events = EPOLLIN | EPOLLOUT | EPOLLET;
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
    }
}

void deregisterFd(int fd) nothrow {
    if(fd >= 0 && fd < descriptors.length) {
        auto descriptor = descriptors.ptr + fd;
        atomicStore(descriptor._writerState, WriterState.READY);
        atomicStore(descriptor._readerState, ReaderState.EMPTY);
        descriptor.scheduleReaders();
        descriptor.scheduleWriters();
        atomicStore(descriptor.intercepted, false);
    }
}

extern(C) void graceful_shutdown_on_signal(int, siginfo_t*, void*)
{
    version(photon_tracing) printStats();
    _exit(9);
}

version(photon_tracing) 
void printStats()
{
    // TODO: report on various events in eventloop/scheduler
    string msg = "Tracing report:\n\n";
    write(2, msg.ptr, msg.length);
}

void startloop()
{
    import core.cpuid;
    uint threads = threadsPerCPU;

    event_loop_fd = cast(int)epoll_create1(0).checked("ERROR: Failed to create event-loop!");
    // use RT signals, disable default termination on signal received
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGNAL);
    pthread_sigmask(SIG_BLOCK, &mask, null).checked;
    signal_loop_fd = cast(int)signalfd(-1, &mask, 0).checked("ERROR: Failed to create signalfd!");

    epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = signal_loop_fd;
    epoll_ctl(event_loop_fd, EPOLL_CTL_ADD, signal_loop_fd, &event).checked;

    termination = Event(0);
    event.events = EPOLLIN;
    event.data.fd = termination.fd;
    epoll_ctl(event_loop_fd, EPOLL_CTL_ADD, termination.fd, &event).checked;

    {
        
        sigaction_t action;
        action.sa_sigaction = &graceful_shutdown_on_signal;
        sigaction(SIGTERM, &action, null).checked;
    }

    ssize_t fdMax = sysconf(_SC_OPEN_MAX).checked;
    descriptors = (cast(shared(Descriptor*)) mmap(null, fdMax * Descriptor.sizeof, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0))[0..fdMax];
    timerFdPool = new shared ObjectPool!TimerFD;
    scheds = new SchedulerBlock[threads];
    foreach(ref sched; scheds) {
        sched.queue = IntrusiveQueue!(FiberExt, Event)(Event(0));
    }
    eventLoop = pthread_create(cast(pthread_t*)&eventLoop, null, &processEventsEntry, null);
}

void stoploop()
{
    void* ret;
    pthread_join(eventLoop, &ret);
}

extern(C) void* processEventsEntry(void*)
{
    for (;;) {
        epoll_event[MAX_EVENTS] events = void;
        signalfd_siginfo[20] fdsi = void;
        int r;
        do {
            r = epoll_wait(event_loop_fd, events.ptr, MAX_EVENTS, -1);
        } while (r < 0 && errno == EINTR);
        checked(r);
        for (int n = 0; n < r; n++) {
            int fd = events[n].data.fd;
            if (fd == termination.fd) {
                foreach(ref s; scheds) s.queue.event.trigger();
                return null;
            }
            else if (fd == signal_loop_fd) {
                logf("Intercepted our aio SIGNAL");
                ssize_t r2 = sys_read(signal_loop_fd, &fdsi, fdsi.sizeof);
                logf("aio events = %d", r2 / signalfd_siginfo.sizeof);
                if (r2 % signalfd_siginfo.sizeof != 0)
                    checked(r2, "ERROR: failed read on signalfd");

                for(int i = 0; i < r2 / signalfd_siginfo.sizeof; i++) { //TODO: stress test multiple signals
                    logf("Processing aio event idx = %d", i);
                    if (fdsi[i].ssi_signo == SIGNAL) {
                        logf("HIT our SIGNAL");
                        auto fiber = cast(FiberExt)cast(void*)fdsi[i].ssi_ptr;
                        fiber.schedule();
                    }
                }
            }
            else {
                logf("Event for fd=%d", fd);
                auto descriptor = descriptors.ptr + fd;
                if (events[n].events & EPOLLIN) {
                    auto state = descriptor.readerState;
                    logf("state = %d", state);
                    final switch(state) with(ReaderState) { 
                        case EMPTY:
                            descriptor.changeReader(EMPTY, READY);
                            descriptor.scheduleReaders();
                            break;
                        case UNCERTAIN:
                            descriptor.changeReader(UNCERTAIN, READY);
                            break;
                        case READING:
                            if (!descriptor.changeReader(READING, UNCERTAIN)) {
                                if (descriptor.changeReader(EMPTY, UNCERTAIN)) // if became empty - move to UNCERTAIN and wake readers
                                    descriptor.scheduleReaders();
                            }
                            break;
                        case READY:
                            break;
                    }
                    logf("Awaits %x", cast(void*)descriptor.readWaiters);
                }
                if (events[n].events & EPOLLOUT) {
                    auto state = descriptor.writerState;
                    logf("state = %d", state);
                    final switch(state) with(WriterState) { 
                        case FULL:
                            descriptor.changeWriter(FULL, READY);
                            descriptor.scheduleWriters();
                            break;
                        case UNCERTAIN:
                            descriptor.changeWriter(UNCERTAIN, READY);
                            break;
                        case WRITING:
                            if (!descriptor.changeWriter(WRITING, UNCERTAIN)) {
                                if (descriptor.changeWriter(FULL, UNCERTAIN)) // if became empty - move to UNCERTAIN and wake writers
                                    descriptor.scheduleWriters();
                            }
                            break;
                        case READY:
                            break;
                    }
                    logf("Awaits %x", cast(void*)descriptor.writeWaiters);
                }
            }
        }
    }
}
