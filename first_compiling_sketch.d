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

//import syscalld: syscall, READ, WRITE;




// This would start User's task on I/O scheduler
void spawn(void function() func);

// run fibers until all of them terminate
void runUntilCompletion();

void main(){
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

// Now the below is LibC shim library
Fiber currentFiber; // this is TLS per user thread


// Queue of ready Fibers, we'd do it per thread but one for now
shared int alive; // count of non-terminated Fibers
//shared Queue!Fiber queue;  // this not a single queue(!)
shared DList!Fiber queue;

Mutex mtx;

// https://syscalls.kernelgrok.com/ --------------------------------------------> x86 syscall table
// http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/ ----------> x64 syscall table

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

ssize_t read(int fd, void *buf, size_t count)
{
    // TODO: assumption - we will set O_NONBLOCK
    //ssize_t resp = core.sys.posix.unistd.read(fd, buf, count);      // -------> maybe https://github.com/kubo39/syscall-d/blob/master/source/syscalld/arch/syscall_x86.d
    ssize_t resp = syscall(3, fd, cast(int) buf, cast(int) count);
    //ssize_t resp = _read(fd, buf, count);
    if (resp < 0) {          // TODO: errno is EWOULDBLOCK, otherwise return resp
         // Error - time to see which one
        add_await(fd, currentFiber, EPOLLIN); // <--- this is USER thread
        // can have > 1 fiber though
        //currentFiber = take(queue); // TODO will address this later
        mtx.lock();
        currentFiber = (cast(DList!Fiber)queue).front;
        (cast(DList!Fiber)queue).removeFront();
        mtx.unlock();
        Fiber.yield();
        return EWOULDBLOCK; // TODO quickfix for now
    }
    else return resp; // the easy way out ;)
}

void runUntilCompletion()
{
    while (alive > 0) { 
        //currentFiber = take(queue); // TODO implement take

        mtx.lock();
        currentFiber = (cast(DList!Fiber)queue).front;
        (cast(DList!Fiber)queue).removeFront();
        mtx.unlock();

        currentFiber.call();
        if (currentFiber.state == Fiber.State.TERM) {
            core.atomic.atomicOp!"-="(alive, 1);
        }
    }
}

void spawn(void function() func) {
    auto f = new Fiber(func);
    mtx.lock();
    (cast(DList!Fiber)queue).insertBack(f);
    mtx.unlock();
}


// I/O scheduler is here ;)

// That should be enough, descriptors[fd] is a state of a descriptor
shared DescriptorState[] descriptors;
shared int event_loop_fd;

// This represents a blocked fiber
struct AwaitingFiber {
    Fiber fiber; // who does it
    int op; // EPOLLIN if reading or EPOLLOUT if writing
}

// represents a state of FD == list of awaiting fibers
struct DescriptorState {
    AwaitingFiber[] waiters;  // can optimize for 1-element case, more on that later
}

void add_await(int fd, Fiber fiber, int op) {
    mtx.lock();
    (cast(DescriptorState[])descriptors)[fd].waiters ~= AwaitingFiber(currentFiber, EPOLLIN); // TODO: locking
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
   
   TODO: epoll is kind nice, and lets us attach data to FD, we'll skip it for now
*/
void event_add_fd(int fd) { // register new FD
    epoll_event event;
    event.events = EPOLLIN | EPOLLOUT; // TODO: most events that make sense to watch for
    event.data.fd = fd;
    epoll_ctl(event_loop_fd, fd, EPOLL_CTL_ADD, &event); // TODO: check for errors 
}

void event_remove_fd(int fd) { // on LibC's close
    epoll_ctl(event_loop_fd, fd, EPOLL_CTL_DEL, null); // TODO: check for errors 
}

void startloop()
{
    event_loop_fd = epoll_create(1000); // just be > 0 on newest kernels, again fail on errors
    eventloop();
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


enum int TIMEOUT = 100, MAX_EVENTS = 100;


int haveUserThreads = 10;

void eventloop()
{
    epoll_event[100] events;
    // so here we spin in a loop, unsurprisingly
    int epollfd = epoll_create1(0);
    while(haveUserThreads) { // to be changed
        // 1. call epoll
        int r = epoll_wait(epollfd, events.ptr, MAX_EVENTS, TIMEOUT);
        if (r < 0) { 
            // TODO handle error
            _exit(r);
        }
        // 2. move waiters ---> queue
        for (int n = 0; n < r; n++) {
            int fd = events[n].data.fd;
            auto w = descriptors[fd].waiters;   // <-- TODO: locking
            //TODO: remove the ones from the waiting list
            foreach(a; w) {
                // 3. the tick is read and write are separate, and then there are TODO: exceptions (errors)
                if ((a.op & events[fd].events) != 0) {
                    //mtx.lock();
                    //Fiber f = a.fiber;
                    //queue.insertBack(f); //something like this? - more or less however flags don't play well
                    (cast(DList!Fiber)queue).insertBack(cast(Fiber)(a.fiber)); //something like this? - more or less however flags don't play well
                    //mtx.unlock();
                }
            }
        }
    }
}
