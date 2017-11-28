// This hides the lock (it can lock-free)
interface WorkQueue(T) {
    shared void push(T item);
    shared T pop(); // blocks if empty
    shared bool tryPop(ref T item); // non-blocking, maybe not the best signature
}


// Concurrency!

// 1.
T item = q.front;
q.pop();

// 2.
if (!q.empty) {
 T item = q.pop();
 ...
}

// https://dlang.org/phobos/core_sync_condition.html

// https://stackoverflow.com/questions/2536692/a-simple-scenario-using-wait-and-notify-in-java
//
synchronized class BlockingQueue(T) : WorkQueue!T {
    shared Condition cond;
    DList!T queue;

    shared void push(T item) {
        queue.insertBack(item);
        cond.notify();
    }

    //...
    shared T pop() {
        /// here you have unique reference to the Q
        while(queue.empty())
            cond.await();
        return queue.removeFront();
    }
}

unittest {

//...

}

//
1. T1 does await
2. T2 notify
3. T1 is unblocked

//
1. T2 notify
2. T1 does await
3. T1 is blocked until next notify


for (;;) {
   // 1. read
   // 2. if would block - switch fiber, continue
    // 2.1 add fiber to await set
    // 2.2 take then next free fiber
    // 2.3 yeild the current fiber
    // 2.4 continue the loop
   // 3. if anything else - return
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


// Have a thread write stuff to a socket, and a fiber to read it and print.
// Fiber folow our scheduler code
// keywords: socketpair, O_NONBLOCKING

