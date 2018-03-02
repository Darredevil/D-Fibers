module BlockingQueue;

import core.internal.spinlock;
import std.container : DList;
import core.sync.condition;
import std.stdio;

// This hides the lock (it can lock-free)
interface WorkQueue(T) {
    shared void push(T item);
    shared T pop(); // blocks if empty
    shared bool tryPop(ref T item); // non-blocking
}

ref T unshared(T)(ref shared T value) {
     return *cast(T*)&value;
}

shared class BlockingQueue(T) : WorkQueue!T {
    private shared Condition cond;
    private shared DList!T queue;

    this() {
        cond = cast(shared)(new Condition(new Mutex));
    }

    void push(T item) {
        cond.unshared.mutex.lock();
        scope(exit) cond.unshared.mutex.unlock();
        queue.unshared.insertBack(item);
        cond.unshared.notify();
    }

    T pop() {
        cond.unshared.mutex.lock();
        scope(exit) cond.unshared.mutex.unlock();
        while(queue.unshared.empty())
            cond.unshared.wait();
        T tmp = queue.unshared.front;
        queue.unshared.removeFront();
        return tmp;
    }

    bool tryPop(ref T item) {
        cond.unshared.mutex.lock();
        scope(exit) cond.unshared.mutex.unlock();
        if (queue.unshared.empty) {
            return false;
        }
        item = queue.unshared.front;
        queue.unshared.removeFront();
        return true;
    }

    @property bool empty() {
        cond.unshared.mutex.lock();
        scope(exit) cond.unshared.mutex.unlock();
        return queue.unshared.empty;
    }
}

unittest
{
    shared BlockingQueue!int bq = new shared BlockingQueue!int;
    assert(bq.empty == true);
    bq.push(3);
    assert(bq.pop == 3);
    bq.push(2);
    bq.push(1);
    bq.push(0);
    bq.push(-5);
    assert(bq.pop == 2);
    int i;
    assert(bq.tryPop(i) == true);
    assert(i == 1);
    while(!bq.empty)
        bq.pop();
    assert(bq.empty == true);
}

unittest
{
    import core.thread;
    shared BlockingQueue!int q = new shared BlockingQueue!int;
    void producer() {
        foreach (v; 0..100) {
            q.push(v);
        }
    }
    void consumer() {
        foreach (v; 0..100) {
            assert(q.pop == v);
        }
    }
    auto prod = new Thread(&producer);
    auto cons = new Thread(&consumer);
    cons.start();
    prod.start();
    prod.join();
    cons.join();
}

shared struct IntrusiveQueue(T) 
if (is(T : Object)) {
    SpinLock lock = SpinLock(SpinLock.Contention.brief);
    T head;
    T tail;

    void push(T item) nothrow {
        lock.lock();
        item.next = null;
        scope(exit) lock.unlock();
        if (tail is null) head = tail = cast(shared)item;
        else {
            tail.next = cast(shared)item;
            tail = cast(shared)item;
        }
    }

    bool tryPop(ref T item) nothrow {
        lock.lock();
        scope(exit) lock.unlock();
        if (!head)
            return false;
        else {
            item = head.unshared;
            head = head.next;
            if (head is null) tail = null;
            return true;
        }
    }
}

class Box(T) {
    Box next;
    T item;
    this(T k) {
        item = k;
    }
}

unittest {
    shared q = IntrusiveQueue!(Box!int)();
    q.push(new Box!int(1));
    q.push(new Box!int(2));
    q.push(new Box!int(3));
    Box!int ret;
    q.tryPop(ret);
    assert(ret.item == 1);
    q.tryPop(ret);
    assert(ret.item == 2);

    q.push(new Box!int(4));
    q.tryPop(ret);
    assert(ret.item == 3);
    q.tryPop(ret);
    assert(ret.item == 4);
    q.push(new Box!int(5));

    q.tryPop(ret);
    assert(ret.item == 5);
    assert(q.tryPop(ret) == false);
}
