// https://www.justsoftwaresolutions.co.uk/threading/implementing-a-thread-safe-queue-using-condition-variables.html

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

synchronized class BlockingQueue(T) : WorkQueue!T {
    private Condition cond;
    private DList!T queue;

    this() {
        cond = cast(shared)(new Condition(new Mutex));
    }

    shared void push(T item) {
        queue.unshared.insertBack(item);
        cond.unshared.notify();
    }

    shared T pop() {
        while(queue.unshared.empty())
            cond.unshared.wait();
        T tmp = queue.unshared.front;
        queue.unshared.removeFront();
        return tmp;
    }

    shared @property bool empty() {
        return queue.unshared.empty();
    }

    shared @property T front() {
        return queue.unshared.front;
    }

    shared bool tryPop(ref T item) {
        if (queue.unshared.empty)
            return false;

        item = queue.unshared.front;
        queue.unshared.removeFront();
        return true;
    }

    shared void waitAndPop(ref T item) {
        while (queue.unshared.empty())
            cond.unshared.wait();

        item = queue.unshared.front;
        queue.unshared.removeFront();
    }

    unittest
    {
        shared BlockingQueue!int bq = new shared BlockingQueue!int;
        assert(bq.empty == true);
        bq.push(3);
        assert(bq.front == 3);
        assert(bq.empty == false);
        bq.push(2);
        bq.push(1);
        bq.push(0);
        bq.push(-5);
        assert(bq.front == 3);
        int i;
        assert(bq.tryPop(i) == true);
        assert(i == 3);
        while(!bq.empty)
            bq.pop();
        assert(bq.empty == true);
    }
}

void main()
{
    shared BlockingQueue!int bq = new shared BlockingQueue!int;
    writeln(&bq);
    writeln(&bq.cond.unshared);
    bq.push(3);
    assert(bq.front == 3);
}
