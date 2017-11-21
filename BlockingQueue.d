// https://www.justsoftwaresolutions.co.uk/threading/implementing-a-thread-safe-queue-using-condition-variables.html

import std.container : DList;
import core.sync.condition;
import std.stdio;

// This hides the lock (it can lock-free)
interface WorkQueue(T) {
    shared void push(T item);
    shared T pop(); // blocks if empty
    shared bool tryPop(ref T item); // non-blocking, maybe not the best signature
}

synchronized class BlockingQueue(T) : WorkQueue!T {
    //private shared Mutex m;
    private shared Condition cond;
    private DList!T queue;

    this() {
        //m = new shared Mutex;
        cond = cast(shared)(new Condition(new Mutex));
        //(cast(DList!T)queue) = new DList!T;
    }

    shared Condition getCond() {
        return (cast(Condition)cond);
    }

    //alias cond = (cast(Condition)condition);
    //alias queue = (cast(DList!T)queue);

    shared void push(T item) {
        (cast(DList!T)queue).insertBack(item);
        (cast(Condition)cond).notify();
    }

    shared T pop() {
        while((cast(DList!T)queue).empty())
            (cast(Condition)cond).wait();
        T tmp = (cast(DList!T)queue).front;
        (cast(DList!T)queue).removeFront();
        return tmp;
    }

    shared @property bool empty() {
        return (cast(DList!T)queue).empty();
    }

    shared @property T front() {
        return (cast(DList!T)queue).front;
    }

    shared bool tryPop(ref T item) {
        if ((cast(DList!T)queue).empty)
            return false;

        item = (cast(DList!T)queue).front;
        (cast(DList!T)queue).removeFront();
        return true;
    }

    shared void waitAndPop(ref T item) {
        while ((cast(DList!T)queue).empty())
            (cast(Condition)cond).wait();

        item = (cast(DList!T)queue).front;
        (cast(DList!T)queue).removeFront();
    }

    //unittest
    //{
    //    BlockingQueue!int bq = new BlockingQueue!int;
    //    bq.push(3);
    //    assert(bq.front == 2);

    //}
}

void main()
{
    shared BlockingQueue!int bq = new shared BlockingQueue!int;
    writeln(&bq);
    writeln(bq.getCond());
    //writeln(bq);
    bq.push(3);
    assert(bq.front == 3);

}
