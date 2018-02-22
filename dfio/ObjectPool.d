module ObjectPool;

import std.container : DList;
import core.sync.mutex;
import core.sys.posix.unistd;
import core.sys.linux.timerfd;
import std.stdio;

ref T unshared(T)(ref shared T value) {
     return *cast(T*)&value;
}

int checked(int value, const char* msg="unknown place") {
    if (value < 0) {
        perror(msg);
        _exit(value);
    }
    return value;
}

interface PoolObject {
    void cleanup();
}

class TimerFD : PoolObject {
    private int timerfd;

    this() {
        timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC).checked;
    }

    int getFD() {
        return timerfd;
    }

    void ms2ts(timespec *ts, ulong ms)
    {
        ts.tv_sec = ms / 1000;
        ts.tv_nsec = (ms % 1000) * 1000000;
    }

    void armTimer(int timeout) {
        timespec ts_timeout;
        ms2ts(&ts_timeout, timeout); //convert miliseconds to timespec
        itimerspec its;
        its.it_value = ts_timeout;
        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 0;
        timerfd_settime(timerfd, 0, &its, null);
    }

    void cleanup() {
        // disarm timer
        itimerspec its;
        its.it_value.tv_sec = 0;
        its.it_value.tv_nsec = 0;
        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 0;
        timerfd_settime(timerfd, 0, &its, null);
        //close(timerfd);
    }
}

shared class ObjectPool(T : PoolObject) {
    private shared Mutex mtx;
    private shared DList!T available;
    private shared DList!T inUse;

    this() {
        mtx = new shared Mutex;
    }

    T getObject() {
        mtx.lock();
        scope(exit) mtx.unlock();
        if (!available.unshared.empty) {
            T tmp = available.unshared.front;
            available.unshared.removeFront();
            return tmp;
        }
        return createPoolObject();
    }

    T createPoolObject() {
        mtx.lock();
        scope(exit) mtx.unlock();
        T obj = new T();
        inUse.unshared.insertBack(obj);
        return obj;
    }

    void releaseObject(T obj) {
        mtx.lock();
        scope(exit) mtx.unlock();
        obj.cleanup();
        available.unshared.insertBack(obj);
        inUse.unshared.linearRemoveElement(obj);
    }
}
