module dfio_win;

version(Windows):

import core.sys.windows.core;
import core.stdc.stdio;
import core.stdc.stdlib;
import std.container.dlist;
import std.exception;
import std.windows.syserror;

//opaque structs
struct UMS_COMPLETION_LIST;
struct UMS_CONTEXT;
struct PROC_THREAD_ATTRIBUTE_LIST;

struct UMS_SCHEDULER_STARTUP_INFO {
    ULONG                      UmsVersion;
    UMS_COMPLETION_LIST*       CompletionList;
    UmsSchedulerProc           SchedulerProc;
    PVOID                      SchedulerParam;
}

struct UMS_CREATE_THREAD_ATTRIBUTES {
  DWORD UmsVersion;
  PVOID UmsContext;
  PVOID UmsCompletionList;
}

enum UMS_SCHEDULER_REASON: uint {
  UmsSchedulerStartup = 0,
  UmsSchedulerThreadBlocked = 1,
  UmsSchedulerThreadYield = 2
}

enum UMS_VERSION =  0x0100;
enum
    PROC_THREAD_ATTRIBUTE_NUMBER = 0x0000FFFF,
    PROC_THREAD_ATTRIBUTE_THREAD = 0x00010000,    // Attribute may be used with thread creation
    PROC_THREAD_ATTRIBUTE_INPUT = 0x00020000,     // Attribute is input only
    PROC_THREAD_ATTRIBUTE_ADDITIVE = 0x00040000;  // Attribute may be "accumulated," e.g. bitmasks, counters, etc.

enum
    ProcThreadAttributeParentProcess                = 0,
    ProcThreadAttributeHandleList                   = 2,
    ProcThreadAttributeGroupAffinity                = 3,
    ProcThreadAttributePreferredNode                = 4,
    ProcThreadAttributeIdealProcessor               = 5,
    ProcThreadAttributeUmsThread                    = 6,
    ProcThreadAttributeMitigationPolicy             = 7;

 enum UMS_THREAD_INFO_CLASS: uint { 
  UmsThreadInvalidInfoClass  = 0,
  UmsThreadUserContext       = 1,
  UmsThreadPriority          = 2,
  UmsThreadAffinity          = 3,
  UmsThreadTeb               = 4,
  UmsThreadIsSuspended       = 5,
  UmsThreadIsTerminated      = 6,
  UmsThreadMaxInfoClass      = 7
}

uint ProcThreadAttributeValue(uint Number, bool Thread, bool Input, bool Additive)
{
    return (Number & PROC_THREAD_ATTRIBUTE_NUMBER) | 
     (Thread != FALSE ? PROC_THREAD_ATTRIBUTE_THREAD : 0) | 
     (Input != FALSE ? PROC_THREAD_ATTRIBUTE_INPUT : 0) | 
     (Additive != FALSE ? PROC_THREAD_ATTRIBUTE_ADDITIVE : 0);
}

enum PROC_THREAD_ATTRIBUTE_UMS_THREAD = ProcThreadAttributeValue(ProcThreadAttributeUmsThread, true, true, false);

extern(Windows) BOOL EnterUmsSchedulingMode(UMS_SCHEDULER_STARTUP_INFO* SchedulerStartupInfo);
extern(Windows) BOOL UmsThreadYield(PVOID SchedulerParam);
extern(Windows) BOOL DequeueUmsCompletionListItems(UMS_COMPLETION_LIST* UmsCompletionList, DWORD WaitTimeOut, UMS_CONTEXT** UmsThreadList);
extern(Windows) UMS_CONTEXT* GetNextUmsListItem(UMS_CONTEXT* UmsContext);
extern(Windows) BOOL ExecuteUmsThread(UMS_CONTEXT* UmsThread);
extern(Windows) BOOL CreateUmsCompletionList(UMS_COMPLETION_LIST** UmsCompletionList);
extern(Windows) BOOL CreateUmsThreadContext(UMS_CONTEXT** lpUmsThread);
extern(Windows) BOOL DeleteUmsThreadContext(UMS_CONTEXT* UmsThread);
extern(Windows) BOOL QueryUmsThreadInformation(
    UMS_CONTEXT*          UmsThread,
    UMS_THREAD_INFO_CLASS UmsThreadInfoClass,
    PVOID                 UmsThreadInformation,
    ULONG                 UmsThreadInformationLength,
    PULONG                ReturnLength
);

extern(Windows) BOOL InitializeProcThreadAttributeList(
  PROC_THREAD_ATTRIBUTE_LIST* lpAttributeList,
  DWORD                        dwAttributeCount,
  DWORD                        dwFlags,
  PSIZE_T                      lpSize
);

extern(Windows) VOID DeleteProcThreadAttributeList(PROC_THREAD_ATTRIBUTE_LIST* lpAttributeList);
extern(Windows) BOOL UpdateProcThreadAttribute(
  PROC_THREAD_ATTRIBUTE_LIST* lpAttributeList,
  DWORD                        dwFlags,
  DWORD_PTR                    Attribute,
  PVOID                        lpValue,
  SIZE_T                       cbSize,
  PVOID                        lpPreviousValue,
  PSIZE_T                      lpReturnSize
);

extern(Windows) HANDLE CreateRemoteThreadEx(
  HANDLE                       hProcess,
  PSECURITY_ATTRIBUTES        lpThreadAttributes,
  SIZE_T                       dwStackSize,
  LPTHREAD_START_ROUTINE       lpStartAddress,
  LPVOID                       lpParameter,
  DWORD                        dwCreationFlags,
  PROC_THREAD_ATTRIBUTE_LIST*  lpAttributeList,
  LPDWORD                      lpThreadId
);

enum STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000;

alias UmsSchedulerProc = extern(Windows) VOID function(UMS_SCHEDULER_REASON Reason, ULONG_PTR ActivationPayload, PVOID SchedulerParam);

struct RingQueue(T)
{
    T* store;
    size_t length;
    size_t fetch, insert, size;
    
    this(size_t capacity)
    {
        store = cast(T*)malloc(T.sizeof * capacity);
        length = capacity;
        size = 0;
    }

    void push(T ctx)
    {
        store[insert++] = ctx;
        if (insert == length) insert = 0;
        size += 1;
    }

    T pop()
    {
        auto ret = store[fetch++];
        if (fetch == length) fetch = 0;
        size -= 1;
        return ret;
    }
    bool empty(){ return size == 0; }
}

UMS_COMPLETION_LIST* completionList;
RingQueue!(UMS_CONTEXT*) queue;
int activeThreads = 0;

void startloop()
{
    wenforce(CreateUmsCompletionList(&completionList), "failed to create UMS completion");
    queue = RingQueue!(UMS_CONTEXT*)(100_000);
}

extern(Windows) uint worker(void* func)
{
    auto dg = cast(void delegate()*)func;
    (*dg)();
    return 0;
}

void spawn(void delegate() func)
{
    import std.conv;
    ubyte[128] buf;
    size_t size = buf.length;
    PROC_THREAD_ATTRIBUTE_LIST* attrList = cast(PROC_THREAD_ATTRIBUTE_LIST*)buf.ptr;
    wenforce(InitializeProcThreadAttributeList(attrList, 1, 0, &size), "failed to initialize proc thread");
    scope(exit) DeleteProcThreadAttributeList(attrList);
    
    UMS_CONTEXT* ctx;
    wenforce(CreateUmsThreadContext(&ctx), "failed to create UMS context");

    UMS_CREATE_THREAD_ATTRIBUTES umsAttrs;
    umsAttrs.UmsCompletionList = completionList;
    umsAttrs.UmsContext = ctx;
    umsAttrs.UmsVersion = UMS_VERSION;
    
    wenforce(UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_UMS_THREAD, &umsAttrs, umsAttrs.sizeof, null, null), "failed to update pric thread");
    HANDLE handle = wenforce(CreateRemoteThreadEx(GetCurrentProcess(), null, 64*1024, &worker, &func,
        0/*STACK_SIZE_PARAM_IS_A_RESERVATION*/, attrList, null), "failed to create thread");
    activeThreads += 1;
}

void runFibers()
{
    UMS_SCHEDULER_STARTUP_INFO info;
    info.UmsVersion = UMS_VERSION;
    info.CompletionList = completionList;
    info.SchedulerProc = &umsScheduler;
    info.SchedulerParam = null;
    wenforce(SetThreadAffinityMask(GetCurrentThread(), 0x1), "failed to set affinity");
    wenforce(EnterUmsSchedulingMode(&info), "failed to enter UMS mode\n");
}

import std.format;

void outputToConsole(const(wchar)[] msg)
{
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    uint size = cast(uint)msg.length;
    WriteConsole(output, msg.ptr, size, &size, null);
}

void logf(T...)(const(wchar)[] fmt, T args)
{
    debug try {
        formattedWrite(&outputToConsole, fmt, args);
    }
    catch (Exception e) {
        outputToConsole("ARGH!"w);
    }
}

extern(Windows) VOID umsScheduler(UMS_SCHEDULER_REASON Reason, ULONG_PTR ActivationPayload, PVOID SchedulerParam)
{
    UMS_CONTEXT* ready;
    logf("-----\nGot scheduled, reason: %d, completion list: %x\n"w, Reason, completionList);
    if(!DequeueUmsCompletionListItems(completionList, 0, &ready)){
        logf("Failed to dequeue ums workers!\n"w);
        return;
    }    
    for (;;)
    {
      while (ready != null)
      {
          logf("Dequeued UMS thread context: %x\n"w, ready);
          queue.push(ready);
          ready = GetNextUmsListItem(ready);
      }
      while(!queue.empty)
      {
        UMS_CONTEXT* ctx = queue.pop;
        logf("Fetched thread context from our queue: %x\n", ctx);
        BOOLEAN terminated;
        uint size;
        if(!QueryUmsThreadInformation(ctx, UMS_THREAD_INFO_CLASS.UmsThreadIsTerminated, &terminated, BOOLEAN.sizeof, &size))
        {
            logf("Query UMS failed: %d\n"w, GetLastError());
            return;
        }
        if (!terminated)
        {
            auto ret = ExecuteUmsThread(ctx);
            if (ret == ERROR_RETRY) // this UMS thread is locked, try it later
            {
                logf("Need retry!\n");
                queue.push(ctx);
            }
            else
            {
                logf("Failed to execute thread: %d\n"w, GetLastError());
                return;
            }
        }
        else
        {
            logf("Terminated: %x\n"w, ctx);
            //TODO: delete context or maybe cache them somewhere?
            DeleteUmsThreadContext(ctx);
            activeThreads -= 1;
        }
      }
      if (activeThreads == 0)
      {
          logf("Shutting down\n"w);
          return;
      }
      if(!DequeueUmsCompletionListItems(completionList, INFINITE, &ready))
      {
           logf("Failed to dequeue UMS workers!\n"w);
           return;
      }
    }
}
