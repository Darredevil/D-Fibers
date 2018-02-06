module dfio_win;

version(Windows):

import core.sys.windows.core;
import core.stdc.stdio;
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
extern(Windows) UMS_CONTEXT* GetNextUmsListItem(UMS_CONTEXT** UmsContext);
extern(Windows) BOOL ExecuteUmsThread(UMS_CONTEXT* UmsThread);
extern(Windows) BOOL CreateUmsCompletionList(UMS_COMPLETION_LIST** UmsCompletionList);
extern(Windows) BOOL CreateUmsThreadContext(UMS_CONTEXT** lpUmsThread);

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

alias UmsSchedulerProc = extern(Windows) VOID function(UMS_SCHEDULER_REASON Reason, ULONG_PTR ActivationPayload, PVOID SchedulerParam);

UMS_COMPLETION_LIST* completionList;

struct SchedulerContext {
    UMS_COMPLETION_LIST* completionList;
    DList!(UMS_CONTEXT*) queue;
    int blocked;
}

HANDLE thread;

void startloop()
{
    wenforce(CreateUmsCompletionList(&completionList), "failed to create UMS completion");
    thread = CreateThread(null, 0, &schedulerEntry, completionList, 0, null); 
    wenforce(SetThreadAffinityMask(thread, 1), "setting affinity failed");
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
    
    UMS_CONTEXT * ctx;
    enforce(CreateUmsThreadContext(&ctx), "failed to create UMS context");

    UMS_CREATE_THREAD_ATTRIBUTES umsAttrs;
    umsAttrs.UmsCompletionList = completionList;
    umsAttrs.UmsContext = ctx;
    umsAttrs.UmsVersion = UMS_VERSION;

    wenforce(UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_UMS_THREAD, &umsAttrs, umsAttrs.sizeof, null, null), "failed to update pric thread");
    CreateRemoteThreadEx(GetCurrentProcess(), null, 64*1024, &worker, &func, 0, attrList, null);
}

void runFibers()
{
    WaitForSingleObject(thread, 1000);
}

extern(Windows) uint schedulerEntry(void* parameter)
{
    SchedulerContext context;
    context.completionList = cast(UMS_COMPLETION_LIST*)parameter;
    context.queue = make!(DList!(UMS_CONTEXT*));
    UMS_SCHEDULER_STARTUP_INFO info;
    info.UmsVersion = UMS_VERSION;
    info.CompletionList = completionList;
    info.SchedulerProc = &umsScheduler;
    info.SchedulerParam = &context;
    
    if (!EnterUmsSchedulingMode(&info))
    {
        printf("Failed to enter UMS mode\n");
    }
    return 0;
}

extern(Windows) VOID umsScheduler(UMS_SCHEDULER_REASON Reason, ULONG_PTR ActivationPayload, PVOID SchedulerParam)
{
    printf("!!!!\n");
    UMS_CONTEXT* ready;
    SchedulerContext* context = cast(SchedulerContext*)SchedulerParam;
    auto completionList = context.completionList;
    auto queue = &context.queue;
    wenforce(DequeueUmsCompletionListItems(completionList, 0, &ready), "failed to dequeue ums workers");
    for (;;)
    {
      while (ready)
      {
          UMS_CONTEXT* ctx = GetNextUmsListItem(&ready);
          queue.insertBack(ctx);
      }
      while(!queue.empty)
      {
        UMS_CONTEXT* ctx = queue.front;
        queue.removeFront();
        auto ret = ExecuteUmsThread(ctx);
        if (ret == ERROR_RETRY) // this UMS thread is locked, try it later
          queue.insertBack(ctx);
        else 
        {
            printf("Failure to execute %d\n", ret);
            assert(0); // should not get there
        }
      }
      wenforce(DequeueUmsCompletionListItems(completionList, INFINITE, &ready), "failed to dequeue ums workers");
    }
}
