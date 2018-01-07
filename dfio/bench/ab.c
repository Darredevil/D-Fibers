// Modified version of G-WAN HTTP wrapper script
// 
// ============================================================================
// G-WAN ApacheBench / Weighttp / HTTPerf wrapper    http://gwan.ch/source/ab.c
// See the benchmark tutorial:       http://gwan.ch/en_apachebench_httperf.html
// ----------------------------------------------------------------------------
// build: gcc -O2 ab.c -o abc -lpthread
//
// usage:
// ./abc [SERVER_NAME] [FROM-TO:NBR[A]+STEPxITERATIONS] <IP[:PORT]/[URI]>
// ./abc .................................... help (missing URL)
// ./abc gwan ............................... help (missing URL)
// ./abc 127.0.0.1:8080/1.html .............. ok   (without CPU/RAM statistics)
// ./abc gwan 127.0.0.1:8080/1.html ......... ok   (with    CPU/RAM statistics)
// ./abc [0-1000+10x3] 127.0.0.1:8080/1.html  ok   (concurrency range)
//
// SERVER_NAME: gwan, nginx, etc. (process name)
// FROM       : concurrency range start
// TO         : concurrency range end
// NBR        : number of requests per weighttp run
// A          : use HTTP Keep-Alives (optional)
// STEP       : concurrencies to skip in in range step
// ITERATIONS : number of repetitions for each weighttp run
// ----------------------------------------------------------------------------
// Dependency: weighttp from http://redmine.lighttpd.net/projects/weighttp/wiki
//
// ab.c will:
//
//  1) invoke Apache Benchmark (IBM), Weighttp (Lighttpd) or HTTPerf (HP) on
//     the [1-1000] concurrency range;
//
//  2) optionally collect CPU / RAM usage for the specified tested server:
//     "./abc gwan /", or "./abc nginx /" (will collect stats for all active
//     server instances, including all their processes and thread workers);
//
//  3) collect results in a CSV file suitable for LibreOffice charting:
//     http://www.documentfoundation.org/download/
//
// Doing 1) and 2) in the same process reduces the overhead of using different
// processes ('htop' and others consume a lot of CPU resources to report the
// RAM / CPU resources usage because they do many things that we don't need):
//
//      Client          Requests per second              CPU
//   -----------  ------------------------------  ----------------  -----
//   Concurrency    min        ave         max      user    kernel   RAM
//   -----------  -------    -------     -------  -------  -------  -----
//   =>   30,     496307,    507626,     522668,    1047,    5943,   2.18
//   ...
//
// Besides controlling CPU/RAM resource usage, specifying the SERVER_NAME also
// lets ab.c check if the server crashed and restarted thread/process workers
// during the test (yes, some do that).
// ----------------------------------------------------------------------------
// If you see this system message:
//
//  "error: connect() failed: Cannot assign requested address (99)"
//
// Then the Linux kernel has exhausted the available TCP port numbers and the
// client tests tool (AB, or weighttp) cannot establish any further connection.
//
// Edit the /etc/sysctl.conf file and add the lines below:
//
//  # avoid TIME_WAIT states on localhost with high-concurrency tests
//  # "error: connect() failed: Cannot assign requested address (99)"
//  net.ipv4.tcp_tw_reuse = 1
//  net.ipv4.tcp_tw_recycle = 1
//
// Then reload this system configuration file with: sysctl /etc/sysctl.conf
// (more kernel tweaks are available below, look for "/etc/sysctl.conf")
// ============================================================================
// ab.c HISTORY: the major number is ab.c's years of existence, started in 2009
//
// 5.10.7 changes: added the free system RAM value for each concurrency step as
//                 some servers delegate the task to the OS kernel, which does
//                 consume system RAM rather than the server application RAM
//                 (of course, this measure is only valid when a test is made
//                 on a system running no other task for the test duration).
//
// 5.10.5 changes: some server workers (either threads or processes) crash and
//                 are restarted using different pids. Some servers also start
//                 thread/process workers 'on-demand' during the test. To still
//                 collect all the CPU/RAM usage statistics of these servers we
//                 now check if the pids list established at startup is still
//                 relevant or needs a refresh. We now display the final count
//                 of threads and processes if it has changed, as well as the
//                 number of relaunches.
//
// 5.9.11 changes: replaced "ps -C" by "ps -A | grep -i" for the altered server
//                 names that escaped ab.c's RAM & CPU resources collection and
//                 reworked the code accordingly.
//
// 2.10.2 changes: prints sum of user/kernel CPU time, signals weighttp errors,
//                 replaced "pidof " with "ps -C" for not found single-process.
//
// 2.9.26 changes: collects and logs all server's workers CPU and memory usage
//                 (use: "ab gwan", or "ab nginx" to enable this feature).
//
// 2.4.20 changes: detect & report open (ab.txt output) file permission errors.
//
// 2.1.20 changes: added support for HTTPerf and Weighttpd as alternatives to
//                 ApacheBench (Weighttpd is multithreaded and more desirable).
//
// v1.0.6 changes: corrected 64-bit platform issues and added support for gzip,
//                 dumped a non-2xx reply on stderr for further investigations.
//
// v1.0.5 changes: added support for non-2xx response codes and trailing stats.
//
// v1.0.4 changes: initial release to test the whole 1-1,000 concurrency range.
//                 ApacheBench only tests a given concurreny level and it does
//                 not fully represent the capabilities of a server, nor it can
//                 avoid the peaks (jitter) than ab.c prevents by using several
//                 rounds for each concurrency level.
// ----------------------------------------------------------------------------
// This program, written by TrustLeap.ch, is left in the public domain.
// ============================================================================

// Select your benchmarking tool below:
//
//#define IBM_APACHEBENCH // single-thread, made better by Zeus' author
//#define HP_HTTPERF      // single-thread, from HP, less practical than AB
#define LIGHTY_WEIGHTTP   // multi-thread, made by the Lighttpd Team
                          // faster than AB (same user interface)
                          //http://redmine.lighttpd.net/projects/weighttp/wiki

#define TRACK_ERRORS      // signals HTTP errors (weighttp only)

#ifdef IBM_APACHEBENCH
# define CLI_NAME "ab"
#elif defined HP_HTTPERF
# define CLI_NAME "httperf"
#elif defined LIGHTY_WEIGHTTP
# define CLI_NAME "weighttp"
#endif

// ----------------------------------------------------------------------------
// Windows:
// ----------------------------------------------------------------------------
// usage: define _WIN32 below and use a C compiler to compile and link a.c

//#ifndef _WIN32
//# define _WIN32
//#endif
#ifdef _WIN32
# pragma comment(lib, "ws2_32.lib")
# define read(sock, buf, len) recv(sock, buf, len, 0)
# define write(sock, buf, len) send(sock, buf, len, 0)
# define close(sock) closesocket(sock)
#endif

//          Unless you target a localhost test, don't use a Windows machine as
//          the client (to run ab) as the performances are really terrible (ab
//          does not use the 'IO completion ports' Windows proprietary APIs and
//          BSD socket calls are much slower under Windows than on Linux).
//
//          G-WAN for Windows upgrades Registry system values to remove some
//          artificial limits (original values are just renamed), you need to
//          reboot after you run G-WAN for the first time to load those values.
//          Rebooting for each test has an effect on Windows (you are faster),
//          like testing after IIS 7.0 was tested (you are even faster), and
//          the Windows Vista 64-bit TCP/IP stack is 10% faster (for all) if
//          ASP.Net is *not* installed.
//
//          Under Windows, run gwan like this:
//
//              C:\gwan> gwan -b
//
//          The -b flag (optional) disables G-WAN's denial of service shield,
//          this gives better raw performances (this is mandatory for tests
//          under Windows because the overhead of the Denial of Service Shield
//          is breaking the benchmarks).
// ----------------------------------------------------------------------------
// Linux:
// ----------------------------------------------------------------------------
// usage: ./gwan -r ab.c  (a new instance of G-WAN will run this C source code)
//
//          Linux Ubuntu 8.1 did not show significant boot-related side-effects
//          but here also I have had to tune the system (BOTH on the server and
//          client sides).                               ^^^^
//
//          The modification below works after a reboot (if an user is logged):
//          sudo gedit /etc/security/limits.conf
//              * soft nofile 200000
//              * hard nofile 200000
//
//          If you are logged as 'root' in a terminal, type (instant effect):
//              ulimit -HSn 200000
//
/*          sudo gedit /etc/sysctl.conf

                # "Performance Scalability of a Multi-Core Web Server", Nov 2007
                # Bryan Veal and Annie Foong, Intel Corporation, Page 4/10
                fs.file-max = 5000000
                net.core.netdev_max_backlog = 400000
                net.core.optmem_max = 10000000
                net.core.rmem_default = 10000000
                net.core.rmem_max = 10000000
                net.core.somaxconn = 100000
                net.core.wmem_default = 10000000
                net.core.wmem_max = 10000000
                net.ipv4.conf.all.rp_filter = 1
                net.ipv4.conf.default.rp_filter = 1
                net.ipv4.tcp_congestion_control = bic
                net.ipv4.tcp_ecn = 0
                net.ipv4.tcp_max syn backlog = 12000
                net.ipv4.tcp_max tw buckets = 2000000
                net.ipv4.tcp_mem = 30000000 30000000 30000000
                net.ipv4.tcp_rmem = 30000000 30000000 30000000
                net.ipv4.tcp_sack = 1
                net.ipv4.tcp_syncookies = 0
                net.ipv4.tcp_timestamps = 1
                net.ipv4.tcp_wmem = 30000000 30000000 30000000

                # optionally, avoid TIME_WAIT states on localhost no-HTTP Keep-Alive tests:
                #    "error: connect() failed: Cannot assign requested address (99)"
                # On Linux, the 2MSL time is hardcoded to 60 seconds in /include/net/tcp.h:
                # #define TCP_TIMEWAIT_LEN (60*HZ)
                # The option below lets you reduce TIME_WAITs by several orders of magnitude
                # but this option is for benchmarks, NOT for production servers (NAT issues)
                net.ipv4.tcp_tw_recycle = 1
*/
//              # other settings found from various sources
//              fs.file-max = 200000
//              net.ipv4.ip_local_port_range = 1024 65535
//              net.ipv4.ip_forward = 0
//              net.ipv4.conf.default.rp_filter = 1
//              net.core.rmem_max = 262143
//              net.core.rmem_default = 262143
//              net.core.netdev_max_backlog = 32768
//              net.core.somaxconn = 2048
//              net.ipv4.tcp_rmem = 4096 131072 262143
//              net.ipv4.tcp_wmem = 4096 131072 262143
//              net.ipv4.tcp_sack = 0
//              net.ipv4.tcp_dsack = 0
//              net.ipv4.tcp_fack = 0
//              net.ipv4.tcp_fin_timeout = 30
//              net.ipv4.tcp_orphan_retries = 0
//              net.ipv4.tcp_keepalive_time = 120
//              net.ipv4.tcp_keepalive_probes = 3
//              net.ipv4.tcp_keepalive_intvl = 10
//              net.ipv4.tcp_retries2 = 15
//              net.ipv4.tcp_retries1 = 3
//              net.ipv4.tcp_synack_retries = 5
//              net.ipv4.tcp_syn_retries = 5
//              net.ipv4.tcp_timestamps = 0
//              net.ipv4.tcp_max_tw_buckets = 32768
//              net.ipv4.tcp_moderate_rcvbuf = 1
//              kernel.sysrq = 0
//              kernel.shmmax = 67108864
//
//          Use 'sudo sysctl -p /etc/sysctl.conf' to update your environment
//          -the command must be typed in each open terminal for the changes
//          to take place (same effect as a reboot).
//
//          As I was not able to make the 'open files limit' persist for G-WAN
//          after a reboot, G-WAN attemps to setup this to an 'optimal' value
//          depending on the amount of RAM available on your system:
//
//             fd_max = (256 * (totalram / 4) < 200000) ? 256 * (total / 4)
//                                                      : 1000000;
//
//          For this to work, you have to run gwan as 'root':
//
//              # ./gwan
//              or
//              $ sudo ./gwan
// ----------------------------------------------------------------------------
//          NB: on a 1 GbE LAN and for the for 100.html test, this test was up
//              to 2x faster when client and server were using Linux 64-bit
//              (instead of Linux 32-bit) but absolute performances are less
//              relevant than relative server performances for me, hence the
//              localhost test).
//
//              Experiments demonstrate that, for a 100-byte static file, IIS
//              and Apache use 90-100% of a 4-Core CPU at high concurrencies
//              while being much slower than G-WAN (which uses "0%" of the CPU
//              on a gigabit LAN).
//
//              A low CPU usage matters because leaving free CPU resources
//              available for other tasks allows G-WAN to:
//
//                - achieve better performances by not starving the system;
//                - make room to generate dynamic contents (C servlets);
//                - make room for a database, proxy, email or virtual server;
//                - save energy (CPUs consume more energy under high loads);
//                - save money (doing 20-200,000x more on each of your server).
//
//              For a small static file such as the 100.html file, if your test
//              on a LAN is slower than on localhost then your environment is
//              the bottleneck (NICs, switch, client CPU, client OS...).
// ============================================================================
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
# include <winsock2.h>
# include <process.h>
# include <windows.h>
typedef unsigned char    u8;
typedef unsigned int     u32;
typedef unsigned __int64 u64;
# define FMTU64 "I64u"
#else
# include <stdint.h>
# include <arpa/inet.h>
# include <ctype.h>
# include <errno.h>
# include <linux/major.h>
# include <netinet/in.h>
# include <netdb.h>
# include <unistd.h>
# include <sys/param.h>
# include <sys/resource.h>
# include <sys/socket.h>
# include <sys/sysctl.h>
# include <sys/time.h>
# include <sys/types.h>
# include <sys/user.h>
# include <sys/utsname.h>

typedef unsigned char       u8;
typedef unsigned int       u32;
typedef   signed long long s64;
typedef unsigned long long u64;
# define FMTU64 "llu"

// ----------------------------------------------------------------------------
// gloabl variables
// ----------------------------------------------------------------------------
volatile int ab_done = 0;      // only main() thread can write it
static float sys_used_ram = 0; // set at startup, once

static u64   pid_ram(u32 pid);
static void sys_ram(s64 *free, s64 *total, s64 *buffers, s64 *cached);

// ----------------------------------------------------------------------------
// making sure we can get all the pids of any given process name:
//
// ps -eL | grep -i 'gwan'
//
// ppid   pid       pid name
// ----  ----    --------------
// 3793  3793 ?  00:00:07 gwan      // process
// 3793  3794 ?  00:07:41 gwan_1    // worker threads
// 3793  3795 ?  00:07:41 gwan_2
// 3793  3796 ?  00:07:41 gwan_3
// ...
// ----------------------------------------------------------------------------
// find all pids of all processes/threads containing 'name'
// (process pids are stored as negative integers to distinguish them from
// thread pids)
// ----------------------------------------------------------------------------
static int pidsof(char *name, int **pids)
{
   if(!name || !*name || !pids) return 0;

   char str[4096];
   sprintf(str, "ps -eL | grep -i '%s'", name);

   FILE *f = popen(str, "r");
   if(!f) return 0;

   *str = 0;
   int len = fread(str, 1, sizeof(str) - 1, f);
   pclose(f);
   if(!len) return 0;

   int *n = *pids = (int*)malloc(sizeof(int) * 512),
        nbr_pids = 0, pid = 0, ppid = 0;
   char *p = str, *pp, *e;
   while(*p)
   {
      while(*p && *p == ' ') p++; // pass blanks
      pp = p;
      while(*p && *p != ' ') p++; // pass parent pid & close string
      *p++ = 0;                    // close string
      ppid = atoi(pp);             // get parent pid
      if(!ppid) break;            // done
      e = p;                       // point to the child pid
      while(*e && *e == ' ') e++; // pass child pid
      while(*e && *e != ' ') e++;
      if(*e == ' ') *e = 0;       // close child pid string

      // if parent pid == child pid then that's a process pid
      // (else that's a thread pid)
      const int pid = atoi(p);
      const int thread = (ppid != pid);
      n[nbr_pids++] = pid * (thread ? 1 : -1);
      //printf("%d] ppid:%d pid:%d\n", nbr_pids -1, ppid, pid);

      p = e + 1;
      while(*p != '\n') p++; // pass the rest of the line
      if(*p) p++;
      //printf("pid[%d]: %d\n", nbr_pids -1, n[nbr_pids -1]);
   }

   *pids = (int*)realloc(*pids, sizeof(int) * nbr_pids);
   return nbr_pids;
}
// ----------------------------------------------------------------------------
// wait 'n' milliseconds
// ----------------------------------------------------------------------------
static void msdelay(u32 milisec)
{
   struct timespec req;
   time_t sec = (u32)(milisec / 1000);
   milisec = milisec - (sec * 1000);
   req.tv_sec = sec;
   req.tv_nsec = milisec * 1000000L;
   while(nanosleep(&req, &req) == -1)
      continue;
}
// ----------------------------------------------------------------------------
// convert a string into an integer
// ----------------------------------------------------------------------------
static u64 atou64(const u8 *s)
{
   u64 v = 0, c;
   while(*s == ' ' || *s == '\t') *s++;
   while((u64)(c = *s++ - '0') < 10u) v = v * 10 + c;
   return v;
}
// ----------------------------------------------------------------------------
static int is_digit(char c)
{
   return ((u8)c - '0') < 10u;
}
// ----------------------------------------------------------------------------
/* convert an integer into a string
// ----------------------------------------------------------------------------
static char *u64toa(u64 v, char *s)
{
   char *p = s;
   int offset = v;
   do p++, offset = offset / 10; while(offset); *p = 0;
   do *p-- = "0123456789"[v % 10], v = v / 10; while(v);
   return s;
}*/
// ----------------------------------------------------------------------------
// "16:14:07" // HH:MM:SS (not thread-safe but we don't care here)
// ----------------------------------------------------------------------------
static char *tm_now(void)
{
   static char str[16] = {0};
   time_t ltime = time(NULL);
   struct tm *tm = localtime(&ltime);

   str[0] = '0' + (tm->tm_hour > 9 ? tm->tm_hour / 10: 0);
   str[1] = '0' + (tm->tm_hour > 9 ? tm->tm_hour % 10: tm->tm_hour);
   str[2] = ':';
   str[3] = '0' + (tm->tm_min > 9 ? tm->tm_min / 10: 0);
   str[4] = '0' + (tm->tm_min > 9 ? tm->tm_min % 10: tm->tm_min);
   str[5] = ':';
   str[6] = '0' + (tm->tm_sec > 9 ? tm->tm_sec / 10: 0);
   str[7] = '0' + (tm->tm_sec > 9 ? tm->tm_sec % 10: tm->tm_sec);
   str[8] = 0;
   return str;
}
// ----------------------------------------------------------------------------
// collect the CPU and RAM resources consumed by the server threads/processes,
// only one time per second, WHILE the client test tool is running (doing this
// AFTER the client did its job would miss the server RAM & CPU resources load)
// ----------------------------------------------------------------------------
// Total server CPU usage = for_all_pids(utime + stime + cutime + cstime)
//
// $ man 5 proc
//
// utime %lu
// Amount of time that this process has been scheduled in user mode, measured
// in clock ticks (divide by sysconf(_SC_CLK_TCK). This includes guest time,
// guest_time (time spent running a virtual CPU, see below), so that
// applications that are not aware of the guest time field do not lose that
// time from their calculations.
//
// stime %lu
// Amount of time that this process has been scheduled in kernel mode,
// measured in clock ticks (divide by sysconf(_SC_CLK_TCK).
//
// cutime %ld
// Amount of time that this process's waited-for children have been scheduled
// in user mode, measured in clock ticks (divide by sysconf(_SC_CLK_TCK).
// (See also times(2).) This includes guest time, cguest_time (time spent
// running a virtual CPU, see below).
//
// cstime %ld
// Amount of time that this process's waited-for children have been scheduled
// in kernel mode, measured in clock ticks (divide by sysconf(_SC_CLK_TCK).
// ----------------------------------------------------------------------------

#ifndef _WIN32
typedef struct
{
   s64 user, kernel;
} icpu_t;
#endif

typedef struct
{
   char   *cpu_ram_buf;
   int     nbr_pids, *pids;
   icpu_t *old_cpu;
} res_args_t;

static void th_resources(void *ptr)
{
   res_args_t *arg = (res_args_t*)ptr;
   char *cpu_ram_buf = arg->cpu_ram_buf;
   int nbr_pids = arg->nbr_pids;
   int *pids = arg->pids;
   icpu_t *old_cpu = arg->old_cpu;
//int count = 0;
   *cpu_ram_buf = 0;
   char str[32], buffer[1024];
   FILE *f;
   msdelay(100); // give time for AB to warm-up the server
   s64 mem = 0, max_mem = 0; // in Bytes
   float max_sys_mem = 0;   // in MBs
   icpu_t cpu = {0, 0};

   // -------------------------------------------------------------------------
   // this first loop is for the time spent by the client tool to work
   // -------------------------------------------------------------------------
   int loop = 80; // 100 + (80 * 10 ms) < 1 second (length of the each ab shot)
   while(loop-- && !ab_done) // loop to track the (varying) RAM usage
   {
      int i = nbr_pids;
      while(i-- && !ab_done) // for each server worker thread / process
      {
         // we have to sum the memory usage of all processes but
         // we don't do that for threads (they don't have a memory
         // usage by their own: the sbrk pointer marking the end of
         // the addressable memory area is process-wide and shared
         // by all threads)
         if(pids[i] > 0) continue; // ignore thread pids

         const int pid = abs(pids[i]);

         // get the memory footprint of all process pids
         sprintf(str, "/proc/%u/stat", pid);
         f = fopen(str, "r"); if(!f) continue;
         const size_t len = fread(buffer, 1, sizeof(buffer) - 1, f);
         fclose(f); if(len <= 0) continue;
         buffer[len] = 0;
   /*    $man proc
      0: pid      %d   process ID
         comm     %s   executable filename, in parentheses
         state    %c   R:run, S:sleep, D:wait, Z:zombie, T:traced, W:paging
         ppid     %d   parent's PID
         pgrp     %d   process' group ID
         session  %d   process' session ID
         tty_nr   %d   tty used by the process
      7: tpgid    %d   parent 'terminal' process' group ID
         flags    %lu  process flags (math bit: 4d, traced bit: 10d)
         minflt   %lu  minor faults that did not load a page from disk
         cminflt  %lu  minor faults that the process + children made
         majflt   %lu  major faults that loaded a page from disk
         cmajflt  %lu  major faults that process + children made
     13: utime    %lu  jiffies that process has spent in user mode
         stime    %lu  jiffies that process has spent in kernel mode
     15: cutime   %ld  jiffies that process + children have spent in user mode
         cstime   %ld  jiffies that process + children have spent in kernel mode
         priority %ld  standard nice value, plus fifteen (never negative)
         nice     %ld  nice value ranges from 19 (nicest) to -19 (not nice)
         threads  %ld   Number of threads in this process (since Linux 2.6)
         intvaltm %ld  jiffies before next SIGALRM sent due to an interval timer
         starttm  %lu  jiffies the process started after system boot
         vsize    %lu  virtual memory size in bytes
     23: rss      %ld  nbr of pages the process has in real memory
     */
         // puts(buffer); exit(0);                  7
         //   pid  cmdln st ppid  pgrp ssid ttynr tpgid  flags  minflt...
         //  ----- -----  - ---- ----- ---- ----- ----- ------- ----
//    0: // "10510 (gwan) S 2861 10383 2861 34818 10383 4202560 3256 64533
         //  0 0
//   13: //  5587 23839 187 15 20 0 7 0 3048896 1764040704
//   23: //  2324 18446744073709551615 1048576 1247500 140736402151728
         //  140510228127776 140510359544675 0 0 1073745920 575214
         //  18446744073709551615 0 0 -1 6

         char *p = buffer;       // the 'pid' field
         p = strchr(p, ')') + 2; // find the 'state' field

         // D: waiting in uninterruptible disk sleep
         // R: running
         // S: sleeping in an interruptible wait
         // T: traced or stopped (on  a  signal)
         // W: paging
         // X: dead
         // Z: zombie
         //printf("pid: %d status: %c\n", abs(pids[i]), *p);

         if(*p >= 'D' && *p <= 'W') // track a [R]unning process
         {
            p += 2; // skip 'state' (we now point to 'ppid')

            // pass spaces to skip unused variables
            int n = 20;
            while(n) if(*p++ == ' ') n--;
            //printf("\nrss: %s\n", p);

            // get the physical memory used by this PROCESS
            mem += atou64((u8*)p) << 12llu; // convert 4096-byte pages into bytes
            //printf("\n[%d] phys:%.8s mem:%llu\n", pid, p, mem);
         }

         // measure the system RAM that the server may use indirectly via
         // kernel syscalls, caches, etc.
         {
            s64 sys_free_ram = 0, sys_total_ram = 0,
                sys_buff_ram = 0, sys_cach_ram = 0;
            sys_ram(&sys_free_ram, &sys_total_ram, &sys_buff_ram, &sys_cach_ram);
            float sys_mem = (sys_total_ram + sys_buff_ram + sys_cach_ram
                            - sys_free_ram)
                            - sys_used_ram;
            if(sys_mem > max_sys_mem) max_sys_mem = sys_mem;
         }

      } // while(i-- && !ab_done) // (pids loop)

      // we only keep the highest value found during this pass
      if(mem > max_mem) max_mem = mem;
      mem = 0;
      msdelay(10); // take another measure after a small pause
   }

   // ------------------------------------------------------------------------
   // now the client test tool has done its job, get the (always increasing)
   // CPU time (in "jiffies")
   // ------------------------------------------------------------------------
   int i = nbr_pids;
   while(i--) // for each server worker process
   {
      // ignore thread pids (utime/stime is per-process and identical for
      // all threads at any given time)
      if(pids[i] > 0) continue;
      const int pid = abs(pids[i]);

      s64 new_cpu_user = 0, new_cpu_system = 0;
      sprintf(str, "/proc/%u/stat", pid);
      f = fopen(str, "r"); if(!f) continue;
      const size_t len = fread(buffer, 1, sizeof(buffer) - 1, f);
      fclose(f); if(len <= 0) continue;
      buffer[len] = 0;

      char *p = strchr(buffer, ')') + 2; // find the 'state' field
      if(*p >= 'D' && *p <= 'W')         // track a [R]unning process
      {
         p += 2; // skip 'state' (we now point to 'ppid')

         // pass spaces to skip unused variables
         int n = 10;
         while(n) if(*p++ == ' ') n--;

         // now we point on 'utime'
         //printf("\nbuf:%s\n\nutime:%s\n\n", buffer, p);

//#define TRACE_CPU_USAGE
#ifdef TRACE_CPU_USAGE
         // the slow way (to trace/debug):
         {
            char comm[256], state;
            int pid, ppid, pgrp, session, tty, tpgid, flags;
            ulong minflt, cminflt, majflt, cmajflt,
                  utime, stime, cutime, cstime, counter, priority,
                  timeout, itrealvalue, starttime, vsize, rss, rlim;

            sscanf(buffer,
                   "%d (%[^)]) %c %d %d %d %d %d "
                   "%u %lu %lu %lu %lu %lu %lu %ld "
                   "%ld %ld %ld %lu %lu %ld %lu %lu "
                   "%lu",
            &pid, comm, &state, &ppid, &pgrp, &session, &tty, &tpgid,

            &flags, &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime,
            &cutime,

            &cstime, &counter, &priority, &timeout, &itrealvalue, &starttime,
            &vsize, &rss,

            &rlim);

            printf(
            "pid         : %d\n" /*
            "comm        : %s\n"
            "state       : %c\n"
            "ppid        : %d\n"
            "pgrp        : %d\n"
            "session     : %d\n"
            "tty         : %d\n"
            "tpgid       : %d\n"
            "flags       : 0x%x\n" // flags %u (%lu before Linux 2.6.22)
            "minflt      : %lu  minor faults\n"
            "cminflt     : %lu  cumulated minor faults\n"
            "majflt      : %lu  minor faults\n"
            "cmajflt     : %lu  cumulated major faults\n" */
            "utime       : %ld  user time jiffies\n"
            "stime       : %ld  system time jiffies\n"
            "cutime      : %ld  cumulated user time jiffies\n"
            "cstime      : %ld  cumulated system time jiffies\n" /*
            "priority    : %ld  -2:low priority to -100:high priority\n"
            "nice        : %ld  19:low priority to -20:high priority\n"
            "nb_threads  : %ld  threads in this process (since Linux 2.6)\n"
            "itrealvalue : %lu  jiffies before SIGALARM\n"
            "starttime   : %lld jiffies (system uptime at start time)\n"
            "vsize       : %lu  bytes in virtual memory\n"
            "rss         : %lu  bytes in real memory\n"
            "rlim        : %lu  bytes (RSS soft limit)\n"
            "startcode   : 0x%lx\n"
            "encode      : 0x%lx\n"
            "startstack  : 0x%lx\n"
            "kstkesp     : 0x%lx stack ESP\n"
            "kstkeip     : 0x%lx stack EIP\n"
            "signal      : 0x%lx pending signals mask\n"
            "blocked     : 0x%lx blocked signals mask\n"
            "sigignore   : 0x%lx ignored signals mask\n"
            "sigcatch    : 0x%lx caught signals mask\n"
            "wchan       : 0x%lx waiting channel address\n"
            "nswap       : %lu Number of pages swapped (not maintained)\n"
            "cnswap      : %lu Cumulative nswap for child processes\n"
            "exit_signal : %d  Signal to be sent to parent when we die\n"
            "processor   : %d  CPU number last executed on\n"
            "rt_priority : %u  (%u Linux 2.5.19+; was %lu)\n"
            "policy      : %u  (%u Linux 2.5.19+; was %lu)\n"
            "IO_ticks    : %llu Aggregated block I/O delays\n"
            "guest_time  : %lu (since Linux 2.6.24)\n"
            "cguest_time : %ld (since Linux 2.6.24)\n"
             */ "\n",
            pid, /* comm, state, ppid, pgrp, session, tty, tpgid, flags,
            minflt, cminflt, majflt, cmajflt, */
            utime, stime, cutime, cstime /* ,
            counter, priority, timeout, itrealvalue, starttime, vsize, rss,
            rlim, startcode, endcode, startstack, kstkesp, kstkeip, signal,
            blocked, sigignore, sigcatch, wchan */);
            int static ccc = 0;
            if(ccc++ > 10) exit(0);
         }
#endif // TRACE_CPU_USAGE

         // get 'utime' and 'stime' (CPU time consumed by process)
         new_cpu_user = atou64((u8*)p); while(*p != ' ') p++; p++;
         new_cpu_system = atou64((u8*)p); while(*p != ' ') p++; p++;

         // add 'cutime' and 'cstime' (CPU time consumed by children)
         new_cpu_user += atou64((u8*)p); while(*p != ' ') p++; p++;
         new_cpu_system += atou64((u8*)p);

         // CPU time slice consumed by all server worker processes
         cpu.user += new_cpu_user - old_cpu[i].user;
         cpu.kernel += new_cpu_system - old_cpu[i].kernel;
/*
         printf("[%d]user old:%7lld + step:%7lld = new:%7lld (total:%7lld)\n",
                i, old_cpu[i].user,
                new_cpu_user - old_cpu[i].user, new_cpu_user,
                cpu.user);
*/
         // save elapsed CPU time for next pass to start from this point
         old_cpu[i].user = new_cpu_user;
         old_cpu[i].kernel = new_cpu_system;

      } // if not zombie
   } // loop pids

   /* format cumulated results (user/kernel proportion)
   const double total = (cpu.user + cpu.kernel) / 100.;
   sprintf(cpu_ram_buf, "%7.02f, %7.02f, %6.02f,", // User, Kernel, MB RAM
            (cpu.user / total),// / nbr_cpu,   // "System load"
            (cpu.kernel / total),// / nbr_cpu, // "System load"
            max_mem / (1024. * 1024.)); */

   // format cumulated results (user/kernel amounts)
   sprintf(cpu_ram_buf, "%7lld, %7lld, %6.02f, %6.01f,", // User, Kernel, RAM
           cpu.user,
           cpu.kernel,
           max_mem / (1024. * 1024.),
           max_sys_mem / (1024. * 1024.)); // difference since test start

   //printf("cpu_ram_buf[%d]:%s\n", (int)strlen(cpu_ram_buf), cpu_ram_buf);
}
// ----------------------------------------------------------------------------
// invoke a command and fetch its output
// ----------------------------------------------------------------------------
static int run_cmd(char *cmd, char *buf, int buflen)
{
   FILE *f = popen(cmd, "r");
   if(!f)
   {
      perror("!run_cmd():");
      return 0;
   }
   *buf = 0;
   int len = fread(buf, 1, buflen, f);
   pclose(f);
   if(!*buf) return 0;
   buf[len] = 0;
   return len;
}
// ------------------------------------
// just a wrapper for the code above
// ------------------------------------
typedef struct
{
   char *cmd, *buf;
   u32 buflen;
} run_cmd_t;

void th_run_cmd(void *ptr)
{
   run_cmd_t *arg = (run_cmd_t*)ptr;
   long len = run_cmd(arg->cmd, arg->buf, arg->buflen);
   pthread_exit((void*)len);
}
// ----------------------------------------------------------------------------
// return the file PATH of process pid
// (needs 'root' privileges for 'root' processes)
// ----------------------------------------------------------------------------
char *pid_path(u32 pid, char *path, int pathlen)
{
   char str[32];
   snprintf(str, sizeof(str) - 1, "/proc/%u/exe", pid);
   const int res = readlink(str, path, pathlen);
   if(res < 0)
   {
      *path = 0;
      //perror("pid_path(): "); // "Permission denied"
   }
   return path;
}
// ----------------------------------------------------------------------------
// return the version of a server (providing it supports "server -v")
// ----------------------------------------------------------------------------
// gwan -v   => "\nG-WAN 2.9.16 (Sep 16 2011 13:11:41)"
// nginx -v  => "nginx: nginx version: nginx/1.0.6"
// ----------------------------------------------------------------------------
char *srv_ver(char *SERVER_NAME, char *version, int verlen)
{
   char cmd[256];
   sprintf(cmd, "%s -v 2>&1", SERVER_NAME);
   *version = 0;
   run_cmd(cmd, version, verlen);
   if(*version)
   {
      char *p = version;

      // pass padding
      while(*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
      version = p;

      // keep only first line of text
      while(*p && *p != '\n') p++; if(*p) *p = 0; // erase last '\n'

      return version;
   }
   return version;
}
// ----------------------------------------------------------------------------
// return the physical RAM used by process 'pid'
// ----------------------------------------------------------------------------
static u64 pid_ram(u32 pid)
{
   char str[32];
   sprintf(str, "/proc/%u/statm", pid);
   FILE *f = fopen(str, "r");
   if(f)
   {
      unsigned long virt = 0, phys = 0;
      int len = fscanf(f, "%lu %lu", &virt, &phys);
      fclose(f);
      return (u64)phys << 12llu; // convert 4096-byte pages into bytes
   }
   return 0;
}
// ----------------------------------------------------------------------------
// return the free/used physical RAM of the System
// ----------------------------------------------------------------------------
// "Buffers": (small) short-lived RAM cache for FS metadata (name, attribute)
// "Cached" : RAM used to cache file blocks for I/O (shrinks under RAM pressure)
//
// cat /proc/meminfo
// MemTotal:        8163924 kB
// MemFree:          314752 kB
// Buffers:           67316 kB
// Cached:          6228024 kB
// ...
static void sys_ram(s64 *free, s64 *total, s64 *buffers, s64 *cached)
{
   int todo = (free != 0) + (total != 0) + (buffers != 0) + (cached != 0);
   FILE *f = fopen("/proc/meminfo", "r");
   if(f)
   {
      char buf[80];
      while(fgets(buf, sizeof(buf), f))
      {
         if(total && !*total && !memcmp(buf, "MemTotal:", 9))
            *total = atol(buf + 10), todo--;
         else
         if(free && !*free && !memcmp(buf, "MemFree:", 8))
            *free = atol(buf + 9), todo--;
         else
         if(buffers && !*buffers && !memcmp(buf, "Buffers:", 8))
            *buffers = atol(buf + 9), todo--;
         else
         if(cached && !*cached && !memcmp(buf, "Cached:", 7))
            *cached = atol(buf + 8), todo--;

         if(!todo) break;
      }
   }
}
// ----------------------------------------------------------------------------
// print the number and type of CPUs and Cores, according to the Linux kernel
// ----------------------------------------------------------------------------
// Note: with AMD CPUs recent Linux releases are reporting only half of the
//       CPU Cores actually present. As a result, G-WAN may look like twice as
//       slow (G-WAN can't reply to more requests per second than sent to it).
//       The workaround used in G-WAN is to run the CPUID instruction to fetch
//       the right number of Cores, also on AMD CPUs (which use different sets
//       of codes and return values than Intel CPUs, so that's different code).
//       This can't reasonably be done for this weighttpd wrapper as the AMD
//       CPUID detection is too long and relies on assembly language.
//       So, here we just check the Ubuntu release number and double the number
//       of CPU Cores when needed (see below the comment in the code).
// ----------------------------------------------------------------------------
static int cpu_type(FILE *fo)
{
   int nbr_cpu = 0, phys_cpu_id = -1, nbr_cores = 0;
   char buffer[1024], model[80] = {0};
   FILE *f = fopen("/proc/cpuinfo", "r");
   if(f)
   {
      while(fgets(buffer, sizeof(buffer), f))
      {
         if(!strncmp(buffer, "processor\t:", 11))
            nbr_cpu++;
         else
         if(!strncmp(buffer, "physical id\t:", 13))
         {
            int id = atoi(buffer + 14);
            if(id > phys_cpu_id)
               phys_cpu_id = id;
         }
         else
         if(!*model && !strncmp(buffer, "model name\t:", 12))
         {
            char *s = buffer + 13, *d = model;
            while(*s)
            {
               *d++ = *s;
               if(*s++ == ' ') // copy string removing consecutive spaces
               {
                  while(*s == ' ') s++;
                  *d++ = *s++;
               }
            }
         }

         if(!nbr_cores && !strncmp(buffer, "cpu cores\t:", 11))
            nbr_cores = atoi(buffer + 12);
      }

      fclose(f);
   }

   // extra step for Linux kernel v3+ reporting half the Cores of AMD CPUs
   char os[1024];
   int len = run_cmd("uname -a", os, sizeof(os));
   if(len)
   {
      if(strstr(model, "AMD") && strstr(os, " 3."))
      {
         fprintf(stdout, "=> Nbr-CPU-Cores x2 for Linux kernel v3+ on AMD platforms\n");
         nbr_cores *= 2;
      }
   }

   if(nbr_cores > 0) nbr_cpu = nbr_cores;

   fprintf(stdout, "CPU: %d x %u-Core CPU(s) %s",
          phys_cpu_id >= 0 ? phys_cpu_id + 1 : 1, nbr_cores, model);
   fprintf(fo, "CPU: %d x %u-Core CPU(s) %s",
           phys_cpu_id >= 0 ? phys_cpu_id + 1 : 1, nbr_cores, model);

   return nbr_cpu << 16 | (nbr_cores ? nbr_cores : 1); // never 0 please!
}
// ----------------------------------------------------------------------------
void dump_srv_topology(char *buf, FILE *fo,
                       char *SERVER_NAME,
                       int *process_pid, int nbr_pids, int *pids)
{
   sprintf(buf, "> Server '%s' process topology:\n"
           "---------------------------------------------\n", SERVER_NAME);
   fputs(buf, fo);
   fprintf(stdout, "%s", buf);
   float mem_sum = 0;
   int i = nbr_pids;
   while(i--)
   {
      const int pid = abs(pids[i]);
      char *p = buf + sprintf(buf, "%3d] pid:%d ", i, pid);
      if(pids[i] < 0) // list RAM for processes
      {
         float mem = (float)pid_ram(pid) / (1024. * 1024.);
         mem_sum += mem;
         sprintf(p, "Process RAM: %.02f MB\n", mem);
         *process_pid = pid;
      }
      else
         strcpy(p, "Thread\n");

      fputs(buf, fo);
      fprintf(stdout, "%s", buf);
   }
   sprintf(buf, "---------------------------------------------\n"
           "Total '%s' server footprint: %.02f MB",
           SERVER_NAME, mem_sum);
   puts(buf);
   fprintf(fo, "%s\n", buf);
}
#endif
// ----------------------------------------------------------------------------
// upgrade 'size' if string contains a 'K', or 'M' (Kilobytes or Megabytes)
// ----------------------------------------------------------------------------
static u32 atou32k(const char *v)
{
   char *p = (char*)v;
   u32 size = 0;
   for(; *p && size < UINT_MAX; p++)
   {
      switch(*p) // here we don't check that 'M' is the first/last character!
      {
         case '0' ... '9': size = (10 * size) + (*p - '0'); break;
         case         'K': size <<=      10; break;
         case         'M': size <<=      20; break;
         case         'k': size  *=    1000; break;
         case         'm': size  *= 1000000; break;
         default         : return size;
      }
   }
   return size;
}
// ============================================================================

static int http_req(char *request, FILE *f);

// avoid unecessary parameter-passing in helper routines
// (IP[] is so large for large Domain names)
char IP[80] = {0}, PORT[8] = ":80"; // default port is 80
char *SERVER_NAME = 0, *URL = 0, *RANGE = 0, KEEP_ALIVES_STR[] = "-k";

// default range and number of requests
int  FROM = 0, TO = 1000, STEP = 10, ITER = 3;
int  NBR_REQUESTS = 100000;

int main(int argc, char *argv[])
{
   int i, j, nbr, max_rps, min_rps, ave_rps;
   char str[256], buf[4070], buffer[256], cpu_ram_buf[256] = {0};
   time_t st = time(NULL);
   u64 tmax_rps = 0, tmin_rps = 0, tave_rps = 0;
   FILE *f;
   puts(" ");

   // -------------------------------------------------------------------------
   // check program arguments
   // -------------------------------------------------------------------------
   if(argc < 2)
   {
help: fprintf(stderr, "usage:\n\n"
      "./abc [SERVER_NAME] [FROM-TO:NBR[A]+STEPxITERATIONS] <IP[:PORT]/URI>"
      "\n\n"
      "  SERVER_NAME: gwan, nginx, etc. (process name)\n"
      "  FROM       : concurrency range start\n"
      "  TO         : concurrency range end\n"
      "  NBR        : number of requests per weighttp run\n"
      "  A          : use HTTP Keep-Alives (optional)\n"
      "  STEP       : concurrencies to skip in in range step\n"
      "  ITERATIONS : number of repetitions for each weighttp run\n\n"
      "examples:\n"
      " ./abc                                  (show this help)\n"
      " ./abc 127.0.0.1/                       (HOST+URI = URL)\n"
      " ./abc 127.0.0.1:8080/100.html          (URL with PORT)\n"
      " ./abc gwan 127.0.0.1/100.html          (SERVER and URL)\n"
      " ./abc gwan [0-1k:100k+10x3] 127.0.0.1/ (SERVER, RANGE, URL)\n\n"
      " (default range is: from 0 to 1000, step:10, 3 iterations,\n"
      "  if a range is speficied, all its parameters must be set,\n"
      "  and the order of the all the arguments must be respected)\n\n");
      exit(1);
   }
   //printf("argc: %d\n", argc);
   if(argc == 2) // check it's a valid URL
   {
      URL = argv[1];
      if(!strchr(URL, '.')) // not a domain name nor an 'IP' address
      {
         fprintf(stderr, "bad URL: %s\n\n", URL);
         goto help;
      }
   }
   // check that we have SERVER_NAME and a valid URL (and an optional range)
   if(argc >= 3)
   {
      if(argc == 3) // either (SERVER_NAME + URL) or (RANGE + URL)
      {
         if(argv[1][0] == '[') RANGE = argv[1], URL = argv[2];
         else            SERVER_NAME = argv[1], URL = argv[2];
      }
      else
      if(argc == 4) // (SERVER_NAME + range + URL)
      {
         SERVER_NAME = argv[1];
         RANGE = argv[2];
         URL = argv[3];
      }
      else
      {
         fputs("* too many arguments\n\n", stderr);
         goto help;
      }
   }
   // parse 'IP' and 'PORT' from 'URL'
   {
      char *p = strchr(URL, ':');
      if(p) // found a port
      {
         strncpy(PORT, p, sizeof(PORT) - 1);
         char *q = strchr(PORT, '/'); if(q) *q = 0;
         *p++ = 0; // close 'IP' string and reach 'URI'
         strncpy(IP, URL, sizeof(IP) - 1);
         while(is_digit(*p)) p++; // pass PORT
         URL = p;
      }
      else // no port specified, use 80 as default port
      {
         p = strchr(URL, '/');
         if(p - URL > sizeof(IP) - 1)
         {
            fprintf(stderr, "\n\nbad host: %s\n\n", p);
            goto help;
         }
         memcpy(IP, URL, p - URL);
         IP[p - URL] = 0;
         URL += p - URL;
      }
   }
   // parse the RANGE, if any
   while(RANGE)
   {
      char *pFROM = 0, *pTO = 0, *pNBR = 0, *pSTEP = 0, *pITER = 0;
      char *p = RANGE, *end = strchr(RANGE, ']');
      pFROM = ++p; while(*p != '-' && p < end) p++; if(p == end) goto bad_range;
      pTO   = ++p; while(*p != ':' && p < end) p++; if(p == end) goto bad_range;
      pNBR  = ++p; while(*p != '+' && p < end) p++; if(p == end) goto bad_range;
      pSTEP = ++p; while(*p != 'x' && p < end) p++; if(p == end) goto bad_range;
      pITER = ++p;

      FROM         = atou32k(pFROM);
      TO           = atou32k(pTO);
      NBR_REQUESTS = atou32k(pNBR);
      STEP         = atou32k(pSTEP);
      ITER         = atou32k(pITER);

      // enable/disable HTTP keep-Alives
      if(pSTEP[-2] != 'A') *KEEP_ALIVES_STR = 0;
      printf("pSTEP[-2]: '%c'\n", pSTEP[-2]);
      break;

bad_range:
      fputs("* bad range\n\n", stderr);
      goto help;
   }
/*
   fprintf(stderr, "IP    : %s\n", IP);
   fprintf(stderr, "PORT  : %s\n", PORT);
   fprintf(stderr, "URL   : %s\n", URL);
   fprintf(stderr, "SERVER: %s\n", SERVER_NAME);
   fprintf(stderr, "RANGE : %s\n", RANGE);
   fprintf(stderr, "FROM  : %u\n", FROM);
   fprintf(stderr, "TO    : %u\n", TO);
   fprintf(stderr, "NBR   : %u\n", NBR_REQUESTS);
   fprintf(stderr, "KEEP-A: %u\n", *KEEP_ALIVES_STR != 0);
   fprintf(stderr, "STEP  : %u\n", STEP);
   fprintf(stderr, "ITER  : %u\n", ITER);
   fprintf(stderr, "\n");
   exit(0); */

   // -------------------------------------------------------------------------
   // open an output file which name is built from the SERVER_NAME and the URL
   // -------------------------------------------------------------------------
   FILE *fo;
   {
      char cleanURL[256], *q = cleanURL, *p = URL + 1,
           *e = p + MIN(sizeof(cleanURL) - 1, strlen(p));
      while(p < e)
      {
         const u8 c = *p++;
         switch(c) // "A-Za-z0-9-._~:/?#[]@!$&'()*+,;=%"
         {
#ifdef _WIN32
            case '\\': // filter what breaks Windows fs
            case ':':
            case '*':
            case '?':
            case '\"':
            case '<':
            case '>':
            case '|': *q++ = '_'; break;
#else
            case '/': *q++ = '!'; break; // filter what breaks Unix fs
#endif
            default : *q++ = c; break;
         }
      }
      *q = 0;

      char filename[256]; // keep filenames readable...
      snprintf(filename, sizeof(filename) -1, "%s_%s%s.csv",
               SERVER_NAME ? SERVER_NAME : "x", cleanURL, RANGE);
      fo = fopen(filename, "w+b");
   }
   if(!fo)
   {
      perror("can't open output file"); // "Permission denied"
      return 1;
   }

   {
      const char fmt[] =
            "=============================================================="
            "=================\n"
            "G-WAN ApacheBench / Weighttp / HTTPerf wrapper       "
            "http://gwan.ch/source/ab.c\n"
            "--------------------------------------------------------------"
            "-----------------\nNow: %s";
      time_t tm; time(&tm);
      struct tm *t = localtime(&tm);
      fprintf(fo, fmt, asctime(t));
      fprintf(stdout, fmt, asctime(t));
   }

   // -------------------------------------------------------------------------
   // find CPU topology, RAM, OS release, etc.
   // -------------------------------------------------------------------------
#ifndef _WIN32
   int nbr_cpu = cpu_type(fo), nbr_cores = nbr_cpu & 0x0000ffff;
   nbr_cpu >>= 16;
   {
      s64 sys_free_ram = 0, sys_total_ram = 0,
          sys_buff_ram = 0, sys_cach_ram = 0;
      sys_ram(&sys_free_ram, &sys_total_ram, &sys_buff_ram, &sys_cach_ram);
      if(sys_free_ram && sys_total_ram)
      {
         // keep it in Bytes here
         sys_used_ram = sys_total_ram + sys_buff_ram + sys_cach_ram
                      - sys_free_ram;

         sprintf(buf, "RAM: %.02f/%.02f (Free/Total, in GB)\n",
                 sys_free_ram / (1024 * 1024.), sys_total_ram / (1024 * 1024.));
         fputs(buf, fo);
         fprintf(stdout, "%s", buf);
      }
   }
   {
      char name[256] = {0};
      f = fopen("/etc/issue", "r");
      if(f)
      {
         int len = fread(name, 1, sizeof(name) - 1, f);
         if(len > 0)
         {
            name[len] = 0; // just in case
            char *p = name;
            while(*p && !iscntrl(*p)) p++; *p = 0;
         }
         fclose(f);
      }
      struct utsname u; uname(&u);
      sprintf(buf, "OS : %s %s v%s %s\n     %s\n",
              u.sysname, u.machine, u.version, u.release, name);
      fprintf(fo, "%s", buf);
      fprintf(stdout, "%s", buf);
   }
   {
      const char fmt[] = "abc: max open sockets: %ld\n\n";
      const long fds = sysconf(_SC_OPEN_MAX);
      fprintf(fo, fmt, fds);
      fprintf(stdout, fmt, fds);
   }

   // -------------------------------------------------------------------------
   // servers like Nginx implement workers with processes (others, like G-WAN
   // use threads), so we have to find all the possible process/thread mixes
   // -------------------------------------------------------------------------
   icpu_t *old_cpu = 0, *beg_cpu = 0;
   int nbr_pids = 0, nbr_srv_launches = 1;
   int *pids = 0, process_pid = 0;

   if(SERVER_NAME) // any server process name provided on command line?
   {
      nbr_pids = pidsof(SERVER_NAME, &pids);
      if(!nbr_pids)
      {
         fprintf(stderr, "\nCan't find any process containing '%s'\n"
                 "(Make sure the '%s' server is started)\n\n",
                 SERVER_NAME, SERVER_NAME);
         exit(1);
      }

      old_cpu = (icpu_t*)calloc(nbr_pids, sizeof(icpu_t)),
      beg_cpu = (icpu_t*)calloc(nbr_pids, sizeof(icpu_t));

      dump_srv_topology(buf, fo, SERVER_NAME, &process_pid, nbr_pids, pids);

      // try to get the server version ('root' privileges are required for
      // web servers run under the 'root' account)
      char srv_path[512];
      pid_path(process_pid, srv_path, sizeof(srv_path));
      if(srv_path && *srv_path)
      {
         fprintf(stdout, "%s\n", srv_path);
         fprintf(fo, "%s\n", srv_path);
         char version[1024];
         char *v = srv_ver(srv_path, version, sizeof(version));
         if(v && *v)
         {
            fprintf(stdout, "%s\n", v);
            fprintf(fo, "%s\n", v);
         }
      }

      // get the start count of CPU jiffies for this server
      res_args_t res_args = {cpu_ram_buf, nbr_pids, pids, beg_cpu};
      th_resources(&res_args);
   }

   // -------------------------------------------------------------------------
   // log the test configuration
   // -------------------------------------------------------------------------
   {
      char str[4096];
      snprintf(str, sizeof(str),
               "\n" CLI_NAME " -n %u -c [%u-%u step:%d rounds:%u] "

#ifdef IBM_APACHEBENCH
               "-S -d "
#endif
#ifdef LIGHTY_WEIGHTTP
               "-t %u "
#endif
               "%s "
               "\"http://%s%s%s\"\n\n",
               NBR_REQUESTS,
               FROM, TO, STEP, ITER,
#ifdef LIGHTY_WEIGHTTP
               nbr_cores,
#endif
               KEEP_ALIVES_STR, IP, PORT, URL);

#endif
      fputs(str, fo);
      fputs(str, stdout);

   }

   // -------------------------------------------------------------------------
   // check that a server is listening on the provided IP:PORT
   // -------------------------------------------------------------------------
   int ret = http_req(URL, fo);
   if(ret < 0)
   {
      fprintf(stderr, "\n * Can't find a server listening on '%s%s'\n"
              "   (Make sure a server is listening there)\n\n",
              IP, PORT);
      exit(2);
   }
   else // some servers are really slow for 404, so it may make sense to
   if(ret == 404) // benchmark this - just make sure that's your intent...
   {
      fprintf(stderr, "\n * Warning: the resource '%s' is not found (404)\n"
              "   (Make sure you want to test 404 replies)\n\n",
              URL);
      sleep(3); // let users read the warning before text is scrolling...
   }
   fprintf(stdout, "\n");
   fprintf(fo, "\n");

   // -------------------------------------------------------------------------
   // test header
   // -------------------------------------------------------------------------
   {
      const char head1[] =
      " Number        Requests per second            CPU               RAM\n"
      "   of     ----------------------------  ----------------  --------------\n"
      "Clients      min       ave       max      user    kernel  SRV MB  SYS MB    Time\n"
      "--------  --------  --------  --------  -------  -------  ------  ------  --------\n";
      const char head2[] =
      " Number        Requests per second\n"
      "   of     ----------------------------\n"
      "Clients      min       ave       max         Time\n"
      "--------  --------  --------  --------  --------------\n";
      const char *head = SERVER_NAME && nbr_pids ? head1 : head2;
      printf("%s", head); // avoid (a) CRLF, (b) GCC warning
      fputs(head, fo);
      fflush(stdout);
   }

   // -------------------------------------------------------------------------
   // prepare the client command line
   // -------------------------------------------------------------------------
   for(i = FROM; i <= TO; i += STEP)
   {
#ifdef IBM_APACHEBENCH
      // ApacheBench makes it straight for you since you can directly tell
      // the 'concurrency' and 'duration' you wish:
      sprintf(str, "ab -n %u -c %d -S -d -t 1 %s "
                   "-H \"Accept-Encoding: gzip\" " // HTTP compression
                   "\"http://%s%s%s\""
#ifdef _WIN32
                   " > ab.txt"
#endif
                   , NBR_REQUESTS, i ? i : 1, KEEP_ALIVES_STR, IP, PORT, URL);

#elif defined HP_HTTPERF
      // HTTPerf does not let you specify the 'concurrency'rate:
      //
      //    rate    : number of TCP  connections per second
      //    num-con : number of TCP  connections
      //    num-call: number of HTTP requests
      //
      // If we want 100,000 HTTP requests, we have to calculate how many
      // '--num-conn' and '--num-call' to specify for a given '--rate':
      //
      //   nbr_req = rate * num-call
      //
      //   'num-conn' makes it last longer, but to get any given 'rate'
      //   'num-conn' must always be >= to 'rate'
      //
      // HTTPerf creates new connections grogressively and only collects
      // statistics after 5 seconds (to let servers 'warm-up' before they
      // are tested). This is NOT reflecting real-life situations where
      // clients send requests on short but intense bursts.
      //
      // Also, HTTPerf's looooong shots make the TIME_WAIT state become a
      // problem if you do any serious concurrency test.
      //
      // Finally, HTTPerf is unable to test client concurrency: if 'rate'
      // is 1 but num-conn is 2 and num-call is 100,000 then you are more
      // than likely to end with concurrent connections because not all
      // requests are processed when the second connection is launched.
      //
      // If you use a smaller num-call value then you are testing the TCP
      // /IP stack rather than the user-mode code of the server.
      //
      // As a result, HTTPerf can only be reliably used without Keep-Alives
      // (with num-call=1)
      //

      sprintf(str, "httperf --server=%s --port=%s "
               "--rate=%d "
#ifdef KEEP_ALIVES
               "--num-conns=%u --num-calls 100000 " // KEEP-ALIVES
#else
               "--num-conns=%u --num-calls 1 " // NO Keep_Alives
#endif
               "--timeout 5 --hog --uri=\"%s\""
#ifdef _WIN32
               " > ab.txt"
#endif
               , IP, PORT, i ? i : 1, i ? i : 1, URL);

#elif defined LIGHTY_WEIGHTTP
      sprintf(str, "weighttp -n %u -c %d -t %u %s "
                   "-H \"Accept-Encoding: gzip\" " // HTTP compression
                   "\"http://%s%s%s\""
                   // Weighttp rejects concurrency inferior to thread count:
                   , NBR_REQUESTS, i > nbr_cores ? i : nbr_cores, nbr_cores,
                   KEEP_ALIVES_STR, IP, PORT, URL);
#endif

      // ----------------------------------------------------------------------
      // test loop, running the client tool 'n' times
      // ----------------------------------------------------------------------
      for(max_rps = 0, ave_rps = 0, min_rps = 0xffff0, j = 0; j < ITER; j++)
      {
#ifdef _WIN32
         // Windows needs to take its breath after system() calls (this is not
         // giving any advantage to Windows as all the tests have shown that
         // this OS platform is -by far- the slowest and less scalable of all)
         system(str);
         Sleep(4000);
         // get the information we need from res.txt
         if(!(f = fopen("ab.txt", "rb")))
         {
            fprintf(stdout, "Can't open ab.txt output\n");
            return 1;
         }
         //memset(buf, 0, sizeof(buf) - 1);
         *buf = 0;
         nbr = fread(buf, 1, sizeof(buf) - 1, f);
         if(nbr <= 0)
         {
            fprintf(stdout, "Can't read ab.txt output\n");
            return 1;
         }
         fclose(f);
#else
         // some server workers crash (and are restarted using a different pid)
         // or some servers start thread/process workers 'on-demand' during the
         // test so we have to check if the list of pids we established first
         // is still relevant
         if(SERVER_NAME) // if we were instructed to collect RAM/CPU usage
         {
            int *_pids = 0, process_pid = 0;
            int _nbr_pids = pidsof(SERVER_NAME, &_pids);
            if(!_nbr_pids)
            {
               if(_pids) free(_pids);
               if(pids) free(pids);
               pids = 0; nbr_pids = 0;
               if(old_cpu) free(old_cpu); old_cpu = 0;
               if(beg_cpu) free(beg_cpu); beg_cpu = 0;
               nbr_srv_launches++;
            }
            else
            if(nbr_pids != _nbr_pids
            || memcmp(_pids, pids, _nbr_pids * sizeof(int)))
            {
               // replace the old list by the new list
               // (here we could do better and compare the 2 lists pid by pid
               //  to inherit from previously relevant statistics for a given
               //  pid - that's left as an exercise for the reader...)
               if(pids) free(pids);
               pids = _pids; nbr_pids = _nbr_pids;
               if(old_cpu) free(old_cpu);
               if(beg_cpu) free(beg_cpu);
               old_cpu = (icpu_t*)calloc(nbr_pids, sizeof(icpu_t)),
               beg_cpu = (icpu_t*)calloc(nbr_pids, sizeof(icpu_t));
               nbr_srv_launches++;
            }
         }

         // MUST be done in parallel to 'ab' because otherwise we check the
         // resources consumed by the server AFTER the 'ab' test is done
         if(nbr_pids)
         {
            ab_done = 0;
            run_cmd_t
                     cmd_args = {.cmd = str, .buf = buf, .buflen = sizeof(buf)};
            pthread_t th_ab;
            pthread_create(&th_ab, NULL, th_run_cmd, (void*)&cmd_args);

            res_args_t res_args = {cpu_ram_buf, nbr_pids, pids, old_cpu};
            pthread_t th_res;
            pthread_create(&th_res, NULL, th_resources, (void*)&res_args);

            void *ret_code;
            pthread_join(th_ab, (void**)&ret_code);
            nbr = (long)ret_code;
            ab_done = 1; // one writer, several readers

            pthread_join(th_res, NULL);
         }
         else
            nbr = run_cmd(str, buf, sizeof(buf));
#endif
         if(nbr > 0 && nbr < sizeof(buf))
            *(buf + nbr) = 0;
         nbr = 0;
         if(*buf)
         {
            // IIS 7.0 quickly stops serving loans and sends error 503 (Service
            // unavailable) at a relatively high rate. If we did not detect it
            // this would be interpreted as a 'boost' in performance while, in
            // fact, IIS is dying. Soon, IIS would really die and we would have
            // to reboot the host: a complete IIS stop/restart has no effect).

            // Other issues to catch here are error 30x (redirects) or 404
            // (not found) on badly configured servers that make users report
            // that their application server is fast when this is not the case.
#ifdef IBM_APACHEBENCH
            char *p = strstr(buf, "Non-2xx responses:");
            if(p) // "Non-2xx responses:      50130"
            {
               char *n;
               p += sizeof("Non-2xx responses:");
               while(*p == ' ' || *p == '\t')
                  p++;
               n = p;
               while(*p >= '0' && *p <= '9')
                  p++;
               *p = 0;
               nbr = atoi(n);
               if(nbr)
               {
                  fprintf(stdout, "* Non-2xx responses:%d\n", nbr);
                  fprintf(fo, "* Non-2xx responses:%d\n", nbr);

                  // dump the server reply on stderr for examination
                  http_req(URL, fo);
                  goto end;
               }
            }

            p = strstr(buf, "Requests per second:");
            if(p) // "Requests per second:    16270.00 [#/sec] (mean)"
            {
               char *n;
               p += sizeof("Requests per second:");
               while(*p == ' ' || *p == '\t')
                  p++;
               n = p;
               while(*p >= '0' && *p <= '9')
                  p++;
               *p = 0;
               nbr = atoi(n);
            }
            else
               puts("* 'Requests per second' not found!");
#elif defined HP_HTTPERF
            char *p = strstr(buf, "Reply status:");
            if(p) // "Reply status: 1xx=0 2xx=1000000 3xx=0 4xx=0 5xx=0"
            {
               char *n;
               p += sizeof("Reply status: 1xx=") - 1;

               // we are not interested in "1xx" errors

               if(*p == '0') // pass "2xx=" if no errors
               p = strstr(p, "3xx=");
               if(p && p[4] == '0') // pass "3xx="  if no errors
               p = strstr(p, "4xx=");
               if(p && p[4] == '0') // pass "4xx="  if no errors
               p = strstr(p, "5xx=");
               if(p && p[4] == '0') // pass "5xx="  if no errors
               goto no_errors;

               p+=sizeof("5xx=");

               while(*p == ' ' || *p == '\t') p++; n = p;
               while(*p >= '0' && *p <= '9') p++; *p = 0;
               nbr = atoi(n);
               if(nbr)
               {
                  fprintf(stdout, "* Non-2xx responses:%d\n", nbr);
                  fprintf(fo, "* Non-2xx responses:%d\n", nbr);

                  // dump the server reply on stderr for examination
                  http_req(URL, fo);
                  goto end;
               }
            }
no_errors:
            // Reply rate [replies/s]: min 163943.9 avg 166237.2 max 167482.3
            // stddev 1060.4 (12 samples)
            p = strstr(buf, "Reply rate");
            if(p)
            {
               char *n;
               p += sizeof("Reply rate [replies/s]: min");
               while(*p == ' ' || *p == '\t') p++; n = p;
               while(*p >= '0' && *p <= '9') p++; *p++ = 0; p++;
               min_rps=atoi(n);

               while(*p<'0' || *p>'9') p++; // avg
               n=p;
               while(*p >= '0' && *p <= '9') p++; *p++ = 0; p++;
               ave_rps = atoi(n);

               while(*p < '0' || *p > '9') p++; // max
               n=p;
               while(*p >= '0' && *p <= '9') p++; *p++ = 0; p++;
               max_rps = atoi(n);
            }
            else
            puts("* 'Reply rate' not found!");

            // HTTPerf needs so many more requests than AB that it quickly
            // exhausts the [1 - 65,535] port space. There is no obvious
            // solution other than using several HTTPerf workers OR waiting
            /* a bit between each shot to let the system evacuate the bloat:
            if(!strcmp(IP, "127.0.0.1"))
            {
               int nop = 60;
               fprintf(stdout, "waiting:"); fflush(stdout);
               while(nop--)
               {
                  fprintf(stdout, "."); fflush(stdout);
                  sleep(1);
               }
               fprintf(stdout, "\n"); fflush(stdout);
            }*/
            goto round_done;

#elif defined LIGHTY_WEIGHTTP
            char *p = strstr(buf, "microsec,"); // "microsec, 12345 req/s"
            if(p)
            {
               p += sizeof("microsec,");
               nbr = atoi(p);

#ifdef TRACK_ERRORS
               p = strstr(p, "succeeded,"); // "succeeded, 0 failed, 0 errored"
               u32 nbr_errors = 0;
               if(p)
               {
                  p += sizeof("succeeded,");
                  nbr_errors = atoi(p);
               }
               if(nbr_errors)
               {
                  fprintf(stdout, "* failed responses:%d\n", nbr);
                  fprintf(fo, "* failed responses:%d\n", nbr);

                  // dump the server reply on stderr for examination
                  // (might not help: HTTP headers are fine, most of
                  //  the time the body is corrupted/incomplete/etc.)
                  //
                  //http_req(URL, fo);
                  goto end;
               }
#endif
            }
            //goto round_done;
#endif
         } // if(nbr_pids)

         if(max_rps < nbr) max_rps = nbr;
         if(min_rps > nbr) min_rps = nbr;
         ave_rps += nbr;

      } //for(max_rps = 0, ave_rps = 0, min_rps = 0xffff0, j = 0; j < ITER; j++)

      ave_rps /= ITER;
#ifdef HP_HTTPERF
round_done:
#endif
      tmin_rps += min_rps;
      tmax_rps += max_rps;
      tave_rps += ave_rps;

      // ----------------------------------------------------------------------
      // display concurrency step data for convenience and save it on disk
      // ----------------------------------------------------------------------
      nbr = sprintf(buf, "%7d, %8d, %8d, %8d, %s  %s\n",
               i ? i : 1, min_rps,
               ave_rps, max_rps, cpu_ram_buf, tm_now());
      fwrite(buf, 1, nbr, stdout);
      if(fwrite(buf, 1, nbr, fo) != nbr)
      {
         fprintf(stdout, "fwrite(fo) failed");
         return 1;
      }
      fflush(fo); // in case we interrupt the test with Ctrl-C
   } // for(i = FROM; i <= TO; i += STEP)

end: st = time(NULL) - st;

   strcpy(buf, "---------------------------------------------------------"
               "----------------------");
   puts(buf);
   fputs(buf, fo);
   fputs("\n", fo);

   strftime(str, sizeof(str) - 1, "%X", gmtime(&st));
   sprintf(buf, "min:%"FMTU64"   avg:%"FMTU64"   max:%"FMTU64
   " Time:%ld second(s) [%s]", tmin_rps, tave_rps, tmax_rps, st, str);
   puts(buf);
   fputs(buf, fo);
   fputs("\n", fo);

   strcpy(buf, "---------------------------------------------------------"
               "----------------------\n");
   puts(buf);
   fputs(buf, fo);

   if(SERVER_NAME) // any server process name provided on command line?
   {
      // print the total count of CPU jiffies for this server
      u64 user = 0, kernel = 0;
      int i = nbr_pids;
      while(i--)
          user   += (old_cpu[i].user - beg_cpu[i].user),
          kernel += (old_cpu[i].kernel - beg_cpu[i].kernel);

      sprintf(buf, "CPU jiffies:   user:%"FMTU64"   kernel:%"FMTU64
                   "   total:%"FMTU64,
                   user, kernel, user + kernel);
      puts(buf);
      fputs(buf, fo);

      if(nbr_srv_launches > 1)
      {
         // print the number of server process/thread launches
         sprintf(buf, "\n\n'%s' relaunches (threads/processes): %d\n\n"
                      "WARNING: partially reported CPU/RAM statistics!\n",
                      SERVER_NAME, nbr_srv_launches);
         puts(buf);
         fputs(buf, fo);
         // show breakdown again for comparison with first detection
         //dump_srv_topology(buf, fo, SERVER_NAME, &process_pid, nbr_pids, pids);
      }
   }

   fputs(" ", fo);
   puts(" ");
   fclose(fo);
   return 0;
}
// ============================================================================
// A 'quick and (really) dirty' wget (don't use this code in production!)
// ----------------------------------------------------------------------------
// read a CRLF-terminated line of text from the socket
// return the number of bytes read, -1 if error
// ----------------------------------------------------------------------------
static int read_line(int fd, char *buffer, int max)
{
   char *p = buffer;
   while(max--)
   {
      if(read(fd, p, 1) <= 0) break;
      if(*p == '\r') continue;
      if(*p == '\n') break;
      p++;
   }
   *p = 0;
   return p - buffer;
}
// ----------------------------------------------------------------------------
// read 'len' bytes from the socket
// return the number of bytes read, -1 if error
// ----------------------------------------------------------------------------
static int read_len(int fd, char *buffer, int len)
{
   int ret;
   char *p = buffer;
   while(len > 0)
   {
      ret = read(fd, p, len);
      if(ret <= 0) return -1;
      p += ret;
      len -= ret;
   }
   return p - buffer;
}
// ----------------------------------------------------------------------------
static void so_timeout(int fd, u32 milisecs)
{
   int timeout = milisecs;
   setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
   setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
}
// ----------------------------------------------------------------------------
// connect to the server, send the HTTP request and dump the server reply
// return the HTTP status sent by the server, -1 if error
// ----------------------------------------------------------------------------
static int http_req(char *request, FILE *f) // fd: log file
{
   char buf[4096];
   int  s, ret = -1;

#ifdef _WIN32
   WSADATA sa;
   WORD ver = MAKEWORD(2, 2);
   WSAStartup(ver, &sa);
#endif

   int port = atoi(PORT + 1); // don't forget it's ":8080"
   int addr = inet_addr(IP); // convert string into integer address
   do
   {
      if(addr == INADDR_NONE)   // is it a valid HOST address?
      {
         // get the HOST address of the specified host name
         struct hostent phost, *hp;
         char tmp[1024] = {0};
         int err = 0;
         if(gethostbyname_r(IP, &phost, tmp, sizeof(tmp), &hp, &err) == 0
         && hp)
           addr = *((u32*)phost.h_addr_list[0]);
         else
           addr = INADDR_NONE; // failed to resolve hostname
      }

      if(addr == INADDR_NONE)
      {
         // errno's message not very useful: "Resource temporarily unavailable"
         //perror("can't resolve host ");
         break;
      }

      s = socket(AF_INET, SOCK_STREAM, 0);
      if(s < 0) break; // most unlikely

      //printf("connecting to %s%s...\n", IP, PORT);
      struct sockaddr_in host;
      bzero(&host, sizeof(host));
      host.sin_family = AF_INET;
      host.sin_addr.s_addr = addr;
      host.sin_port = htons(port);
      so_timeout(s, 500); // Linux kernel 2.3.41+ required for connect()
      ret = connect(s, (struct sockaddr*)&host, sizeof(host));
      if(ret) // 0:OK
      {
         //perror("can't connect() "); // redundant with our own error
         break;
      }

      int len = sprintf(buf, "GET %s HTTP/1.1\r\n"
                    "Host: %s%s\r\n"
                    "User-Agent: a.c\r\n"
                    "Accept-Encoding: gzip\r\n"
                    "Connection: close\r\n\r\n", request, IP, PORT);

      ret = write(s, buf, len);
      if(ret != len) break; // most unlikely here

      len = read_line(s, buf, sizeof(buf) - 1);
      if(len <= 0) break;
      printf("=> %s\n", buf);
      if(f) fprintf(f, "=> %s\n", buf);

      // don't do that with production code:
      if(sscanf(buf, "HTTP/1.%*d %3d", (int*)&ret) != 1) break;

      if(ret > 0) // ret is the HTTP status, parse the server reply
      {
         for(*buf = 0;;)
         {
            int n = read_line(s, buf, sizeof(buf) - 1);
            if(n <= 0) break;
            buf[n] = 0;
            printf("   %s\n", buf);
            if(f) fprintf(f, "   %s\n", buf);

            char *p = buf;
            for(; *p && *p != ':'; p++) *p = tolower(*p);
            sscanf(buf, "content-length: %d", &len);
         }

         // print beginning of fetched resource (if printable)
         len = (len > (sizeof(buf) - 1)) ? (sizeof(buf) - 1) : len;
         len = read_len(s, buf, len);
         if(len > 0 && isalpha(buf[0]) && isalpha(buf[1]))
         {
            buf[len] = 0;
            printf("=> %.40s...\n", buf);
            if(f) fprintf(f, "=> %.40s...\n", buf);
         }
      }
      break;
   } while(0);

   close(s);
   return ret;
}
// ============================================================================
// End of Source Code
// ============================================================================

