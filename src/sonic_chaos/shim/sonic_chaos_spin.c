/* sonic-chaos SPIN -- make a daemon's event loop burn CPU without doing any work.
 *
 * This reproduces the *live-lock* shape, which neither a CPU cap nor a container hog can:
 *
 *   cap  (cpu.max)      the daemon is descheduled. Its loop is intact, every consumer is still
 *                       serviced, just slower. CPU reads LOW.
 *   hog  (spinners)     same, with the contention coming from other processes in the cgroup.
 *   pause (SIGSTOP)     the daemon services nothing. CPU reads ZERO.
 *   spin (this)         the daemon's own thread burns CPU inside one call and barely returns to
 *                       its loop. CPU reads 100% and nothing is serviced.
 *
 * That last row is RouteOrch-livelock and an RFC5549 case: RouteOrch reprocessing a retry set
 * that never shrinks, pegging the one thread orchagent has. Because orchagent dispatches every
 * orch from a single `m_select->select()` loop (orchdaemon.cpp:1276), a stuck handler starves
 * PortOrch, NeighOrch, FdbOrch and CoppOrch too -- which is the part a cap cannot imitate, and
 * the reason a test that asserts "a LAG member change is still processed" passes under a cap
 * and fails under the real bug.
 *
 * How
 * ---
 * swss::Select::select() bottoms out at ::epoll_wait() (sonic-swss-common select.cpp:100), a
 * plain C symbol. We interpose it, and in every 100 ms period burn `percent` ms of it; the rest
 * of the period the daemon runs at full speed. At percent=70 the dispatch thread spends 70% of
 * its time spinning and 30% working, whether it is idle or draining a backlog.
 *
 * The burn is charged to the period, not to the call. It used to be charged to every call,
 * which is only `percent` while each call then waits out its period. A daemon with a backlog
 * never waits -- epoll_wait returns at once -- so it burned back to back: on a lab switch a
 * requested 70 ran at 93%, and test/fakeloop in ready mode read 100%. test/run_spin_tests.sh
 * section 5b now holds the share under load.
 *
 * 1..99 is a share, 100 stalls
 * ----------------------------
 * Below 100 the daemon keeps the rest of every period -- 30 ms of each 100 at 70, 10 ms at 90 --
 * so under load it drains in bursts. That is a slowdown, not a stall. Use it when you want a
 * daemon that is late, not one that is gone. (How much it drains in its share depends on what a
 * dispatch costs: orchagent's are milliseconds, so the gate's own per-call overhead is noise; in
 * fakeloop's sub-microsecond loop it is not, which is why that loop keeps less than its 30%.)
 *
 * At 100 the call never forwards, so the loop does not turn and nothing is serviced at all. The
 * cost is that orchagent only checks gOrchShutdownRequested *after* select returns, so while this
 * is armed it cannot see a shutdown request and supervisord will fall back to SIGKILL. Release
 * does not need that -- the spin re-reads the control file every 250 ms and rejoins the normal
 * path on its own -- so this only bites if someone restarts the daemon without disarming first.
 *
 * Three entry points, because SONiC is not one codebase
 * -----------------------------------------------------
 * The swss C++ daemons (orchagent, vlanmgrd, portsyncd, neighsyncd, fpmsyncd, syncd) all reach
 * ``epoll_wait`` through ``swss::Select``. FRR does not: bgpd and zebra block in ``ppoll``
 * (syscall 271, measured on a lab switch). Hooking only epoll_wait would load cleanly into bgpd and
 * then never fire -- a fault that reports success and does nothing, which is the exact false
 * negative this lane exists to catch. So all three of epoll_wait, poll and ppoll are interposed
 * and share one gate.
 *
 * Main thread only
 * ----------------
 * Gated on gettid() == getpid(). orchagent has other threads that reach epoll_wait, and spinning
 * one of those would produce a different fault wearing this one's name.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "hs_json.h"

#define HS_CONTROL_DEFAULT "/sonic-chaos/spin_control.json"
#define HS_STATS_DEFAULT   "/sonic-chaos/spin_stats.json"
#define HS_PERIOD_MS       100     /* same period cgroup bandwidth control uses, so the two
                                    * lanes' percentages mean the same thing */
#define HS_FLUSH_GAP_MS    250

typedef int (*epoll_wait_fn)(int, struct epoll_event *, int, int);
typedef int (*poll_fn)(struct pollfd *, nfds_t, int);
typedef int (*ppoll_fn)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *);

static epoll_wait_fn g_real;
static poll_fn g_real_poll;
static ppoll_fn g_real_ppoll;
static int  g_percent;            /* 0 = disarmed */
static long g_seq;
static long g_control_mtime;
static long g_control_mtime_ns;
static long g_control_size = -1;
static long g_cycles;
static long g_spun_ms;
static long g_last_flush_ms;
/* The current HS_PERIOD_MS window, and how much of it has already been burned. Charging the
 * burn to the period instead of to the call is what makes `percent` a CPU share: see spin_gate. */
static long g_period_start_ms;
static long g_period_spun_ms;
static pid_t g_main_tid;

/* No openlog(): that would rewrite the host program's syslog identity, and anyone debugging
 * this is looking under orchagent's. */
#define hs_log(fmt, ...)  syslog(LOG_NOTICE,  "sonic-chaos-spin: " fmt, ##__VA_ARGS__)
#define hs_warn(fmt, ...) syslog(LOG_WARNING, "sonic-chaos-spin: " fmt, ##__VA_ARGS__)

static const char *control_path(void)
{
    const char *env = getenv("SONIC_CHAOS_SPIN_CONTROL");
    return (env != NULL && *env != '\0') ? env : HS_CONTROL_DEFAULT;
}

static const char *stats_path(void)
{
    const char *env = getenv("SONIC_CHAOS_SPIN_STATS");
    return (env != NULL && *env != '\0') ? env : HS_STATS_DEFAULT;
}

static long now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int is_main_thread(void)
{
    if (g_main_tid == 0) {
        g_main_tid = getpid();
    }
    return (pid_t)syscall(SYS_gettid) == g_main_tid;
}

/* {"seq":N,"percent":P} -- anything else disarms rather than guessing. */
static void reload(const char *path)
{
    char buf[512];
    char key[32];
    hs_json_t j;
    int fd, first = 1;
    long percent = 0, seq = 0;
    ssize_t got;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return;
    }
    got = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (got <= 0) {
        return;
    }
    buf[got] = '\0';

    hs_json_init(&j, buf, (size_t)got);
    if (hs_json_expect(&j, '{') != 0) {
        hs_warn("control file %s is not an object, disarmed", path);
        g_percent = 0;
        return;
    }
    while (hs_json_member(&j, &first, key, sizeof key) == 1) {
        if (strcmp(key, "percent") == 0) {
            hs_json_int(&j, &percent);
        } else if (strcmp(key, "seq") == 0) {
            hs_json_int(&j, &seq);
        } else {
            hs_json_skip_value(&j);
        }
    }
    if (j.err) {
        hs_warn("control file %s did not parse, disarmed", path);
        g_percent = 0;
        return;
    }
    if (percent < 0) {
        percent = 0;
    }
    if (percent > 100) {
        percent = 100;
    }
    g_percent = (int)percent;
    g_seq = seq;
    hs_log("control seq %ld applied: main thread held at %d%% from %s", seq, g_percent, path);
}

static void check_control(void)
{
    const char *path = control_path();
    struct stat st;

    if (stat(path, &st) != 0) {
        if (g_control_size != -1) {
            g_control_size = -1;
            g_control_mtime = 0;
            g_percent = 0;
            hs_log("control file %s removed, disarmed", path);
        }
    } else if ((long)st.st_mtime != g_control_mtime ||
               (long)st.st_mtim.tv_nsec != g_control_mtime_ns ||
               (long)st.st_size != g_control_size) {
        /* Nanoseconds matter: two rewrites in the same second that happen to be the same length
         * would otherwise look unchanged, and the second fault would never arm. */
        g_control_mtime = (long)st.st_mtime;
        g_control_mtime_ns = (long)st.st_mtim.tv_nsec;
        g_control_size = (long)st.st_size;
        reload(path);
    }
}

static void write_stats(void)
{
    char path[512];
    char tmp[560];
    FILE *fh;

    snprintf(path, sizeof path, "%s", stats_path());
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    fh = fopen(tmp, "w");
    if (fh == NULL) {
        return;
    }
    fprintf(fh, "{\"seq\":%ld,\"percent\":%d,\"cycles\":%ld,\"spun_ms\":%ld,"
                "\"pid\":%ld,\"main_tid\":%ld,\"hooked\":true}\n",
            g_seq, g_percent, g_cycles, g_spun_ms, (long)getpid(), (long)g_main_tid);
    fclose(fh);
    rename(tmp, path);
}

/* Burn `ms` of CPU. clock_gettime is a vDSO call the compiler cannot elide, so this really
 * spends the time rather than being optimised into a nop. */
static void burn_ms(int ms)
{
    long deadline = now_ms() + ms;

    while (now_ms() < deadline) {
        continue;
    }
}

/* The shared decision. Returns 1 when the caller spun and should clamp its timeout to
 * ``*left_ms``; 0 when the call should simply go through untouched. */
static int spin_gate(int *left_ms)
{
    long now;
    int spin;

    if (!is_main_thread()) {
        return 0;
    }

    now = now_ms();
    if (now - g_last_flush_ms >= HS_FLUSH_GAP_MS) {
        g_last_flush_ms = now;
        check_control();
        /* Publish after counting, not before: the SAI shim shipped with these the other way
         * round and every counter sat one call behind, which on a quiet box looks exactly like
         * a shim that missed the call. */
        write_stats();
    }

    spin = g_percent;
    if (spin <= 0) {
        return 0;
    }

    if (spin >= 100) {
        /* Total stall: never forward, so the loop does not turn and nothing is serviced.
         * Re-check the control file every slice rather than holding blind, so release still
         * lands within HS_FLUSH_GAP_MS without anyone having to signal the process. */
        while (g_percent >= 100) {
            burn_ms(HS_PERIOD_MS);
            g_cycles++;
            g_spun_ms += HS_PERIOD_MS;
            now = now_ms();
            if (now - g_last_flush_ms >= HS_FLUSH_GAP_MS) {
                g_last_flush_ms = now;
                check_control();
                write_stats();
            }
        }
        return 0;   /* disarmed, or lowered, while we were holding: serve this call normally */
    }

    /* Charge the burn to the period, not to the call. This used to burn `spin` ms on every
     * call, which is `spin`% only while each call then waits out the rest of the period. A
     * daemon draining a backlog never waits: epoll_wait returns at once, it does a few ms of
     * work, calls again, and burned another `spin` ms back to back. On a lab switch that turned a
     * requested 70% into 93% (1,738 bursts in a 131 s window with room for 1,310 periods), and
     * fakeloop in ready mode read 100%. Now each period gets at most `spin` ms; a second call
     * inside the same period finds the budget spent and forwards untouched, so the daemon gets
     * the rest of the period to actually work. Idle behaviour is unchanged: one burn, then the
     * wait fills the period. */
    now = now_ms();
    if (g_period_start_ms == 0 || now - g_period_start_ms >= HS_PERIOD_MS) {
        g_period_start_ms = now;
        g_period_spun_ms = 0;
    }
    if (g_period_spun_ms < spin) {
        int budget = spin - (int)g_period_spun_ms;

        burn_ms(budget);
        g_period_spun_ms += budget;
        g_spun_ms += budget;
        g_cycles++;
    }
    /* Never block past the period boundary, or the next period's burn would start late and the
     * share would drift low on an idle daemon. */
    now = now_ms();
    *left_ms = (int)(HS_PERIOD_MS - (now - g_period_start_ms));
    if (*left_ms < 0) {
        *left_ms = 0;
    }
    return 1;
}

__attribute__((visibility("default")))
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    int left = 0;

    if (g_real == NULL) {
        g_real = (epoll_wait_fn)dlsym(RTLD_NEXT, "epoll_wait");
        if (g_real == NULL) {
            hs_warn("cannot resolve the real epoll_wait, passing nothing through");
            return -1;
        }
    }
    if (spin_gate(&left) && (timeout < 0 || timeout > left)) {
        timeout = left;
    }
    return g_real(epfd, events, maxevents, timeout);
}

__attribute__((visibility("default")))
int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int left = 0;

    if (g_real_poll == NULL) {
        g_real_poll = (poll_fn)dlsym(RTLD_NEXT, "poll");
        if (g_real_poll == NULL) {
            hs_warn("cannot resolve the real poll, passing nothing through");
            return -1;
        }
    }
    if (spin_gate(&left) && (timeout < 0 || timeout > left)) {
        timeout = left;
    }
    return g_real_poll(fds, nfds, timeout);
}

/* What FRR actually blocks in: bgpd and zebra sit in ppoll, not poll and not epoll_wait. */
__attribute__((visibility("default")))
int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo, const sigset_t *mask)
{
    struct timespec capped;
    int left = 0;

    if (g_real_ppoll == NULL) {
        g_real_ppoll = (ppoll_fn)dlsym(RTLD_NEXT, "ppoll");
        if (g_real_ppoll == NULL) {
            hs_warn("cannot resolve the real ppoll, passing nothing through");
            return -1;
        }
    }
    if (spin_gate(&left)) {
        long want_ns = (long)left * 1000000L;

        /* NULL means "block forever", which is longer than whatever is left of the period. */
        if (tmo == NULL ||
            (long)tmo->tv_sec * 1000000000L + (long)tmo->tv_nsec > want_ns) {
            capped.tv_sec = left / 1000;
            capped.tv_nsec = (long)(left % 1000) * 1000000L;
            tmo = &capped;
        }
    }
    return g_real_ppoll(fds, nfds, tmo, mask);
}

__attribute__((destructor))
static void flush_on_exit(void)
{
    if (g_cycles > 0) {
        write_stats();
    }
}
