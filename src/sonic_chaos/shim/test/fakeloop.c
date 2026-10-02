/* Stands in for orchagent: an epoll loop on one thread, plus a second thread with its own loop.
 *
 *   fakeloop idle  <seconds>    nothing is ever ready, so epoll_wait blocks -- an idle daemon
 *   fakeloop ready <seconds>    an eventfd is always ready, so it returns at once -- a daemon
 *                               draining a backlog
 *   fakeloop ppoll <seconds>    the same loop on ppoll instead of epoll -- what FRR's bgpd and
 *                               zebra actually block in, so the suite covers that path too
 *
 * Reports per-thread CPU, so the tests can tell "the main thread burns CPU" (idle mode) apart
 * from "the loop stops turning" (ready mode) apart from "the worker thread was left alone".
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

static int g_seconds;
static int g_ready;
static long g_worker_iters;
static double g_worker_cpu_ms;
static long g_main_iters;
static double g_main_cpu_ms, g_wall_ms;
static int g_main_done;
static const char *g_mode = "idle";
static int g_ppoll;

static void report(void)
{
    printf("mode=%s\n", g_mode);
    printf("main_iterations=%ld\n", g_main_iters);
    printf("main_cpu_pct=%d\n", (int)(g_main_cpu_ms * 100.0 / g_wall_ms + 0.5));
    printf("worker_iterations=%ld\n", g_worker_iters);
    printf("worker_cpu_pct=%d\n", (int)(g_worker_cpu_ms * 100.0 / g_wall_ms + 0.5));
    fflush(stdout);
}

static double now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static double thread_cpu_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

/* One epoll loop for `seconds`, returning how many times round it went. `counter`, when given,
 * is published as we go so the watchdog can report it if this loop never comes back. */
static long loop(int ready, int seconds, long *counter)
{
    struct epoll_event ev, out[4];
    int epfd = epoll_create1(0);
    int fd;
    long iters = 0;
    double deadline;

    fd = ready ? eventfd(1, EFD_NONBLOCK) : eventfd(0, EFD_NONBLOCK);
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);

    deadline = now_ms() + seconds * 1000.0;
    while (now_ms() < deadline) {
        if (g_ppoll) {
            struct pollfd pfd;
            struct timespec tmo;

            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            tmo.tv_sec = 1;
            tmo.tv_nsec = 0;
            ppoll(&pfd, 1, &tmo, NULL);
        } else {
            epoll_wait(epfd, out, 4, 1000);
        }
        iters++;
        if (counter != NULL) {
            *counter = iters;
        }
    }
    close(fd);
    close(epfd);
    return iters;
}

static void *worker(void *unused)
{
    double before = thread_cpu_ms();
    int grace;

    (void)unused;
    g_worker_iters = loop(g_ready, g_seconds, NULL);
    g_worker_cpu_ms = thread_cpu_ms() - before;

    /* Watchdog. Under a total stall the main thread never returns from epoll_wait, so it never
     * reaches its own deadline and the process would hang forever. This thread is never gated,
     * so it is the one that can still report and exit. */
    for (grace = 0; grace < 50 && !g_main_done; grace++) {
        struct timespec nap = {0, 100 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    if (!g_main_done) {
        g_main_cpu_ms = g_wall_ms;      /* stalled means spinning, by definition */
        report();
        _exit(0);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    double cpu_before, wall_before;
    pthread_t tid;

    g_mode = argc > 1 ? argv[1] : "idle";
    g_seconds = argc > 2 ? atoi(argv[2]) : 2;
    g_ppoll = strcmp(g_mode, "ppoll") == 0;
    g_ready = strcmp(g_mode, "ready") == 0 || g_ppoll;   /* ppoll mode uses a ready fd too */
    g_wall_ms = g_seconds * 1000.0;      /* the watchdog's denominator if we never come back */

    pthread_create(&tid, NULL, worker, NULL);

    cpu_before = thread_cpu_ms();
    wall_before = now_ms();
    loop(g_ready, g_seconds, &g_main_iters);
    g_main_cpu_ms = thread_cpu_ms() - cpu_before;
    g_wall_ms = now_ms() - wall_before;
    g_main_done = 1;

    pthread_join(tid, NULL);
    report();
    return 0;
}
