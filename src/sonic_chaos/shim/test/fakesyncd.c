/* Stands in for syncd: asks for the API tables the way syncd does, calls through them, and
 * prints what came back as key=value lines for run_tests.sh to check.
 *
 * Run it with and without LD_PRELOAD and the difference is the shim.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int32_t sai_status_t;

extern sai_status_t sai_api_query(int api, void **api_method_table);

extern int fake_route_create_calls;
extern int fake_route_remove_calls;
extern int fake_route_bulk_calls;
extern int fake_vlan_member_remove_calls;
extern int fake_vlan_member_bulk_calls;
extern unsigned long fake_route_create_attr_count;
extern unsigned long fake_vlan_member_remove_oid;
extern unsigned long fake_vlan_bulk_arg6;
extern unsigned long fake_vlan_bulk_arg7;

typedef sai_status_t (*route_create_fn)(const void *, uint32_t, const void *);
typedef sai_status_t (*route_remove_fn)(const void *);
typedef sai_status_t (*route_bulk_fn)(uint32_t, const void *, const uint32_t *, const void **,
                                      int, sai_status_t *);
typedef sai_status_t (*vlan_member_remove_fn)(uint64_t);
typedef sai_status_t (*vlan_member_bulk_fn)(uint64_t, uint32_t, const uint32_t *, const void **,
                                            int, uint64_t *, sai_status_t *);

#define SAI_API_VLAN  4
#define SAI_API_ROUTE 6

static void **route_table;
static void **vlan_table;

static long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int query_tables(void)
{
    if (sai_api_query(SAI_API_ROUTE, (void **)&route_table) != 0 ||
        sai_api_query(SAI_API_VLAN, (void **)&vlan_table) != 0) {
        fprintf(stderr, "fakesyncd: sai_api_query failed\n");
        return -1;
    }
    return 0;
}

/* Pause between repetitions, so each one clears the shim's flush throttle. Without it three
   back-to-back calls produce a single flush and say nothing about per-call accounting. */
static int pace_ms;

/* Each repetition is one route create, one route remove and one vlan member remove. */
static void exercise(int repeats)
{
    int entry = 0;
    int i;

    for (i = 0; i < repeats; i++) {
        sai_status_t rc;

        if (pace_ms > 0) {
            struct timespec gap = {0, (long)pace_ms * 1000 * 1000};
            nanosleep(&gap, NULL);
        }

        rc = ((route_create_fn)route_table[0])(&entry, 3, NULL);
        printf("route_create.%d rc=%d\n", i, rc);

        rc = ((route_remove_fn)route_table[1])(&entry);
        printf("route_remove.%d rc=%d\n", i, rc);

        rc = ((vlan_member_remove_fn)vlan_table[5])(0x1000 + (uint64_t)i);
        printf("vlan_member_remove.%d rc=%d\n", i, rc);
    }
}

static void exercise_bulk(void)
{
    uint64_t oids[2] = {0, 0};
    sai_status_t statuses[2] = {0, 0};
    const uint32_t attr_counts[2] = {1, 1};
    sai_status_t rc;

    rc = ((vlan_member_bulk_fn)vlan_table[8])(0x99, 2, attr_counts, NULL, 0, oids, statuses);
    printf("vlan_member_bulk rc=%d\n", rc);
    printf("vlan_member_bulk.arg6_ok=%d\n", fake_vlan_bulk_arg6 == (unsigned long)(uintptr_t)oids);
    printf("vlan_member_bulk.arg7_ok=%d\n",
           fake_vlan_bulk_arg7 == (unsigned long)(uintptr_t)statuses);

    rc = ((route_bulk_fn)route_table[4])(2, NULL, attr_counts, NULL, 0, statuses);
    printf("route_bulk rc=%d\n", rc);
}

/* What the shim has published so far, read back while this process is still alive -- so the
   destructor has not run and only the in-call flush can have written it. */
static void report_published(void)
{
    const char *path = getenv("SONIC_CHAOS_SAI_STATS");
    char buf[8192] = {0};
    const char *at;
    FILE *fh;

    if (path == NULL || (fh = fopen(path, "r")) == NULL) {
        printf("published.route_create=none\n");
        return;
    }
    if (fread(buf, 1, sizeof(buf) - 1, fh) == 0 && ferror(fh)) {
        fclose(fh);
        printf("published.route_create=unreadable\n");
        return;
    }
    fclose(fh);
    at = strstr(buf, "\"op\":\"create\"");
    if (at != NULL && (at = strstr(at, "\"calls\":")) != NULL) {
        printf("published.route_create=%ld\n", strtol(at + 8, NULL, 10));
    } else {
        printf("published.route_create=absent\n");
    }
}

static void report(long elapsed)
{
    printf("reached.route_create=%d\n", fake_route_create_calls);
    printf("reached.route_remove=%d\n", fake_route_remove_calls);
    printf("reached.route_bulk=%d\n", fake_route_bulk_calls);
    printf("reached.vlan_member_remove=%d\n", fake_vlan_member_remove_calls);
    printf("reached.vlan_member_bulk=%d\n", fake_vlan_member_bulk_calls);
    printf("forwarded.route_create_attr_count=%lu\n", fake_route_create_attr_count);
    printf("forwarded.vlan_member_remove_oid=0x%lx\n", fake_vlan_member_remove_oid);
    printf("elapsed_ms=%ld\n", elapsed);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "basic";
    int repeats = argc > 2 ? atoi(argv[2]) : 1;
    long start;

    if (query_tables() != 0) {
        return 1;
    }
    start = now_ms();

    if (strcmp(mode, "published") == 0) {
        pace_ms = 300;   /* comfortably past the shim's 250 ms flush interval */
    }

    if (strcmp(mode, "bulk") == 0) {
        exercise_bulk();
    } else if (strcmp(mode, "retune") == 0) {
        /* Two rounds with a pause between them: the control file is rewritten in the gap, so
         * the second round must pick up the new rule without a restart. */
        struct timespec pause = {0, 600 * 1000 * 1000};
        exercise(repeats);
        printf("--- retune ---\n");
        nanosleep(&pause, NULL);
        exercise(repeats);
    } else {
        exercise(repeats);
    }

    if (strcmp(mode, "published") == 0) {
        report_published();
    }
    report(now_ms() - start);
    return 0;
}
