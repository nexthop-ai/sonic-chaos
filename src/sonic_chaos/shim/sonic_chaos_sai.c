/* sonic-chaos SAI shim -- delay, fail, or drop SAI calls underneath syncd.
 *
 * WHY AN INTERPOSER AT ALL
 * ------------------------
 * Every other injector in sonic-chaos hits a process or a database. None of them can answer
 * "what does orchagent do when the ASIC says ITEM_NOT_FOUND on this one remove?", which is the
 * shape of stale-member, or "what happens when a route create takes two seconds?", which is every
 * timeout below orchagent. Those answers live under syncd, so that is where we sit.
 *
 * HOW IT ATTACHES
 * ---------------
 * SAI is not reached through named symbols that could simply be overridden. syncd calls
 * sai_api_query(api, &table) once per API at start-up and keeps the returned pointer, then
 * calls through the function pointers inside it forever after. So:
 *
 *   1. LD_PRELOAD puts our sai_api_query ahead of the vendor's.
 *   2. We call the real one (dlsym RTLD_NEXT) and get the vendor's table.
 *   3. We overwrite selected slots of that table with trampolines and remember the originals.
 *   4. Each trampoline consults the control file and then delays / returns a status / drops /
 *      calls the original.
 *
 * Because the patch lands in the table rather than in a control flag, arming and disarming
 * afterwards is just a write to the control file: the shim re-reads it on mtime change and a
 * trampoline with no rule is a direct call through. Only the *first* arming costs a syncd
 * restart, which matters because on real hardware that restart is itself a dataplane event.
 *
 * THE TRAMPOLINE SIGNATURE
 * ------------------------
 * A trampoline cannot know the signature of the function it is standing in for, and there are
 * hundreds. It does not need to: every SAI entry point takes at most eight integer or pointer
 * arguments and returns sai_status_t, with no floats and nothing passed by value. Under the
 * SysV AMD64 ABI a function declared with eight pointer arguments therefore forwards any of
 * them unchanged, and a callee that takes fewer simply ignores the rest. One shape covers the
 * lot. (hs_tags.h is generated from the SAI headers, so the slot numbers are read out of the
 * same declarations syncd itself was built against rather than guessed.)
 *
 * SAFETY
 * ------
 * The shim is wired in through an LD_PRELOAD on syncd's own supervisord entry, so it reaches
 * one program rather than every process in the container. It still does nothing at load time:
 * there is no constructor, all state is statically initialised, and the first work happens
 * inside sai_api_query. That way a stray preload -- a debugging session, a future change to
 * how syncd is launched -- costs a process nothing at all.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* RTLD_NEXT */
#endif

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "hs_json.h"
#include "hs_tags.h"

/* ------------------------------------------------------------------ SAI ABI (no SAI headers)
 *
 * Only the handful of declarations the shim actually needs. Keeping the SAI headers out means
 * the shim builds anywhere with a C compiler, and cannot drift from the vendor library over a
 * detail it never touches.
 */
typedef int32_t sai_status_t;

#define SAI_STATUS_SUCCESS          0
#define SAI_STATUS_NOT_SUPPORTED    (-2)
#define SAI_STATUS_NOT_IMPLEMENTED  (-15)

#define HS_CONTROL_DEFAULT "/sonic-chaos/sai_control.json"
#define HS_STATS_DEFAULT   "/sonic-chaos/sai_stats.json"

#define HS_CONTROL_MAX     (256 * 1024)
#define HS_MAX_ENTRIES     256           /* rules in one control file, wildcards included */
#define HS_RELOAD_GAP_MS   250           /* how often a call may stat() the control file */
#define HS_NAME_MAX        64

/* ------------------------------------------------------------------ state */

typedef struct {
    int  active;
    int  delay_ms;
    int  status;
    int  has_status;
    int  drop;
    long count;        /* 0 = unlimited */
} hs_rule_t;

typedef sai_status_t (*hs_fn_t)(void *, void *, void *, void *, void *, void *, void *, void *);

static void    *g_real[HS_NUM_HOOKS];
static char     g_hooked[HS_NUM_HOOKS];

static pthread_rwlock_t g_rules_lock = PTHREAD_RWLOCK_INITIALIZER;
static hs_rule_t        g_rules[HS_NUM_TAGS][HS_NUM_OPS];
static long             g_remaining[HS_NUM_TAGS][HS_NUM_OPS];
static char             g_logged[HS_NUM_TAGS][HS_NUM_OPS];
static long             g_seq;

/* Object types the control file asked us to patch.
 *
 * We deliberately do NOT patch everything hs_tags.h knows about. That table is generated from
 * the SAI headers in this tree, but the vendor library may have been built against an older
 * SAI whose API structs are shorter -- and syncd would not notice, because it never calls the
 * members added since. Writing a trampoline into a slot past the end of the vendor's struct
 * would corrupt whatever sits after it. Patching only what was asked for keeps us inside the
 * long-settled head of each struct, which is where every object type anyone injects lives.
 *
 * The cost is that arming a new object type needs a syncd restart; injectors/sai.py knows
 * this, compares the hooked set in the stats file against what it needs, and restarts only
 * when it must.
 */
static char g_hook_wanted[HS_NUM_TAGS];

/* Object types this process actually looked at while syncd was querying the APIs. That is
 * the honest answer to "would restarting syncd change anything?": a type considered but
 * not patched (vendor left the slots empty) would not be patched by a restart either. */
static char g_hook_seen[HS_NUM_TAGS];

static unsigned long g_calls[HS_NUM_TAGS][HS_NUM_OPS];
static unsigned long g_matched[HS_NUM_TAGS][HS_NUM_OPS];
static unsigned long g_injected[HS_NUM_TAGS][HS_NUM_OPS];

static pthread_mutex_t g_reload_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_hook_lock = PTHREAD_MUTEX_INITIALIZER;
static long g_last_check_ms;
static long g_control_mtime;
static long g_control_mtime_ns;
static long g_control_size = -1;
static int  g_hook_count;

/* ------------------------------------------------------------------ helpers */

static const char *control_path(void)
{
    const char *env = getenv("SONIC_CHAOS_SAI_CONTROL");
    return (env != NULL && *env != '\0') ? env : HS_CONTROL_DEFAULT;
}

static const char *stats_path(void)
{
    const char *env = getenv("SONIC_CHAOS_SAI_STATS");
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

static void sleep_ms(int ms)
{
    struct timespec req;

    req.tv_sec = ms / 1000;
    req.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&req, &req) != 0) {
        continue;   /* interrupted: finish the remaining time rather than cut the fault short */
    }
}

/* No openlog(): that would rewrite the host program's syslog identity. Without it these land
 * under syncd's own ident, which is where anyone debugging this will look. */
#define hs_log(fmt, ...) syslog(LOG_NOTICE, "sonic-chaos: " fmt, ##__VA_ARGS__)
#define hs_warn(fmt, ...) syslog(LOG_WARNING, "sonic-chaos: " fmt, ##__VA_ARGS__)

static int tag_index(const char *name)
{
    int i;

    for (i = 0; i < HS_NUM_TAGS; i++) {
        if (strcmp(hs_tags[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static int op_index(const char *name)
{
    int i;

    for (i = 0; i < HS_NUM_OPS; i++) {
        if (strcmp(hs_op_names[i], name) == 0) {
            return i;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ control file */

typedef struct {
    int       tag;     /* -1 for the "*" wildcard */
    int       op;      /* -1 for the "*" wildcard */
    hs_rule_t rule;
} hs_entry_t;

/* Read one {"delay_ms":..,"status":..,"drop":..,"count":..} leaf. Unknown keys are skipped so
 * the file can carry fields for humans (status_name) without the shim caring. */
static int parse_rule(hs_json_t *j, hs_rule_t *rule)
{
    char key[HS_NAME_MAX];
    int first = 1;
    int rc;

    memset(rule, 0, sizeof(*rule));
    rule->active = 1;
    if (hs_json_expect(j, '{') != 0) {
        return -1;
    }
    while ((rc = hs_json_member(j, &first, key, sizeof(key))) == 1) {
        long value;
        if (strcmp(key, "delay_ms") == 0) {
            if (hs_json_int(j, &value) != 0) {
                return -1;
            }
            rule->delay_ms = (int)value;
        } else if (strcmp(key, "status") == 0) {
            if (hs_json_peek(j) == 'n') {
                if (hs_json_skip_value(j) != 0) {
                    return -1;
                }
            } else {
                if (hs_json_int(j, &value) != 0) {
                    return -1;
                }
                rule->status = (int)value;
                rule->has_status = 1;
            }
        } else if (strcmp(key, "drop") == 0) {
            if (hs_json_bool(j, &rule->drop) != 0) {
                return -1;
            }
        } else if (strcmp(key, "count") == 0) {
            if (hs_json_int(j, &rule->count) != 0) {
                return -1;
            }
        } else if (hs_json_skip_value(j) != 0) {
            return -1;
        }
    }
    if (rc < 0) {
        return -1;
    }
    if (rule->delay_ms < 0 || rule->count < 0) {
        return -1;
    }
    return 0;
}

/* "hook": ["route_entry", "vlan_member"] -- or ["*"] for every object type we know. */
static int parse_hook_list(hs_json_t *j, char *wanted)
{
    char name[HS_NAME_MAX];
    int first = 1;

    if (hs_json_expect(j, '[') != 0) {
        return -1;
    }
    for (;;) {
        int c = hs_json_peek(j);
        int tag;

        if (c == ']') {
            j->p++;
            return 0;
        }
        if (first) {
            first = 0;
        } else if (hs_json_expect(j, ',') != 0) {
            return -1;
        }
        if (hs_json_string(j, name, sizeof(name)) != 0) {
            return -1;
        }
        if (strcmp(name, "*") == 0) {
            memset(wanted, 1, HS_NUM_TAGS);
            hs_warn("control file asked to hook every object type; "
                    "that reaches slots a shorter vendor API struct may not have");
            continue;
        }
        tag = tag_index(name);
        if (tag < 0) {
            hs_warn("control file wants to hook unknown object type %s, ignoring", name);
            continue;
        }
        wanted[tag] = 1;
    }
}

static int parse_control(const char *text, size_t len, hs_entry_t *entries, int max, long *seq,
                         char *wanted)
{
    hs_json_t j;
    char key[HS_NAME_MAX];
    int first = 1;
    int count = 0;
    int rc;

    *seq = 0;
    memset(wanted, 0, HS_NUM_TAGS);
    hs_json_init(&j, text, len);
    if (hs_json_expect(&j, '{') != 0) {
        return -1;
    }
    while ((rc = hs_json_member(&j, &first, key, sizeof(key))) == 1) {
        if (strcmp(key, "seq") == 0) {
            if (hs_json_int(&j, seq) != 0) {
                return -1;
            }
            continue;
        }
        if (strcmp(key, "hook") == 0) {
            if (parse_hook_list(&j, wanted) != 0) {
                return -1;
            }
            continue;
        }
        if (strcmp(key, "rules") != 0) {
            if (hs_json_skip_value(&j) != 0) {
                return -1;
            }
            continue;
        }

        /* "rules": { "<object type>": { "<op>": {...} } } */
        char tag_name[HS_NAME_MAX];
        int tags_first = 1;
        int tag_rc;

        if (hs_json_expect(&j, '{') != 0) {
            return -1;
        }
        while ((tag_rc = hs_json_member(&j, &tags_first, tag_name, sizeof(tag_name))) == 1) {
            char op_name[HS_NAME_MAX];
            int ops_first = 1;
            int op_rc;
            int tag = (strcmp(tag_name, "*") == 0) ? -1 : tag_index(tag_name);

            if (tag == -1 && strcmp(tag_name, "*") != 0) {
                hs_warn("control file names unknown object type %s, ignoring", tag_name);
            }
            if (hs_json_expect(&j, '{') != 0) {
                return -1;
            }
            while ((op_rc = hs_json_member(&j, &ops_first, op_name, sizeof(op_name))) == 1) {
                int op = (strcmp(op_name, "*") == 0) ? -1 : op_index(op_name);
                hs_rule_t rule;

                if (parse_rule(&j, &rule) != 0) {
                    return -1;
                }
                if (op == -1 && strcmp(op_name, "*") != 0) {
                    hs_warn("control file names unknown op %s, ignoring", op_name);
                    continue;
                }
                if (tag == -1 && strcmp(tag_name, "*") != 0) {
                    continue;
                }
                if (count >= max) {
                    hs_warn("control file has more than %d rules, ignoring the rest", max);
                    continue;
                }
                entries[count].tag = tag;
                entries[count].op = op;
                entries[count].rule = rule;
                count++;
                /* A rule is itself a request to patch that object type, so a hand-written
                 * control file does not have to repeat it in "hook". */
                if (tag >= 0) {
                    wanted[tag] = 1;
                } else {
                    memset(wanted, 1, HS_NUM_TAGS);
                }
            }
            if (op_rc < 0) {
                return -1;
            }
        }
        if (tag_rc < 0) {
            return -1;
        }
    }
    if (rc < 0) {
        return -1;
    }
    return count;
}

/* Flatten the parsed entries into the per-(tag, op) table the hot path reads. Applied
 * least-specific first, so "*"/"*" is a floor that a named rule overrides. */
static void install(const hs_entry_t *entries, int count, long seq, const char *wanted)
{
    hs_rule_t table[HS_NUM_TAGS][HS_NUM_OPS];
    int specificity;
    int i;
    int tag;
    int op;

    memset(table, 0, sizeof(table));
    for (specificity = 0; specificity <= 2; specificity++) {
        for (i = 0; i < count; i++) {
            int own = (entries[i].tag >= 0 ? 1 : 0) + (entries[i].op >= 0 ? 1 : 0);
            if (own != specificity) {
                continue;
            }
            for (tag = 0; tag < HS_NUM_TAGS; tag++) {
                if (entries[i].tag >= 0 && entries[i].tag != tag) {
                    continue;
                }
                for (op = 0; op < HS_NUM_OPS; op++) {
                    if (entries[i].op >= 0 && entries[i].op != op) {
                        continue;
                    }
                    table[tag][op] = entries[i].rule;
                }
            }
        }
    }

    pthread_rwlock_wrlock(&g_rules_lock);
    memcpy(g_rules, table, sizeof(g_rules));
    for (tag = 0; tag < HS_NUM_TAGS; tag++) {
        for (op = 0; op < HS_NUM_OPS; op++) {
            g_remaining[tag][op] = table[tag][op].count;
            g_logged[tag][op] = 0;
        }
        /* Accumulated, never cleared: a slot already patched stays patched for the life of
         * the process, so forgetting we wanted it would only make the stats lie. */
        if (wanted != NULL && wanted[tag]) {
            g_hook_wanted[tag] = 1;
        }
    }
    g_seq = seq;
    pthread_rwlock_unlock(&g_rules_lock);
}

static void clear_rules(void)
{
    install(NULL, 0, 0, NULL);
}

static void write_stats(void);

static void reload(const char *path)
{
    static char buffer[HS_CONTROL_MAX];
    hs_entry_t entries[HS_MAX_ENTRIES];
    char wanted[HS_NUM_TAGS];
    ssize_t got;
    long seq = 0;
    int count;
    int fd;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        clear_rules();
        hs_log("control file %s is gone, nothing armed", path);
        return;
    }
    got = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (got < 0) {
        hs_warn("cannot read %s, keeping the previous rules", path);
        return;
    }
    buffer[got] = '\0';

    count = parse_control(buffer, (size_t)got, entries, HS_MAX_ENTRIES, &seq, wanted);
    if (count < 0) {
        /* Half a fault spec is worse than none: disarm rather than act on a partial parse. */
        clear_rules();
        hs_warn("%s is not valid control JSON, disarmed everything", path);
        return;
    }
    install(entries, count, seq, wanted);
    hs_log("control seq %ld applied: %d rule(s) from %s", seq, count, path);
}

/* Re-read the control file if it changed. Caller holds g_reload_lock. */
static void check_control(void)
{
    const char *path = control_path();
    struct stat st;

    if (stat(path, &st) != 0) {
        if (g_control_size != -1) {
            g_control_size = -1;
            g_control_mtime = 0;
            clear_rules();
            hs_log("control file %s removed, disarmed", path);
        }
    } else if ((long)st.st_mtime != g_control_mtime ||
               (long)st.st_mtim.tv_nsec != g_control_mtime_ns ||
               (long)st.st_size != g_control_size) {
        /* Nanoseconds matter: two rewrites inside the same second that happen to be the same
         * length would otherwise look unchanged, and the second fault would never arm. */
        g_control_mtime = (long)st.st_mtime;
        g_control_mtime_ns = (long)st.st_mtim.tv_nsec;
        g_control_size = (long)st.st_size;
        reload(path);
    }
}

/* Called on every intercepted SAI call, so it must stay cheap: one clock read, and a stat()
 * at most four times a second. */
static void maybe_reload(void)
{
    long now = now_ms();

    if (now - __atomic_load_n(&g_last_check_ms, __ATOMIC_RELAXED) < HS_RELOAD_GAP_MS) {
        return;
    }
    if (pthread_mutex_trylock(&g_reload_lock) != 0) {
        return;   /* another thread is already looking */
    }
    __atomic_store_n(&g_last_check_ms, now, __ATOMIC_RELAXED);
    check_control();
    /* Same budget pays for publishing the counters, so status() sees live numbers while SAI
     * traffic is flowing rather than only after a control change. */
    write_stats();
    pthread_mutex_unlock(&g_reload_lock);
}

/* Same, but never skipped: used once at hook time, where the answer decides what gets patched. */
static void force_reload(void)
{
    pthread_mutex_lock(&g_reload_lock);
    __atomic_store_n(&g_last_check_ms, now_ms(), __ATOMIC_RELAXED);
    check_control();
    pthread_mutex_unlock(&g_reload_lock);
}

/* ------------------------------------------------------------------ stats
 *
 * Written by the hook path only, so only syncd ever produces one. Its presence is not what
 * proves the shim is loaded -- injectors/sai.py reads /proc/<syncd>/maps for that -- but it is
 * what turns "a fault is armed" into "the fault was reached N times".
 */
static void write_stats(void)
{
    const char *path = stats_path();
    char tmp[512];
    char body[16 * 1024];
    size_t used = 0;
    int printed_one = 0;
    int tag;
    int op;
    int fd;
    int n;

    n = snprintf(body, sizeof(body),
                 "{\"pid\":%d,\"sai_version\":\"%s\",\"hooks\":%d,\"seq\":%ld,\"updated\":%ld,"
                 "\"hooked\":[",
                 (int)getpid(), HS_SAI_VERSION, g_hook_count, g_seq, (long)time(NULL));
    if (n < 0 || (size_t)n >= sizeof(body)) {
        return;
    }
    used = (size_t)n;

    /* Which object types actually got patched. injectors/sai.py diffs this against what the
     * spec needs and restarts syncd only when something is missing. */
    for (tag = 0; tag < HS_NUM_TAGS; tag++) {
        if (!g_hook_seen[tag]) {
            continue;
        }
        n = snprintf(tmp, sizeof(tmp), "%s\"%s\"", printed_one ? "," : "", hs_tags[tag].name);
        if (n < 0 || used + (size_t)n + 16 >= sizeof(body)) {
            break;
        }
        memcpy(body + used, tmp, (size_t)n);
        used += (size_t)n;
        printed_one = 1;
    }
    memcpy(body + used, "],\"rules\":[", 11);
    used += 11;
    printed_one = 0;

    pthread_rwlock_rdlock(&g_rules_lock);
    for (tag = 0; tag < HS_NUM_TAGS; tag++) {
        for (op = 0; op < HS_NUM_OPS; op++) {
            unsigned long calls = __atomic_load_n(&g_calls[tag][op], __ATOMIC_RELAXED);
            if (!g_rules[tag][op].active && calls == 0) {
                continue;
            }
            n = snprintf(tmp, sizeof(tmp),
                         "%s{\"object_type\":\"%s\",\"op\":\"%s\",\"armed\":%s,\"calls\":%lu,"
                         "\"matched\":%lu,\"injected\":%lu,\"delay_ms\":%d,\"status\":%d,"
                         "\"drop\":%s,\"remaining\":%ld}",
                         printed_one ? "," : "", hs_tags[tag].name, hs_op_names[op],
                         g_rules[tag][op].active ? "true" : "false", calls,
                         __atomic_load_n(&g_matched[tag][op], __ATOMIC_RELAXED),
                         __atomic_load_n(&g_injected[tag][op], __ATOMIC_RELAXED),
                         g_rules[tag][op].delay_ms,
                         g_rules[tag][op].has_status ? g_rules[tag][op].status : 0,
                         g_rules[tag][op].drop ? "true" : "false",
                         __atomic_load_n(&g_remaining[tag][op], __ATOMIC_RELAXED));
            if (n < 0 || used + (size_t)n + 3 >= sizeof(body)) {
                goto done;   /* truncate rather than grow: this is a status file, not a log */
            }
            memcpy(body + used, tmp, (size_t)n);
            used += (size_t)n;
            printed_one = 1;
        }
    }
done:
    pthread_rwlock_unlock(&g_rules_lock);
    if (used + 3 > sizeof(body)) {
        return;
    }
    memcpy(body + used, "]}\n", 3);
    used += 3;

    /* Rename into place so a reader never sees half a file. */
    n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        return;
    }
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        return;
    }
    if (write(fd, body, used) == (ssize_t)used) {
        close(fd);
        if (rename(tmp, path) != 0) {
            unlink(tmp);
        }
    } else {
        close(fd);
        unlink(tmp);
    }
}

/* ------------------------------------------------------------------ the hot path */

static sai_status_t dispatch(int hook, void *a0, void *a1, void *a2, void *a3,
                             void *a4, void *a5, void *a6, void *a7)
{
    int tag = hook / HS_NUM_OPS;
    int op = hook % HS_NUM_OPS;
    hs_fn_t real = (hs_fn_t)g_real[hook];
    hs_rule_t rule;
    int log_this = 0;

    /* Count first, publish second. maybe_reload() is what flushes the stats file, so doing it
     * the other way round wrote a count that excluded the very call triggering the write --
     * every (object type, operation) sat one call behind, and on a quiet box that call could
     * be minutes old. Adding one route to a settled switch looked like the shim had missed it. */
    __atomic_add_fetch(&g_calls[tag][op], 1, __ATOMIC_RELAXED);
    maybe_reload();

    pthread_rwlock_rdlock(&g_rules_lock);
    rule = g_rules[tag][op];
    pthread_rwlock_unlock(&g_rules_lock);

    if (!rule.active) {
        return real != NULL ? real(a0, a1, a2, a3, a4, a5, a6, a7) : SAI_STATUS_NOT_IMPLEMENTED;
    }

    if (rule.count > 0) {
        long left = __atomic_load_n(&g_remaining[tag][op], __ATOMIC_RELAXED);
        for (;;) {
            if (left <= 0) {
                /* Budget spent: this rule is done, let the call through untouched. */
                return real != NULL ? real(a0, a1, a2, a3, a4, a5, a6, a7)
                                    : SAI_STATUS_NOT_IMPLEMENTED;
            }
            if (__atomic_compare_exchange_n(&g_remaining[tag][op], &left, left - 1, 1,
                                            __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)) {
                break;
            }
        }
    }

    __atomic_add_fetch(&g_matched[tag][op], 1, __ATOMIC_RELAXED);
    if (__atomic_exchange_n(&g_logged[tag][op], 1, __ATOMIC_RELAXED) == 0) {
        log_this = 1;   /* first hit of each rule, so syslog shows the fault landing, once */
    }

    if (rule.delay_ms > 0) {
        if (log_this) {
            hs_log("delaying %s %s by %d ms", hs_tags[tag].name, hs_op_names[op], rule.delay_ms);
        }
        sleep_ms(rule.delay_ms);
    }

    if (rule.drop) {
        if (log_this) {
            hs_log("dropping %s %s: returning SUCCESS without calling the ASIC",
                   hs_tags[tag].name, hs_op_names[op]);
        }
        __atomic_add_fetch(&g_injected[tag][op], 1, __ATOMIC_RELAXED);
        return SAI_STATUS_SUCCESS;
    }
    if (rule.has_status) {
        if (log_this) {
            hs_log("failing %s %s with status %d", hs_tags[tag].name, hs_op_names[op],
                   rule.status);
        }
        __atomic_add_fetch(&g_injected[tag][op], 1, __ATOMIC_RELAXED);
        return (sai_status_t)rule.status;
    }

    __atomic_add_fetch(&g_injected[tag][op], 1, __ATOMIC_RELAXED);
    return real != NULL ? real(a0, a1, a2, a3, a4, a5, a6, a7) : SAI_STATUS_NOT_IMPLEMENTED;
}

#define HS_DEFINE_TRAMPOLINE(n)                                                               \
    static sai_status_t hs_trampoline_##n(void *a0, void *a1, void *a2, void *a3,             \
                                          void *a4, void *a5, void *a6, void *a7)             \
    {                                                                                         \
        return dispatch((n), a0, a1, a2, a3, a4, a5, a6, a7);                                 \
    }

HS_TRAMPOLINES(HS_DEFINE_TRAMPOLINE)

#define HS_REFERENCE_TRAMPOLINE(n) hs_trampoline_##n,

static hs_fn_t const g_trampolines[HS_NUM_HOOKS] = {
    HS_TRAMPOLINES(HS_REFERENCE_TRAMPOLINE)
};

/* ------------------------------------------------------------------ patching the table */

static int is_ours(const void *fn)
{
    int i;

    for (i = 0; i < HS_NUM_HOOKS; i++) {
        if ((const void *)g_trampolines[i] == fn) {
            return 1;
        }
    }
    return 0;
}

/* The vendor's API struct is usually relocated read-only data, so make the pages writable
 * before patching. They stay writable: we are a fault-injection build, and restoring the
 * protection would only break a later re-hook. */
static int make_writable(void *addr, size_t len)
{
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t start;
    uintptr_t end;

    if (page <= 0) {
        page = 4096;
    }
    start = (uintptr_t)addr & ~(uintptr_t)(page - 1);
    end = ((uintptr_t)addr + len + (uintptr_t)page - 1) & ~(uintptr_t)(page - 1);
    return mprotect((void *)start, (size_t)(end - start), PROT_READ | PROT_WRITE);
}

static void hook_api(int api, void **table)
{
    char wanted[HS_NUM_TAGS];
    int lowest = -1;
    int highest = -1;
    int installed = 0;
    int tag;
    int op;

    pthread_rwlock_rdlock(&g_rules_lock);
    memcpy(wanted, g_hook_wanted, sizeof(wanted));
    pthread_rwlock_unlock(&g_rules_lock);

    for (tag = 0; tag < HS_NUM_TAGS; tag++) {
        if (hs_tags[tag].api != api || !wanted[tag]) {
            continue;
        }
        for (op = 0; op < HS_NUM_OPS; op++) {
            int slot = hs_tags[tag].slot[op];
            if (slot < 0) {
                continue;
            }
            if (lowest < 0 || slot < lowest) {
                lowest = slot;
            }
            if (slot > highest) {
                highest = slot;
            }
        }
    }
    if (lowest < 0) {
        return;   /* nothing generated for this API */
    }

    if (make_writable(&table[lowest], (size_t)(highest - lowest + 1) * sizeof(void *)) != 0) {
        hs_warn("cannot make the API %d table writable, leaving it alone", api);
        return;
    }

    for (tag = 0; tag < HS_NUM_TAGS; tag++) {
        if (hs_tags[tag].api != api || !wanted[tag]) {
            continue;
        }
        g_hook_seen[tag] = 1;
        for (op = 0; op < HS_NUM_OPS; op++) {
            int slot = hs_tags[tag].slot[op];
            int hook = tag * HS_NUM_OPS + op;
            void *current;

            if (slot < 0 || g_hooked[hook]) {
                continue;
            }
            current = table[slot];
            if (current == NULL || is_ours(current)) {
                continue;   /* vendor does not implement it, or we already patched this table */
            }
            g_real[hook] = current;
            table[slot] = (void *)g_trampolines[hook];
            g_hooked[hook] = 1;
            installed++;
        }
    }

    g_hook_count += installed;
    if (installed > 0) {
        hs_log("hooked %d entry point(s) in SAI API %d (%d total)", installed, api, g_hook_count);
    }
}

/* ------------------------------------------------------------------ the interposed symbol */

/* Built with -fvisibility=hidden, so this is the one symbol the shim exports -- exactly the
 * one LD_PRELOAD has to resolve ahead of the vendor library. */
__attribute__((visibility("default")))
sai_status_t sai_api_query(int api, void **api_method_table);

sai_status_t sai_api_query(int api, void **api_method_table)
{
    static sai_status_t (*real_query)(int, void **);
    static pthread_mutex_t resolve_lock = PTHREAD_MUTEX_INITIALIZER;
    sai_status_t rc;

    pthread_mutex_lock(&resolve_lock);
    if (real_query == NULL) {
        *(void **)&real_query = dlsym(RTLD_NEXT, "sai_api_query");
    }
    pthread_mutex_unlock(&resolve_lock);

    if (real_query == NULL) {
        hs_warn("no real sai_api_query behind us; is the shim preloaded into the wrong process?");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    rc = real_query(api, api_method_table);
    if (rc != SAI_STATUS_SUCCESS || api_method_table == NULL || *api_method_table == NULL) {
        return rc;
    }

    /* Read the control file before patching, not after: it is what says which object types to
     * patch, and it was written before syncd was restarted. Forcing the read here also means
     * the very first SAI call already carries whatever was armed. */
    force_reload();

    pthread_mutex_lock(&g_hook_lock);
    hook_api(api, (void **)*api_method_table);
    pthread_mutex_unlock(&g_hook_lock);

    write_stats();
    return rc;
}

/* A short burst of calls can finish inside the flush interval, so publish the final counters
 * on the way out too. Guarded on having hooked something, so a process that was preloaded but
 * never reached SAI writes nothing. */
__attribute__((destructor))
static void flush_on_exit(void)
{
    if (g_hook_count > 0) {
        write_stats();
    }
}
