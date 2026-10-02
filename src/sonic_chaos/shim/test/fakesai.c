/* A stand-in for the vendor's libsai, so the shim can be proven on a laptop.
 *
 * It hands back two API tables laid out exactly like the real ones -- sai_route_api_t and
 * sai_vlan_api_t, same slot order, same arities -- and counts what actually reaches it. The
 * arities matter: the shim's trampolines are declared with eight pointer arguments and stand
 * in for functions taking one, three, six and seven. If that assumption were wrong, these
 * counters and the forwarded-argument check would catch it here rather than on a switch.
 */
#include <stdint.h>
#include <stdio.h>

typedef int32_t sai_status_t;

int fake_route_create_calls;
int fake_route_remove_calls;
int fake_route_bulk_calls;
int fake_vlan_member_remove_calls;
int fake_vlan_member_bulk_calls;

/* What the last forwarded call actually received, so the test can prove the arguments
 * survived the trampoline -- including the seventh, which travels on the stack. */
unsigned long fake_route_create_attr_count;
unsigned long fake_vlan_member_remove_oid;
unsigned long fake_vlan_bulk_arg6;
unsigned long fake_vlan_bulk_arg7;

/* The real API structs hold function pointers of many different shapes; a table of void*
 * is the closest portable stand-in, and it is how the shim reaches the slots too. */
typedef void *slot_t;

/* --- sai_route_api_t: create/remove/set/get then the bulk four --- */

static sai_status_t route_create(const void *entry, uint32_t attr_count, const void *attrs)
{
    (void)entry;
    (void)attrs;
    fake_route_create_calls++;
    fake_route_create_attr_count = attr_count;
    return 0;
}

static sai_status_t route_remove(const void *entry)
{
    (void)entry;
    fake_route_remove_calls++;
    return 0;
}

static sai_status_t route_set(const void *entry, const void *attr)
{
    (void)entry;
    (void)attr;
    return 0;
}

static sai_status_t route_get(const void *entry, uint32_t attr_count, void *attrs)
{
    (void)entry;
    (void)attr_count;
    (void)attrs;
    return 0;
}

/* sai_bulk_create_route_entry_fn -- six arguments, all in registers. */
static sai_status_t route_bulk_create(uint32_t count, const void *entries,
                                      const uint32_t *attr_counts, const void **attrs,
                                      int mode, sai_status_t *statuses)
{
    (void)count;
    (void)entries;
    (void)attr_counts;
    (void)attrs;
    (void)mode;
    (void)statuses;
    fake_route_bulk_calls++;
    return 0;
}

static slot_t route_table[8] = {
    (slot_t)(void (*)(void))route_create,
    (slot_t)(void (*)(void))route_remove,
    (slot_t)(void (*)(void))route_set,
    (slot_t)(void (*)(void))route_get,
    (slot_t)(void (*)(void))route_bulk_create,
    NULL,   /* remove_route_entries: a slot the vendor left unimplemented */
    NULL,
    NULL,
};

/* --- sai_vlan_api_t: vlan at 0..3, vlan_member at 4..7, bulk members at 8..9 --- */

static sai_status_t vlan_noop(void)
{
    return 0;
}

static sai_status_t vlan_member_remove(uint64_t oid)
{
    fake_vlan_member_remove_calls++;
    fake_vlan_member_remove_oid = (unsigned long)oid;
    return 0;
}

/* sai_bulk_object_create_fn -- seven arguments, so the last one is passed on the stack.
 * This is the case that would break a trampoline declared with only six. */
static sai_status_t vlan_member_bulk_create(uint64_t switch_id, uint32_t count,
                                            const uint32_t *attr_counts, const void **attrs,
                                            int mode, uint64_t *oids, sai_status_t *statuses)
{
    (void)switch_id;
    (void)count;
    (void)attr_counts;
    (void)attrs;
    (void)mode;
    fake_vlan_member_bulk_calls++;
    fake_vlan_bulk_arg6 = (unsigned long)(uintptr_t)oids;
    fake_vlan_bulk_arg7 = (unsigned long)(uintptr_t)statuses;
    return 0;
}

static slot_t vlan_table[13] = {
    (slot_t)(void (*)(void))vlan_noop,             /* create_vlan */
    (slot_t)(void (*)(void))vlan_noop,             /* remove_vlan */
    (slot_t)(void (*)(void))vlan_noop,             /* set_vlan_attribute */
    (slot_t)(void (*)(void))vlan_noop,             /* get_vlan_attribute */
    (slot_t)(void (*)(void))vlan_noop,             /* create_vlan_member */
    (slot_t)(void (*)(void))vlan_member_remove,    /* remove_vlan_member */
    (slot_t)(void (*)(void))vlan_noop,             /* set_vlan_member_attribute */
    (slot_t)(void (*)(void))vlan_noop,             /* get_vlan_member_attribute */
    (slot_t)(void (*)(void))vlan_member_bulk_create,
    (slot_t)(void (*)(void))vlan_noop,             /* remove_vlan_members */
    (slot_t)(void (*)(void))vlan_noop,             /* get_vlan_stats */
    (slot_t)(void (*)(void))vlan_noop,             /* get_vlan_stats_ext */
    (slot_t)(void (*)(void))vlan_noop,             /* clear_vlan_stats */
};

#define FAKE_SAI_API_VLAN  4
#define FAKE_SAI_API_ROUTE 6

sai_status_t sai_api_query(int api, void **api_method_table)
{
    if (api_method_table == NULL) {
        return -5;
    }
    if (api == FAKE_SAI_API_ROUTE) {
        *api_method_table = route_table;
        return 0;
    }
    if (api == FAKE_SAI_API_VLAN) {
        *api_method_table = vlan_table;
        return 0;
    }
    return -2;
}
