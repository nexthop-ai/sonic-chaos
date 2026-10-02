/* A strict reader for the subset of JSON the shim's control file uses.
 *
 * The shim runs inside syncd, so it pulls in no libraries beyond libc. The control file is
 * machine-written by injectors/sai.py and has a fixed shape: nested objects whose leaves are
 * integers, booleans, strings and null. That is all this reads. Anything else -- floats at a
 * place we want an integer, \u escapes, a value where an object belongs -- is an error rather
 * than a guess, because a misparsed fault spec is worse than no fault at all.
 *
 * Every function returns 0 on success and -1 on error, and leaves the cursor unusable after an
 * error so callers can check once at the end.
 */
#ifndef HS_JSON_H
#define HS_JSON_H

#include <stddef.h>

typedef struct {
    const char *p;
    const char *end;
    int err;
} hs_json_t;

void hs_json_init(hs_json_t *j, const char *text, size_t len);

/* Next non-space character, or -1 at end of input. Does not consume. */
int hs_json_peek(hs_json_t *j);

/* Consume the next non-space character, which must be `c`. */
int hs_json_expect(hs_json_t *j, char c);

/* Parse a string literal into `out` (always NUL-terminated). Too long is an error. */
int hs_json_string(hs_json_t *j, char *out, size_t cap);

/* Parse an integer. A float, or anything out of long range, is an error. */
int hs_json_int(hs_json_t *j, long *out);

/* Parse true/false into 0/1. */
int hs_json_bool(hs_json_t *j, int *out);

/* Consume any value, including nested objects and arrays. */
int hs_json_skip_value(hs_json_t *j);

/* Iterate the members of an object, after its '{' has been consumed:
 *
 *     int first = 1;
 *     while (hs_json_member(j, &first, key, sizeof key) == 1) { ... read the value ... }
 *     if (j->err) ...
 *
 * Returns 1 with `key` filled and the cursor on the value, 0 at the closing '}', -1 on error.
 */
int hs_json_member(hs_json_t *j, int *first, char *key, size_t cap);

#endif /* HS_JSON_H */
