#include "hs_json.h"

#include <limits.h>
#include <string.h>

static int fail(hs_json_t *j)
{
    j->err = 1;
    return -1;
}

void hs_json_init(hs_json_t *j, const char *text, size_t len)
{
    j->p = text;
    j->end = text + len;
    j->err = 0;
}

static void skip_ws(hs_json_t *j)
{
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r')) {
        j->p++;
    }
}

int hs_json_peek(hs_json_t *j)
{
    if (j->err) {
        return -1;
    }
    skip_ws(j);
    return j->p < j->end ? (unsigned char)*j->p : -1;
}

int hs_json_expect(hs_json_t *j, char c)
{
    if (hs_json_peek(j) != (unsigned char)c) {
        return fail(j);
    }
    j->p++;
    return 0;
}

/* Walk over a string literal without keeping it. `out` may be NULL. */
static int read_string(hs_json_t *j, char *out, size_t cap)
{
    size_t n = 0;

    if (hs_json_expect(j, '"') != 0) {
        return -1;
    }
    while (j->p < j->end && *j->p != '"') {
        char c = *j->p++;
        if (c == '\\') {
            if (j->p >= j->end) {
                return fail(j);
            }
            switch (*j->p++) {
            case '"':  c = '"';  break;
            case '\\': c = '\\'; break;
            case '/':  c = '/';  break;
            case 'b':  c = '\b'; break;
            case 'f':  c = '\f'; break;
            case 'n':  c = '\n'; break;
            case 'r':  c = '\r'; break;
            case 't':  c = '\t'; break;
            default:   return fail(j);   /* including \u: we never emit non-ASCII */
            }
        }
        if (out != NULL) {
            if (n + 1 >= cap) {
                return fail(j);
            }
            out[n++] = c;
        }
    }
    if (j->p >= j->end) {
        return fail(j);
    }
    j->p++;   /* closing quote */
    if (out != NULL) {
        out[n] = '\0';
    }
    return 0;
}

int hs_json_string(hs_json_t *j, char *out, size_t cap)
{
    return read_string(j, out, cap);
}

/* Accumulated by hand rather than with strtol: on glibc 2.38 and later strtol resolves to
 * __isoc23_strtol, which would stop the shim loading on an older syncd container. Nothing
 * else here reaches past glibc 2.34. */
int hs_json_int(hs_json_t *j, long *out)
{
    long value = 0;
    int negative = 0;
    int digits = 0;

    if (hs_json_peek(j) < 0) {
        return fail(j);
    }
    if (*j->p == '-') {
        negative = 1;
        j->p++;
    } else if (*j->p == '+') {
        j->p++;
    }
    while (j->p < j->end && *j->p >= '0' && *j->p <= '9') {
        int digit = *j->p - '0';
        if (value > (LONG_MAX - digit) / 10) {
            return fail(j);
        }
        value = value * 10 + digit;
        j->p++;
        digits++;
    }
    if (digits == 0) {
        return fail(j);
    }
    /* A fractional or exponent part means the producer sent something we would silently
     * truncate -- refuse instead. */
    if (j->p < j->end && (*j->p == '.' || *j->p == 'e' || *j->p == 'E')) {
        return fail(j);
    }
    *out = negative ? -value : value;
    return 0;
}

int hs_json_bool(hs_json_t *j, int *out)
{
    int c = hs_json_peek(j);

    if (c == 't' && (size_t)(j->end - j->p) >= 4 && memcmp(j->p, "true", 4) == 0) {
        j->p += 4;
        *out = 1;
        return 0;
    }
    if (c == 'f' && (size_t)(j->end - j->p) >= 5 && memcmp(j->p, "false", 5) == 0) {
        j->p += 5;
        *out = 0;
        return 0;
    }
    return fail(j);
}

int hs_json_skip_value(hs_json_t *j)
{
    int c = hs_json_peek(j);
    int depth = 0;

    if (c < 0) {
        return fail(j);
    }
    if (c == '"') {
        return read_string(j, NULL, 0);
    }
    if (c == 'n' && (size_t)(j->end - j->p) >= 4 && memcmp(j->p, "null", 4) == 0) {
        j->p += 4;
        return 0;
    }
    if (c == 't' || c == 'f') {
        int ignored;
        return hs_json_bool(j, &ignored);
    }
    if (c != '{' && c != '[') {
        /* A number, possibly a float -- consume its characters without interpreting them. */
        const char *start = j->p;
        while (j->p < j->end && strchr("+-.eE0123456789", *j->p) != NULL) {
            j->p++;
        }
        return j->p == start ? fail(j) : 0;
    }

    /* Object or array: walk to the matching close, honouring strings so braces inside them
     * do not shift the depth. */
    do {
        c = hs_json_peek(j);
        if (c < 0) {
            return fail(j);
        }
        if (c == '{' || c == '[') {
            depth++;
            j->p++;
        } else if (c == '}' || c == ']') {
            depth--;
            j->p++;
        } else if (c == '"') {
            if (read_string(j, NULL, 0) != 0) {
                return -1;
            }
        } else {
            j->p++;
        }
    } while (depth > 0);
    return 0;
}

int hs_json_member(hs_json_t *j, int *first, char *key, size_t cap)
{
    int c = hs_json_peek(j);

    if (c < 0) {
        return fail(j);
    }
    if (c == '}') {
        j->p++;
        return 0;
    }
    if (*first) {
        *first = 0;
    } else if (hs_json_expect(j, ',') != 0) {
        return -1;
    }
    if (hs_json_string(j, key, cap) != 0 || hs_json_expect(j, ':') != 0) {
        return -1;
    }
    return 1;
}
