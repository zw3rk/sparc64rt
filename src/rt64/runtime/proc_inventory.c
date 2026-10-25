/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/proc_inventory.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    const char *data;
    size_t length;
} span_t;

static bool span_equal(span_t span, const char *text)
{
    size_t length = strlen(text);
    return span.length == length && memcmp(span.data, text, length) == 0;
}

static bool has_nul(const char *text, size_t length)
{
    return text == NULL || memchr(text, '\0', length) != NULL;
}

static bool parse_uint(span_t span, uint64_t maximum, uint64_t *value)
{
    uint64_t parsed = 0;
    if (span.length == 0)
        return false;
    for (size_t i = 0; i < span.length; ++i) {
        unsigned char c = (unsigned char)span.data[i];
        if (c < '0' || c > '9')
            return false;
        uint64_t digit = (uint64_t)(c - '0');
        if (digit > maximum)
            return false;
        if (parsed > (maximum - digit) / 10u)
            return false;
        parsed = parsed * 10u + digit;
    }
    *value = parsed;
    return true;
}

static uint64_t pid_maximum(void)
{
    const unsigned int uint_bits = (unsigned int)(sizeof(uintmax_t) * CHAR_BIT);
    const unsigned int pid_bits = (unsigned int)(sizeof(pid_t) * CHAR_BIT);
    const unsigned int value_bits = pid_bits - 1u;
    if (value_bits >= uint_bits)
        return (uint64_t)(UINTMAX_MAX >> 1u);
    return (uint64_t)(UINTMAX_MAX >> (uint_bits - value_bits));
}

static bool parse_pid(span_t span, bool allow_zero, pid_t *pid)
{
    uint64_t value;
    if (!parse_uint(span, pid_maximum(), &value) ||
        (!allow_zero && value == 0))
        return false;
    *pid = (pid_t)value;
    return true;
}

static bool horizontal_space(char c)
{
    return c == ' ' || c == '\t';
}

static void skip_horizontal(span_t text, size_t *offset)
{
    while (*offset < text.length && horizontal_space(text.data[*offset]))
        ++*offset;
}

static bool next_horizontal_token(span_t text, size_t *offset, span_t *token)
{
    size_t start;
    skip_horizontal(text, offset);
    if (*offset == text.length)
        return false;
    start = *offset;
    while (*offset < text.length && !horizontal_space(text.data[*offset]))
        ++*offset;
    token->data = text.data + start;
    token->length = *offset - start;
    return true;
}

int sparc64_proc_inventory_namespace(const char *text, size_t length,
                                pid_t expected)
{
    size_t offset = 0;
    unsigned int matches = 0;
    pid_t found = 0;
    if (text == NULL || expected <= 0 || has_nul(text, length))
        return EINVAL;
    while (offset < length) {
        size_t end = offset;
        span_t line;
        while (end < length && text[end] != '\n')
            ++end;
        line.data = text + offset;
        line.length = end - offset;
        if (line.length >= 6 && memcmp(line.data, "NStgid", 6) == 0 &&
            (line.length == 6 || line.data[6] == ':' ||
             horizontal_space(line.data[6]))) {
            size_t value_offset = 6;
            span_t token;
            unsigned int ids = 0;
            pid_t only_id = 0;
            if (line.length < 7 || line.data[6] != ':')
                return EINVAL;
            if (++matches != 1)
                return EINVAL;
            value_offset = 7;
            while (value_offset < line.length) {
                uint64_t parsed;
                skip_horizontal(line, &value_offset);
                if (value_offset == line.length)
                    break;
                if (!next_horizontal_token(line, &value_offset, &token) ||
                    !parse_uint(token, pid_maximum(), &parsed) || parsed == 0)
                    return EINVAL;
                ++ids;
                if (ids == 1)
                    only_id = (pid_t)parsed;
            }
            if (ids == 0)
                return EINVAL;
            if (ids != 1)
                return EOPNOTSUPP;
            found = only_id;
        }
        offset = end + (end < length ? 1u : 0u);
    }
    if (matches == 0 || found != expected)
        return EOPNOTSUPP;
    return 0;
}

static bool valid_state(char state)
{
    return state == 'R' || state == 'S' || state == 'D' || state == 'Z' ||
           state == 'T' || state == 't' || state == 'X' || state == 'x' ||
           state == 'K' || state == 'W' || state == 'P' || state == 'I';
}

int sparc64_proc_inventory_parent(const char *text, size_t length, pid_t expected,
                             pid_t *parent)
{
    span_t all, token;
    size_t offset = 0, close = SIZE_MAX;
    pid_t parsed_pid, parsed_parent;
    if (text == NULL || parent == NULL || expected <= 0 ||
        has_nul(text, length))
        return EINVAL;
    all.data = text;
    all.length = length;
    while (all.length > 0 && all.data[all.length - 1] == '\n')
        --all.length;
    if (!next_horizontal_token(all, &offset, &token) ||
        !parse_pid(token, false, &parsed_pid))
        return EINVAL;
    if (parsed_pid != expected)
        return EOPNOTSUPP;
    skip_horizontal(all, &offset);
    if (offset == all.length || all.data[offset] != '(')
        return EINVAL;
    for (size_t i = offset + 1; i < all.length; ++i) {
        if (all.data[i] == ')')
            close = i;
    }
    if (close == SIZE_MAX)
        return EINVAL;
    offset = close + 1;
    skip_horizontal(all, &offset);
    if (offset >= all.length || !valid_state(all.data[offset]))
        return EINVAL;
    ++offset;
    if (offset >= all.length || !horizontal_space(all.data[offset]))
        return EINVAL;
    if (!next_horizontal_token(all, &offset, &token) ||
        !parse_pid(token, true, &parsed_parent))
        return EINVAL;
    *parent = parsed_parent;
    return 0;
}

static int scan_hidepid(span_t options, unsigned int *count, bool *supported)
{
    size_t offset = 0;
    while (offset <= options.length) {
        size_t end = offset;
        span_t item;
        while (end < options.length && options.data[end] != ',')
            ++end;
        item.data = options.data + offset;
        item.length = end - offset;
        if (item.length == 0)
            return EINVAL;
        if (item.length == 7 && memcmp(item.data, "hidepid", 7) == 0) {
            if (++*count != 1)
                return EINVAL;
            *supported = false;
        } else if (item.length >= 8 && memcmp(item.data, "hidepid=", 8) == 0) {
            span_t value = {item.data + 8, item.length - 8};
            if (++*count != 1)
                return EINVAL;
            if (span_equal(value, "0") || span_equal(value, "off"))
                *supported = true;
            else
                *supported = false;
        }
        if (end == options.length)
            break;
        offset = end + 1;
    }
    return 0;
}

typedef struct {
    uint64_t mount_id;
    uint32_t dev_major, dev_minor;
    span_t root, mountpoint, fs_type;
    unsigned int hidepid_count;
    bool hidepid_supported;
} mount_line_t;

static int parse_mount_line(span_t line, mount_line_t *out)
{
    span_t fields[6], token, super_options;
    size_t offset = 0;
    unsigned int field_count = 0, hidepid_count = 0;
    bool hidepid_supported = true;
    uint64_t id, major, minor, ignored;
    bool separator = false;
    if (line.length == 0)
        return EINVAL;
    while (next_horizontal_token(line, &offset, &token)) {
        if (span_equal(token, "-")) {
            if (separator || field_count < 6)
                return EINVAL;
            separator = true;
            break;
        }
        if (field_count < 6) {
            fields[field_count++] = token;
        } else {
            int result = scan_hidepid(token, &hidepid_count,
                                      &hidepid_supported);
            if (result != 0)
                return result;
        }
    }
    if (!separator || field_count != 6 ||
        !parse_uint(fields[0], UINT64_MAX, &id) || id == 0 ||
        !parse_uint(fields[1], UINT64_MAX, &ignored) ||
        fields[2].length == 0 || fields[3].length == 0 ||
        fields[4].length == 0 || fields[5].length == 0)
        return EINVAL;
    size_t colon = 0;
    while (colon < fields[2].length && fields[2].data[colon] != ':')
        ++colon;
    if (colon == fields[2].length || colon == 0 || colon + 1 == fields[2].length)
        return EINVAL;
    span_t major_span = {fields[2].data, colon};
    span_t minor_span = {fields[2].data + colon + 1,
                         fields[2].length - colon - 1};
    if (!parse_uint(major_span, UINT32_MAX, &major) ||
        !parse_uint(minor_span, UINT32_MAX, &minor) ||
        scan_hidepid(fields[5], &hidepid_count, &hidepid_supported) != 0)
        return EINVAL;
    if (!next_horizontal_token(line, &offset, &out->fs_type) ||
        !next_horizontal_token(line, &offset, &token) ||
        !next_horizontal_token(line, &offset, &super_options) ||
        next_horizontal_token(line, &offset, &token))
        return EINVAL;
    int result = scan_hidepid(super_options, &hidepid_count,
                              &hidepid_supported);
    if (result != 0)
        return result;
    out->mount_id = id;
    out->dev_major = (uint32_t)major;
    out->dev_minor = (uint32_t)minor;
    out->root = fields[3];
    out->mountpoint = fields[4];
    out->hidepid_count = hidepid_count;
    out->hidepid_supported = hidepid_supported;
    return 0;
}

static bool proc_overlay(span_t path)
{
    static const char self[] = "/proc/self";
    static const char prefix[] = "/proc/";
    if (path.length >= sizeof(self) - 1 &&
        memcmp(path.data, self, sizeof(self) - 1) == 0 &&
        (path.length == sizeof(self) - 1 || path.data[sizeof(self) - 1] == '/'))
        return true;
    if (path.length <= sizeof(prefix) - 1 ||
        memcmp(path.data, prefix, sizeof(prefix) - 1) != 0)
        return false;
    size_t offset = sizeof(prefix) - 1;
    size_t start = offset;
    while (offset < path.length && path.data[offset] >= '0' &&
           path.data[offset] <= '9')
        ++offset;
    return offset > start &&
           (offset == path.length || path.data[offset] == '/');
}

int sparc64_proc_inventory_mount(const char *text, size_t length,
                            const sparc64_proc_instance_t *expected)
{
    size_t offset = 0;
    unsigned int target_ids = 0, proc_mountpoints = 0;
    mount_line_t selected = {0};
    if (text == NULL || expected == NULL || expected->mount_id == 0 ||
        has_nul(text, length))
        return EINVAL;
    while (offset < length) {
        size_t end = offset;
        span_t line;
        mount_line_t parsed = {0};
        while (end < length && text[end] != '\n')
            ++end;
        line.data = text + offset;
        line.length = end - offset;
        int result = parse_mount_line(line, &parsed);
        if (result != 0)
            return result;
        if (span_equal(parsed.mountpoint, "/proc"))
            ++proc_mountpoints;
        if (proc_overlay(parsed.mountpoint))
            return EOPNOTSUPP;
        if (parsed.mount_id == expected->mount_id) {
            if (++target_ids != 1)
                return EINVAL;
            selected = parsed;
        }
        offset = end + (end < length ? 1u : 0u);
    }
    if (proc_mountpoints > 1)
        return EINVAL;
    if (target_ids != 1 || selected.dev_major != expected->dev_major ||
        selected.dev_minor != expected->dev_minor ||
        !span_equal(selected.root, "/") ||
        !span_equal(selected.mountpoint, "/proc") ||
        !span_equal(selected.fs_type, "proc"))
        return EOPNOTSUPP;
    if (selected.hidepid_count > 1)
        return EINVAL;
    if (!selected.hidepid_supported)
        return EOPNOTSUPP;
    return 0;
}
