/**
 * @file plugin_types.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief Built-in types plugins and interface for user types plugins.
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#include "common.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plugins_types.h"
#include "dict.h"
#include "tree_schema.h"
#include "tree_schema_internal.h"
#include "xpath.h"

API LY_ERR
ly_type_parse_int(const char *datatype, int base, int64_t min, int64_t max, const char *value, size_t value_len, int64_t *ret, struct ly_err_item **err)
{
    char *errmsg = NULL;

    LY_CHECK_ARG_RET(NULL, err, datatype, LY_EINVAL);

    /* consume leading whitespaces */
    for (;value_len && isspace(*value); ++value, --value_len);

    if (!value || !value[0] || !value_len) {
        asprintf(&errmsg, "Invalid empty %s value.", datatype);
        goto error;
    }

    switch(ly_parse_int(value, value_len, min, max, base, ret)) {
    case LY_EDENIED:
        asprintf(&errmsg, "Value is out of %s's min/max bounds.", datatype);
        goto error;
    case LY_SUCCESS:
        return LY_SUCCESS;
    default:
        asprintf(&errmsg, "Invalid %s value \"%.*s\".", datatype, (int)value_len, value);
        goto error;
    }

error:
    *err = ly_err_new(LY_LLERR, LY_EINVAL, LYVE_RESTRICTION, errmsg, NULL, NULL);
    return LY_EVALID;
}

API LY_ERR
ly_type_parse_uint(const char *datatype, int base, uint64_t max, const char *value, size_t value_len, uint64_t *ret, struct ly_err_item **err)
{
    char *errmsg = NULL;

    LY_CHECK_ARG_RET(NULL, err, datatype, LY_EINVAL);

    /* consume leading whitespaces */
    for (;value_len && isspace(*value); ++value, --value_len);

    if (!value || !value[0] || !value_len) {
        asprintf(&errmsg, "Invalid empty %s value.", datatype);
        goto error;
    }

    *err = NULL;
    switch(ly_parse_uint(value, value_len, max, base, ret)) {
    case LY_EDENIED:
        asprintf(&errmsg, "Value \"%.*s\" is out of %s's min/max bounds.", (int)value_len, value, datatype);
        goto error;
    case LY_SUCCESS:
        return LY_SUCCESS;
    default:
        asprintf(&errmsg, "Invalid %s value \"%.*s\".", datatype, (int)value_len, value);
        goto error;
    }

error:
    *err = ly_err_new(LY_LLERR, LY_EINVAL, LYVE_RESTRICTION, errmsg, NULL, NULL);
    return LY_EVALID;
}

API LY_ERR
ly_type_parse_dec64(uint8_t fraction_digits, const char *value, size_t value_len, int64_t *ret, struct ly_err_item **err)
{
    LY_ERR rc = LY_EINVAL;
    char *errmsg = NULL;
    char *valcopy = NULL;
    size_t fraction = 0, size, len = 0, trailing_zeros;
    int64_t d;

    /* consume leading whitespaces */
    for (;value_len && isspace(*value); ++value, --value_len);

    /* parse value */
    if (!value_len) {
        errmsg = strdup("Invalid empty decimal64 value.");
        goto error;
    } else if (!isdigit(value[len]) && (value[len] != '-') && (value[len] != '+')) {
        asprintf(&errmsg, "Invalid %lu. character of decimal64 value \"%.*s\".",
                 len + 1, (int)value_len, value);
        goto error;
    }

    if ((value[len] == '-') || (value[len] == '+')) {
        ++len;
    }

    while (len < value_len && isdigit(value[len])) {
        ++len;
    }

    trailing_zeros = 0;
    if (len < value_len && ((value[len] != '.') || !isdigit(value[len + 1]))) {
        goto decimal;
    }
    fraction = len;
    ++len;
    while (len < value_len && isdigit(value[len])) {
        if (value[len] == '0') {
            ++trailing_zeros;
        } else {
            trailing_zeros = 0;
        }
        ++len;
    }
    len = len - trailing_zeros;

decimal:
    if (fraction && (len - 1 - fraction > fraction_digits)) {
        asprintf(&errmsg, "Value \"%.*s\" of decimal64 type exceeds defined number (%u) of fraction digits.", (int)len, value,
                 fraction_digits);
        goto error;
    }
    if (fraction) {
        size = len + (fraction_digits - (len - 1 - fraction));
    } else {
        size = len + fraction_digits + 1;
    }

    if (len + trailing_zeros < value_len) {
        /* consume trailing whitespaces to check that there is nothing after it */
        unsigned long int u;
        for (u = len + trailing_zeros; u < value_len && isspace(value[u]); ++u);
        if (u != value_len) {
            asprintf(&errmsg, "Invalid %lu. character of decimal64 value \"%.*s\".",
                     u + 1, (int)value_len, value);
            goto error;
        }
    }

    /* prepare value string without decimal point to easily parse using standard functions */
    valcopy = malloc(size * sizeof *valcopy);
    if (!valcopy) {
        *err = ly_err_new(LY_LLERR, LY_EMEM, 0, "Memory allocation failed.", NULL, NULL);
        return LY_EMEM;
    }

    valcopy[size - 1] = '\0';
    if (fraction) {
        memcpy(&valcopy[0], &value[0], fraction);
        memcpy(&valcopy[fraction], &value[fraction + 1], len - 1 - (fraction));
        /* add trailing zero characters */
        memset(&valcopy[len - 1], '0', fraction_digits - (len - 1 - fraction));
    } else {
        memcpy(&valcopy[0], &value[0], len);
        /* add trailing zero characters */
        memset(&valcopy[len], '0', fraction_digits);
    }

    rc = ly_type_parse_int("decimal64", 10, INT64_C(-9223372036854775807) - INT64_C(1), INT64_C(9223372036854775807), valcopy, len, &d, err);
    if (!rc && ret) {
        *ret = d;
    }
    free(valcopy);

error:
    if (errmsg) {
        *err = ly_err_new(LY_LLERR, LY_EINVAL, LYVE_RESTRICTION, errmsg, NULL, NULL);
    }
    return rc;
}

API LY_ERR
ly_type_validate_patterns(struct lysc_pattern **patterns, const char *str, size_t str_len, struct ly_err_item **err)
{
    LY_ERR ret = LY_SUCCESS;
    int rc;
    unsigned int u;
    char *errmsg;
    pcre2_match_data *match_data = NULL;

    LY_CHECK_ARG_RET(NULL, str, err, LY_EINVAL);

    LY_ARRAY_FOR(patterns, u) {
        match_data = pcre2_match_data_create_from_pattern(patterns[u]->code, NULL);
        if (!match_data) {
            *err = ly_err_new(LY_LLERR, LY_EMEM, 0, "Memory allocation failed.", NULL, NULL);
            return LY_EMEM;
        }

        rc = pcre2_match(patterns[u]->code, (PCRE2_SPTR)str, str_len, 0, PCRE2_ANCHORED | PCRE2_ENDANCHORED, match_data, NULL);
        if (rc == PCRE2_ERROR_NOMATCH) {
            asprintf(&errmsg, "String \"%.*s\" does not conforms to the %u. pattern restriction of its type.",
                     (int)str_len, str, u + 1);
            *err = ly_err_new(LY_LLERR, LY_ESYS, 0, errmsg, NULL, NULL);
            ret = LY_EVALID;
            goto cleanup;
        } else if (rc < 0) {
            /* error */
            PCRE2_UCHAR pcre2_errmsg[256] = {0};
            pcre2_get_error_message(rc, pcre2_errmsg, 256);
            *err = ly_err_new(LY_LLERR, LY_ESYS, 0, strdup((const char*)pcre2_errmsg), NULL, NULL);
            ret = LY_ESYS;
            goto cleanup;
        }

    cleanup:
        pcre2_match_data_free(match_data);
        if (ret) {
            break;
        }
    }

    return ret;
}

API LY_ERR
ly_type_validate_range(LY_DATA_TYPE basetype, struct lysc_range *range, int64_t value, const char *canonized, struct ly_err_item **err)
{
    unsigned int u;
    char *errmsg = NULL;

    LY_ARRAY_FOR(range->parts, u) {
        if (basetype < LY_TYPE_DEC64) {
            /* unsigned */
            if ((uint64_t)value < range->parts[u].min_u64) {
                if (range->emsg) {
                    errmsg = strdup(range->emsg);
                } else {
                    asprintf(&errmsg, "%s \"%s\" does not satisfy the %s constraint.",
                           (basetype == LY_TYPE_BINARY || basetype == LY_TYPE_STRING) ? "Length" : "Value", canonized,
                           (basetype == LY_TYPE_BINARY || basetype == LY_TYPE_STRING) ? "length" : "range");
                }
                goto error;
            } else if ((uint64_t)value <= range->parts[u].max_u64) {
                /* inside the range */
                return LY_SUCCESS;
            } else if (u == LY_ARRAY_SIZE(range->parts) - 1) {
                /* we have the last range part, so the value is out of bounds */
                if (range->emsg) {
                    errmsg = strdup(range->emsg);
                } else {
                    asprintf(&errmsg, "%s \"%s\" does not satisfy the %s constraint.",
                           (basetype == LY_TYPE_BINARY || basetype == LY_TYPE_STRING) ? "Length" : "Value", canonized,
                           (basetype == LY_TYPE_BINARY || basetype == LY_TYPE_STRING) ? "length" : "range");
                }
                goto error;
            }
        } else {
            /* signed */
            if (value < range->parts[u].min_64) {
                if (range->emsg) {
                    errmsg = strdup(range->emsg);
                } else {
                    asprintf(&errmsg, "Value \"%s\" does not satisfy the range constraint.", canonized);
                }
                goto error;
            } else if (value < range->parts[u].max_64) {
                /* inside the range */
                return LY_SUCCESS;
            } else if (u == LY_ARRAY_SIZE(range->parts) - 1) {
                /* we have the last range part, so the value is out of bounds */
                if (range->emsg) {
                    errmsg = strdup(range->emsg);
                } else {
                    asprintf(&errmsg, "Value \"%s\" does not satisfy the range constraint.", canonized);
                }
                goto error;
            }
        }
    }

    return LY_SUCCESS;

error:
    *err = ly_err_new(LY_LLERR, LY_EVALID, LYVE_RESTRICTION, errmsg, NULL, range->eapptag ? strdup(range->eapptag) : NULL);
    return LY_EVALID;
}

static LY_ERR
ly_type_parse_int_builtin(LY_DATA_TYPE basetype, const char *value, size_t value_len, int options, int64_t *val, struct ly_err_item **err)
{
    switch (basetype) {
    case LY_TYPE_INT8:
        return ly_type_parse_int("int16", (options & LY_TYPE_OPTS_SCHEMA) ? 0 : 10, INT64_C(-128), INT64_C(127), value, value_len, val, err);
    case LY_TYPE_INT16:
        return ly_type_parse_int("int16", (options & LY_TYPE_OPTS_SCHEMA) ? 0 : 10, INT64_C(-32768), INT64_C(32767), value, value_len, val, err);
    case LY_TYPE_INT32:
        return ly_type_parse_int("int32", (options & LY_TYPE_OPTS_SCHEMA) ? 0 : 10,
                         INT64_C(-2147483648), INT64_C(2147483647), value, value_len, val, err);
    case LY_TYPE_INT64:
        return ly_type_parse_int("int64", (options & LY_TYPE_OPTS_SCHEMA) ? 0 : 10,
                         INT64_C(-9223372036854775807) - INT64_C(1), INT64_C(9223372036854775807), value, value_len, val, err);
    default:
        LOGINT(NULL);
        return LY_EINVAL;
    }
}

/**
 * @brief Validate and canonize value of the YANG built-in signed integer types.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_int(struct ly_ctx *ctx, struct lysc_type *type, const char *value, size_t value_len, int options,
                     ly_type_resolve_prefix UNUSED(get_prefix), void *UNUSED(parser),
                     struct lyd_node *UNUSED(context_node), struct lyd_node **UNUSED(trees),
                     const char **canonized, struct ly_err_item **err, void **priv)
{
    LY_ERR ret;
    int64_t i;
    char *str;
    struct lysc_type_num *type_num = (struct lysc_type_num *)type;

    LY_CHECK_RET(ly_type_parse_int_builtin(type->basetype, value, value_len, options, &i, err));
    asprintf(&str, "%"PRId64, i);

    /* range of the number */
    if (type_num->range) {
        LY_CHECK_ERR_RET(ret = ly_type_validate_range(type->basetype, type_num->range, i, str, err), free(str), ret);
    }

    if (options & LY_TYPE_OPTS_CANONIZE) {
        *canonized = lydict_insert_zc(ctx, str);
    } else {
        free(str);
    }

    if (options & LY_TYPE_OPTS_STORE) {
        /* save for the store callback */
        *priv = malloc(sizeof i);
        if (!(*priv)) {
            *err = ly_err_new(LY_LLERR, LY_EMEM, 0, "Memory allocation failed.", NULL, NULL);
            return LY_EMEM;
        }
        *(int64_t*)(*priv) = i;
    }

    if (options & LY_TYPE_OPTS_DYNAMIC) {
        free((char*)value);
    }

    return LY_SUCCESS;
}

/**
 * @brief Store value of the YANG built-in signed integer types.
 *
 * Implementation of the ly_type_store_clb.
 */
static LY_ERR
ly_type_store_int(struct ly_ctx *UNUSED(ctx), struct lysc_type *type, int options,
                  struct lyd_value *value, struct ly_err_item **err, void **priv)
{
    int64_t i;

    if (options & LY_TYPE_OPTS_VALIDATE) {
        /* the value was prepared by ly_type_validate_int() */
        i = *(int64_t*)(*priv);
        free(*priv);
    } else {
        LY_CHECK_RET(ly_type_parse_int_builtin(type->basetype, value->canonized, strlen(value->canonized), options, &i, err));
    }

    /* store the result */
    value->int64 = i;

    return LY_SUCCESS;
}

static LY_ERR
ly_type_parse_uint_builtin(LY_DATA_TYPE basetype, const char *value, size_t value_len, int options, uint64_t *val, struct ly_err_item **err)
{
    switch (basetype) {
    case LY_TYPE_UINT8:
        return ly_type_parse_uint("uint16", (options & LY_TYPE_OPTS_SCHEMA) ? 0 : 10, UINT64_C(255), value, value_len, val, err);
    case LY_TYPE_UINT16:
        return ly_type_parse_uint("uint16", (options & LY_TYPE_OPTS_SCHEMA) ? 0 : 10, UINT64_C(65535), value, value_len, val, err);
    case LY_TYPE_UINT32:
        return ly_type_parse_uint("uint32", (options & LY_TYPE_OPTS_SCHEMA) ? 0 : 10, UINT64_C(4294967295), value, value_len, val, err);
    case LY_TYPE_UINT64:
        return ly_type_parse_uint("uint64", (options & LY_TYPE_OPTS_SCHEMA) ? 0 : 10, UINT64_C(18446744073709551615), value, value_len, val, err);
    default:
        LOGINT(NULL);
        return LY_EINVAL;
    }
}

/**
 * @brief Validate and canonize value of the YANG built-in unsigned integer types.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_uint(struct ly_ctx *ctx, struct lysc_type *type, const char *value, size_t value_len, int options,
                      ly_type_resolve_prefix UNUSED(get_prefix), void *UNUSED(parser),
                      struct lyd_node *UNUSED(context_node), struct lyd_node **UNUSED(trees),
                      const char **canonized, struct ly_err_item **err, void **priv)
{
    LY_ERR ret;
    uint64_t u;
    struct lysc_type_num* type_num = (struct lysc_type_num*)type;
    char *str;

    LY_CHECK_RET(ly_type_parse_uint_builtin(type->basetype, value, value_len, options, &u, err));
    asprintf(&str, "%"PRIu64, u);

    /* range of the number */
    if (type_num->range) {
        LY_CHECK_ERR_RET(ret = ly_type_validate_range(type->basetype, type_num->range, u, str, err), free(str), ret);
    }

    if (options & LY_TYPE_OPTS_CANONIZE) {
        *canonized = lydict_insert_zc(ctx, str);
    } else {
        free(str);
    }

    if (options & LY_TYPE_OPTS_STORE) {
        /* save for the store callback */
        *priv = malloc(sizeof u);
        if (!(*priv)) {
            *err = ly_err_new(LY_LLERR, LY_EMEM, 0, "Memory allocation failed.", NULL, NULL);
            return LY_EMEM;
        }
        *(uint64_t*)(*priv) = u;
    }

    if (options & LY_TYPE_OPTS_DYNAMIC) {
        free((char*)value);
    }

    return LY_SUCCESS;
}

/**
 * @brief Store value of the YANG built-in unsigned integer types.
 *
 * Implementation of the ly_type_store_clb.
 */
static LY_ERR
ly_type_store_uint(struct ly_ctx *UNUSED(ctx), struct lysc_type *type, int options,
                   struct lyd_value *value, struct ly_err_item **err, void **priv)
{
    uint64_t u;

    if (options & LY_TYPE_OPTS_VALIDATE) {
        /* the value was prepared by ly_type_validate_uint() */
        u = *(uint64_t*)(*priv);
        free(*priv);
    } else {
        LY_CHECK_RET(ly_type_parse_uint_builtin(type->basetype, value->canonized, strlen(value->canonized), options, &u, err));
    }

    /* store the result */
    value->uint64 = u;

    return LY_SUCCESS;
}

/**
 * @brief Validate and canonize value of the YANG built-in decimal64 types.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_decimal64(struct ly_ctx *ctx, struct lysc_type *type, const char *value, size_t value_len, int options,
                           ly_type_resolve_prefix UNUSED(get_prefix), void *UNUSED(parser),
                           struct lyd_node *UNUSED(context_node), struct lyd_node **UNUSED(trees),
                           const char **canonized, struct ly_err_item **err, void **priv)
{
    int64_t d;
    struct lysc_type_dec* type_dec = (struct lysc_type_dec*)type;
    char buf[22];

    if (!value || !value[0] || !value_len) {
        *err = ly_err_new(LY_LLERR, LY_EINVAL, LYVE_RESTRICTION, strdup("Invalid empty decimal64 value."), NULL, NULL);
        return LY_EVALID;
    }

    LY_CHECK_RET(ly_type_parse_dec64(type_dec->fraction_digits, value, value_len, &d, err));
    /* prepare canonized value */
    if (d) {
        int count = sprintf(buf, "%"PRId64" ", d);
        if ( (d > 0 && (count - 1) <= type_dec->fraction_digits)
             || (count - 2) <= type_dec->fraction_digits ) {
            /* we have 0. value, print the value with the leading zeros
             * (one for 0. and also keep the correct with of num according
             * to fraction-digits value)
             * for (num<0) - extra character for '-' sign */
            count = sprintf(buf, "%0*"PRId64" ", (d > 0) ? (type_dec->fraction_digits + 1) : (type_dec->fraction_digits + 2), d);
        }
        for (int i = type_dec->fraction_digits, j = 1; i > 0 ; i--) {
            if (j && i > 1 && buf[count - 2] == '0') {
                /* we have trailing zero to skip */
                buf[count - 1] = '\0';
            } else {
                j = 0;
                buf[count - 1] = buf[count - 2];
            }
            count--;
        }
        buf[count - 1] = '.';
    } else {
        /* zero */
        sprintf(buf, "0.0");
    }

    /* range of the number */
    if (type_dec->range) {
        LY_CHECK_RET(ly_type_validate_range(type->basetype, type_dec->range, d, buf, err));
    }

    if (options & LY_TYPE_OPTS_CANONIZE) {
        *canonized = lydict_insert(ctx, buf, strlen(buf));
    }
    if (options & LY_TYPE_OPTS_STORE) {
        /* save for the store callback */
        *priv = malloc(sizeof d);
        if (!(*priv)) {
            *err = ly_err_new(LY_LLERR, LY_EMEM, 0, "Memory allocation failed.", NULL, NULL);
            return LY_EMEM;
        }
        *(int64_t*)(*priv) = d;
    }

    if (options & LY_TYPE_OPTS_DYNAMIC) {
        free((char*)value);
    }

    return LY_SUCCESS;
}

/**
 * @brief Store value of the YANG built-in decimal64 types.
 *
 * Implementation of the ly_type_store_clb.
 */
static LY_ERR
ly_type_store_decimal64(struct ly_ctx *UNUSED(ctx), struct lysc_type *UNUSED(type), int options,
                        struct lyd_value *value, struct ly_err_item **UNUSED(err), void **priv)
{
    int64_t d;

    if (options & LY_TYPE_OPTS_VALIDATE) {
        /* the value was prepared by ly_type_validate_uint() */
        d = *(int64_t*)(*priv);
        free(*priv);
    } else {
        /* TODO if there is usecase for store without validate */
        LOGINT(NULL);
        return LY_EINT;
    }

    /* store the result */
    value->dec64 = d;

    return LY_SUCCESS;
}

/**
 * @brief Validate and canonize value of the YANG built-in binary type.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_binary(struct ly_ctx *ctx, struct lysc_type *type, const char *value, size_t value_len, int options,
                        ly_type_resolve_prefix UNUSED(get_prefix), void *UNUSED(parser),
                        struct lyd_node *UNUSED(context_node), struct lyd_node **UNUSED(trees),
                        const char **canonized, struct ly_err_item **err, void **UNUSED(priv))
{
    size_t start = 0, stop = 0, count = 0, u, termination = 0;
    struct lysc_type_bin *type_bin = (struct lysc_type_bin *)type;
    char *errmsg;

    /* initiate */
    *err = NULL;

    /* validate characters and remember the number of octets for length validation */
    if (value && value_len) {
        /* silently skip leading/trailing whitespaces */
        for (start = 0; (start < value_len) && isspace(value[start]); start++);
        for (stop = value_len - 1; stop > start && isspace(value[stop]); stop--);
        if (start == stop) {
            /* empty string */
            goto finish;
        }

        for (count = 0, u = start; u <= stop; u++) {
            if (value[u] == '\n') {
                /* newline formatting */
                continue;
            }
            count++;

            if ((value[u] < '/' && value[u] != '+') ||
                    (value[u] > '9' && value[u] < 'A') ||
                    (value[u] > 'Z' && value[u] < 'a') || value[u] > 'z') {
                /* non-encoding characters */
                if (value[u] == '=') {
                    /* padding */
                    if (u == stop - 1 && value[stop] == '=') {
                        termination = 2;
                        count++;
                        u++;
                    } else if (u == stop){
                        termination = 1;
                    }
                }
                if (!termination) {
                    /* error */
                    asprintf(&errmsg, "Invalid Base64 character (%c).", value[u]);
                    goto error;
                }
            }
        }
    }

finish:
    if (count & 3) {
        /* base64 length must be multiple of 4 chars */
        errmsg = strdup("Base64 encoded value length must be divisible by 4.");
        goto error;
    }

    /* length of the encoded string */
    if (type_bin->length) {
        char buf[22];
        uint64_t len = ((count / 4) * 3) - termination;
        snprintf(buf, 22, "%"PRIu64, len);
        LY_CHECK_RET(ly_type_validate_range(LY_TYPE_BINARY, type_bin->length, len, buf, err));
    }

    if (options & LY_TYPE_OPTS_CANONIZE) {
        if (start != 0 || stop != value_len) {
            *canonized = lydict_insert_zc(ctx, strndup(&value[start], stop + 1 - start));
        } else if (options & LY_TYPE_OPTS_DYNAMIC) {
            *canonized = lydict_insert_zc(ctx, (char*)value);
            value = NULL;
        } else {
            *canonized = lydict_insert(ctx, value_len ? value : "", value_len);
        }
    }
    if (options & LY_TYPE_OPTS_DYNAMIC) {
        free((char*)value);
    }

    return LY_SUCCESS;

error:
    if (!*err) {
        *err = ly_err_new(LY_LLERR, LY_EVALID, LYVE_RESTRICTION, errmsg, NULL, NULL);
    }
    return (*err)->no;
}

/**
 * @brief Validate value of the YANG built-in string type.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_string(struct ly_ctx *ctx, struct lysc_type *type, const char *value, size_t value_len, int options,
                        ly_type_resolve_prefix UNUSED(get_prefix), void *UNUSED(parser),
                        struct lyd_node *UNUSED(context_node), struct lyd_node **UNUSED(trees),
                        const char **canonized, struct ly_err_item **err, void **UNUSED(priv))
{
    struct lysc_type_str *type_str = (struct lysc_type_str *)type;

    /* length restriction of the string */
    if (type_str->length) {
        char buf[22];
        snprintf(buf, 22, "%lu", value_len);
        LY_CHECK_RET(ly_type_validate_range(LY_TYPE_BINARY, type_str->length, value_len, buf, err));
    }

    /* pattern restrictions */
    LY_CHECK_RET(ly_type_validate_patterns(type_str->patterns, value, value_len, err));

    if (options & LY_TYPE_OPTS_CANONIZE) {
        if (options & LY_TYPE_OPTS_DYNAMIC) {
            *canonized = lydict_insert_zc(ctx, (char*)value);
            value = NULL;
        } else {
            *canonized = lydict_insert(ctx, value_len ? value : "", value_len);
        }
    }

    if (options & LY_TYPE_OPTS_DYNAMIC) {
        free((char*)value);
    }

    return LY_SUCCESS;
}

/**
 * @brief Validate and canonize value of the YANG built-in bits type.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_bits(struct ly_ctx *ctx, struct lysc_type *type, const char *value, size_t value_len, int options,
                      ly_type_resolve_prefix UNUSED(get_prefix), void *UNUSED(parser),
                      struct lyd_node *UNUSED(context_node), struct lyd_node **UNUSED(trees),
                      const char **canonized, struct ly_err_item **err, void **priv)
{
    LY_ERR ret = LY_EVALID;
    size_t item_len;
    const char *item;
    struct ly_set *items = NULL, *items_ordered = NULL;
    size_t buf_size = 0;
    char *buf = NULL;
    size_t index;
    unsigned int u, v;
    char *errmsg = NULL;
    struct lysc_type_bits *type_bits = (struct lysc_type_bits*)type;
    int iscanonical = 1;
    size_t ws_count;
    size_t lws_count; /* leading whitespace count */

    /* remember the present items for further work */
    items = ly_set_new();
    LY_CHECK_RET(!items, LY_EMEM);

    for (index = ws_count = lws_count = 0; index < value_len; index++, ws_count++) {
        if (isspace(value[index])) {
            continue;
        }
        if (index == ws_count) {
            lws_count = ws_count;
        } else if (ws_count > 1) {
            iscanonical = 0;
        }
        ws_count = 0;

        /* start of the item */
        item = &value[index];
        for (item_len = 0; index + item_len < value_len && !isspace(item[item_len]); item_len++);
        LY_ARRAY_FOR(type_bits->bits, u) {
            if (!strncmp(type_bits->bits[u].name, item, item_len) && type_bits->bits[u].name[item_len] == '\0') {
                /* we have the match */
                int inserted;

                /* check that the bit is not disabled */
                LY_ARRAY_FOR(type_bits->bits[u].iffeatures, v) {
                    if (!lysc_iffeature_value(&type_bits->bits[u].iffeatures[v])) {
                        asprintf(&errmsg, "Bit \"%s\" is disabled by its %u. if-feature condition.",
                                 type_bits->bits[u].name, v + 1);
                        goto error;
                    }
                }

                if (iscanonical &&items->count && type_bits->bits[u].position < ((struct lysc_type_bitenum_item*)items->objs[items->count - 1])->position) {
                    iscanonical = 0;
                }
                inserted = ly_set_add(items, &type_bits->bits[u], 0);
                LY_CHECK_ERR_GOTO(inserted == -1, ret = LY_EMEM, error);
                if ((unsigned int)inserted != items->count - 1) {
                    asprintf(&errmsg, "Bit \"%s\" used multiple times.", type_bits->bits[u].name);
                    goto error;
                }
                goto next;
            }
        }
        /* item not found */
        asprintf(&errmsg, "Invalid bit value \"%.*s\".", (int)item_len, item);
        goto error;
next:
        /* remember for canonized form: item + space/termination-byte */
        buf_size += item_len + 1;
        index += item_len;
    }
    /* validation done */

    if (options & LY_TYPE_OPTS_CANONIZE) {
        if (options & LY_TYPE_OPTS_STORE) {
            if (iscanonical) {
                items_ordered = items;
                items = NULL;
            } else {
                items_ordered = ly_set_dup(items, NULL);
                LY_CHECK_ERR_GOTO(!items_ordered, LOGMEM(ctx); ret = LY_EMEM, error);
                items_ordered->count = 0;
            }
        }
        if (iscanonical) {
            if (!ws_count && !lws_count && (options & LY_TYPE_OPTS_DYNAMIC)) {
                *canonized = lydict_insert_zc(ctx, (char*)value);
                value = NULL;
            } else {
                *canonized = lydict_insert(ctx, value_len ? &value[lws_count] : "", value_len - ws_count - lws_count);
            }
        } else {
            buf = malloc(buf_size * sizeof *buf);
            LY_CHECK_ERR_GOTO(!buf, LOGMEM(ctx); ret = LY_EMEM, error);
            index = 0;

            /* generate ordered bits list */
            LY_ARRAY_FOR(type_bits->bits, u) {
                int i = ly_set_contains(items, &type_bits->bits[u]);
                if (i != -1) {
                    int c = sprintf(&buf[index], "%s%s", index ? " " : "", type_bits->bits[u].name);
                    LY_CHECK_ERR_GOTO(c < 0, LOGERR(ctx, LY_ESYS, "sprintf() failed."); ret = LY_ESYS, error);
                    index += c;
                    if (items_ordered) {
                        ly_set_add(items_ordered, &type_bits->bits[u], LY_SET_OPT_USEASLIST);
                    }
                }
            }
            assert(buf_size == index + 1);
            /* termination NULL-byte */
            buf[index] = '\0';

            *canonized = lydict_insert_zc(ctx, buf);
            buf = NULL;
        }
    }

    if (options & LY_TYPE_OPTS_STORE) {
        /* remember the set to store */
        if (items_ordered) {
            *priv = items_ordered;
        } else {
            *priv = items;
            items = NULL;
        }
    }

    if (options & LY_TYPE_OPTS_DYNAMIC) {
        free((char*)value);
    }

    ly_set_free(items, NULL);
    return LY_SUCCESS;
error:
    if (errmsg) {
        *err = ly_err_new(LY_LLERR, LY_EVALID, LYVE_RESTRICTION, errmsg, NULL, NULL);
    }
    ly_set_free(items, NULL);
    ly_set_free(items_ordered, NULL);
    free(buf);
    return ret;
}

/**
 * @brief Store value of the YANG built-in bits type.
 *
 * Implementation of the ly_type_store_clb.
 */
static LY_ERR
ly_type_store_bits(struct ly_ctx *ctx, struct lysc_type *UNUSED(type), int options,
                   struct lyd_value *value, struct ly_err_item **UNUSED(err), void **priv)
{
    LY_ERR ret = LY_SUCCESS;
    struct ly_set *items = NULL;
    unsigned int u;

    if (options & LY_TYPE_OPTS_VALIDATE) {
        /* the value was prepared by ly_type_validate_bits() */
        items = (struct ly_set *)(*priv);
        LY_ARRAY_CREATE_GOTO(ctx, value->bits_items, items->count, ret, cleanup);
        for (u = 0; u < items->count; u++) {
            value->bits_items[u] = items->objs[u];
            LY_ARRAY_INCREMENT(value->bits_items);
        }
    } else {
        /* TODO if there is usecase for store without validate */
        LOGINT(NULL);
        return LY_EINT;
    }

cleanup:
    ly_set_free(items, NULL);
    return ret;
}

/**
 * @brief Free value of the YANG built-in bits type.
 *
 * Implementation of the ly_type_free_clb.
 */
static void
ly_type_free_bits(struct ly_ctx *UNUSED(ctx), struct lysc_type *UNUSED(type), struct lyd_value *value)
{
    LY_ARRAY_FREE(value->bits_items);
    value->bits_items = NULL;
}


/**
 * @brief Validate and canonize value of the YANG built-in enumeration type.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_enum(struct ly_ctx *ctx, struct lysc_type *type, const char *value, size_t value_len, int options,
                      ly_type_resolve_prefix UNUSED(get_prefix), void *UNUSED(parser),
                      struct lyd_node *UNUSED(context_node), struct lyd_node **UNUSED(trees),
                      const char **canonized, struct ly_err_item **err, void **priv)
{
    unsigned int u, v;
    char *errmsg = NULL;
    struct lysc_type_enum *type_enum = (struct lysc_type_enum*)type;

    /* find the matching enumeration value item */
    LY_ARRAY_FOR(type_enum->enums, u) {
        if (!strncmp(type_enum->enums[u].name, value, value_len) && type_enum->enums[u].name[value_len] == '\0') {
            /* we have the match */

            /* check that the enumeration value is not disabled */
            LY_ARRAY_FOR(type_enum->enums[u].iffeatures, v) {
                if (!lysc_iffeature_value(&type_enum->enums[u].iffeatures[v])) {
                    asprintf(&errmsg, "Enumeration \"%s\" is disabled by its %u. if-feature condition.",
                             type_enum->enums[u].name, v + 1);
                    goto error;
                }
            }
            goto match;
        }
    }
    /* enum not found */
    asprintf(&errmsg, "Invalid enumeration value \"%.*s\".", (int)value_len, value);
    goto error;

match:
    /* validation done */
    if (options & LY_TYPE_OPTS_CANONIZE) {
        if (options & LY_TYPE_OPTS_DYNAMIC) {
            *canonized = lydict_insert_zc(ctx, (char*)value);
            value = NULL;
        } else {
            *canonized = lydict_insert(ctx, value_len ? value : "", value_len);
        }
    }

    if (options & LY_TYPE_OPTS_STORE) {
        /* remember the enum definition to store */
        *priv = &type_enum->enums[u];
    }

    if (options & LY_TYPE_OPTS_DYNAMIC) {
        free((char*)value);
    }

    return LY_SUCCESS;

error:
    if (errmsg) {
        *err = ly_err_new(LY_LLERR, LY_EVALID, LYVE_RESTRICTION, errmsg, NULL, NULL);
    }
    return LY_EVALID;
}

/**
 * @brief Store value of the YANG built-in enumeration type.
 *
 * Implementation of the ly_type_store_clb.
 */
static LY_ERR
ly_type_store_enum(struct ly_ctx *UNUSED(ctx), struct lysc_type *UNUSED(type), int options,
                   struct lyd_value *value, struct ly_err_item **UNUSED(err), void **priv)
{
    if (options & LY_TYPE_OPTS_VALIDATE) {
        /* the value was prepared by ly_type_validate_enum() */
        value->enum_item = *priv;
    } else {
        /* TODO if there is usecase for store without validate */
        LOGINT(NULL);
        return LY_EINT;
    }

    return LY_SUCCESS;
}

/**
 * @brief Validate value of the YANG built-in boolean type.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_boolean(struct ly_ctx *ctx, struct lysc_type *UNUSED(type), const char *value, size_t value_len, int options,
                         ly_type_resolve_prefix UNUSED(get_prefix), void *UNUSED(parser),
                         struct lyd_node *UNUSED(context_node), struct lyd_node **UNUSED(trees),
                         const char **canonized, struct ly_err_item **err, void **priv)
{
    int8_t i;

    if (value_len == 4 && !strncmp(value, "true", 4)) {
        i = 1;
    } else if (value_len == 5 && !strncmp(value, "false", 5)) {
        i = 0;
    } else {
        char *errmsg;
        asprintf(&errmsg, "Invalid boolean value \"%.*s\".", (int)value_len, value);
        *err = ly_err_new(LY_LLERR, LY_EVALID, LYVE_RESTRICTION, errmsg, NULL, NULL);
        return LY_EVALID;
    }

    if (options & LY_TYPE_OPTS_CANONIZE) {
        if (i) {
            *canonized = lydict_insert(ctx, "true", 4);
        } else {
            *canonized = lydict_insert(ctx, "false", 5);
        }
    }

    if (options & LY_TYPE_OPTS_STORE) {
        /* save for the store callback */
        *priv = malloc(sizeof i);
        if (!(*priv)) {
            *err = ly_err_new(LY_LLERR, LY_EMEM, 0, "Memory allocation failed.", NULL, NULL);
            return LY_EMEM;
        }
        *(int8_t*)(*priv) = i;
    }

    if (options & LY_TYPE_OPTS_DYNAMIC) {
        free((char*)value);
    }

    return LY_SUCCESS;
}

/**
 * @brief Store value of the YANG built-in boolean type.
 *
 * Implementation of the ly_type_store_clb.
 */
static LY_ERR
ly_type_store_boolean(struct ly_ctx *UNUSED(ctx), struct lysc_type *UNUSED(type), int options,
                   struct lyd_value *value, struct ly_err_item **UNUSED(err), void **priv)
{
    if (options & LY_TYPE_OPTS_VALIDATE) {
        /* the value was prepared by ly_type_validate_enum() */
        value->boolean = *(int8_t*)(*priv);
        free(*priv);
    } else {
        /* TODO if there is usecase for store without validate */
        LOGINT(NULL);
        return LY_EINT;
    }

    return LY_SUCCESS;
}

/**
 * @brief Validate value of the YANG built-in empty type.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_empty(struct ly_ctx *ctx, struct lysc_type *UNUSED(type), const char *value, size_t value_len, int options,
                       ly_type_resolve_prefix UNUSED(get_prefix), void *UNUSED(parser),
                       struct lyd_node *UNUSED(context_node), struct lyd_node **UNUSED(trees),
                       const char **canonized, struct ly_err_item **err, void **UNUSED(priv))
{
    if (value_len) {
        char *errmsg;
        asprintf(&errmsg, "Invalid empty value \"%.*s\".", (int)value_len, value);
        *err = ly_err_new(LY_LLERR, LY_EVALID, LYVE_RESTRICTION, errmsg, NULL, NULL);
        return LY_EVALID;
    }

    if (options & LY_TYPE_OPTS_CANONIZE) {
        *canonized = lydict_insert(ctx, "", 0);
    }
    return LY_SUCCESS;
}

API LY_ERR
ly_type_identity_isderived(struct lysc_ident *base, struct lysc_ident *der)
{
    unsigned int u;

    LY_ARRAY_FOR(base->derived, u) {
        if (der == base->derived[u]) {
            return LY_SUCCESS;
        }
        if (!ly_type_identity_isderived(base->derived[u], der)) {
            return LY_SUCCESS;
        }
    }
    return LY_ENOTFOUND;
}

/**
 * @brief Validate value of the YANG built-in identiytref type.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_identityref(struct ly_ctx *ctx, struct lysc_type *type, const char *value, size_t value_len, int options,
                             ly_type_resolve_prefix get_prefix, void *parser,
                             struct lyd_node *UNUSED(context_node), struct lyd_node **UNUSED(trees),
                             const char **canonized, struct ly_err_item **err, void **priv)
{
    struct lysc_type_identityref *type_ident = (struct lysc_type_identityref *)type;
    const char *id_name, *prefix = value;
    size_t id_len, prefix_len;
    char *errmsg = NULL;
    const struct lys_module *mod;
    unsigned int u;
    struct lysc_ident *ident;

    /* locate prefix if any */
    for (prefix_len = 0; prefix_len < value_len && value[prefix_len] != ':'; ++prefix_len);
    if (prefix_len < value_len) {
        id_name = &value[prefix_len + 1];
        id_len = value_len - (prefix_len + 1);
    } else {
        prefix_len = 0;
        id_name = value;
        id_len = value_len;
    }

    if (!id_len) {
        errmsg = strdup("Invalid empty identityref value.");
        goto error;
    }

    mod = get_prefix(ctx, prefix, prefix_len, parser);
    if (!mod) {
        asprintf(&errmsg, "Invalid identityref \"%.*s\" value - unable to map prefix to YANG schema.", (int)value_len, value);
        goto error;
    }
    LY_ARRAY_FOR(mod->compiled->identities, u) {
        ident = &mod->compiled->identities[u]; /* shortcut */
        if (!strncmp(ident->name, id_name, id_len) && ident->name[id_len] == '\0') {
            /* we have match */
            break;
        }
    }
    if (u == LY_ARRAY_SIZE(mod->compiled->identities)) {
        /* no match */
        asprintf(&errmsg, "Invalid identityref \"%.*s\" value - identity not found.", (int)value_len, value);
        goto error;
    }

    /* check that the identity matches some of the type's base identities */
    LY_ARRAY_FOR(type_ident->bases, u) {
        if (!ly_type_identity_isderived(type_ident->bases[u], ident)) {
            /* we have match */
            break;
        }
    }
    if (u == LY_ARRAY_SIZE(type_ident->bases)) {
        /* no match */
        asprintf(&errmsg, "Invalid identityref \"%.*s\" value - identity not accepted by the type specification.", (int)value_len, value);
        goto error;
    }

    if (options & LY_TYPE_OPTS_CANONIZE) {
        if (id_name == value && (options & LY_TYPE_OPTS_DYNAMIC)) {
            *canonized = lydict_insert_zc(ctx, (char*)value);
            value = NULL;
        } else {
            *canonized = lydict_insert(ctx, id_name, id_len);
        }
    }

    if (options & LY_TYPE_OPTS_STORE) {
        *priv = ident;
    }

    if (options & LY_TYPE_OPTS_DYNAMIC) {
        free((char*)value);
    }

    return LY_SUCCESS;

error:
    *err = ly_err_new(LY_LLERR, LY_EVALID, LYVE_RESTRICTION, errmsg, NULL, NULL);
    return LY_EVALID;
}

/**
 * @brief Store value of the YANG built-in identityref type.
 *
 * Implementation of the ly_type_store_clb.
 */
static LY_ERR
ly_type_store_identityref(struct ly_ctx *UNUSED(ctx), struct lysc_type *UNUSED(type), int options,
                          struct lyd_value *value, struct ly_err_item **UNUSED(err), void **priv)
{
    if (options & LY_TYPE_OPTS_VALIDATE) {
        /* the value was prepared by ly_type_validate_enum() */
        value->ident = *priv;
    } else {
        /* TODO if there is usecase for store without validate */
        LOGINT(NULL);
        return LY_EINT;
    }

    return LY_SUCCESS;
}

/**
 * @brief Validation of instance-identifier - check presence of the specific node in the (data/schema) tree.
 *
 * In the case the instance-identifier type does not require instance (@p require_instance is 0) or the data @p trees
 * are not complete (called in the middle of data parsing), the @p token is checked only to match schema tree.
 * Otherwise, the provided data @p trees are used to find instance of the node specified by the token and @p node_d as
 * its parent.
 *
 * @param[in] ctx libyang context
 * @param[in] orig Complete instance-identifier expression for logging.
 * @param[in] orig_len Length of the @p orig string.
 * @param[in] options [Type plugin options ](@ref plugintypeopts) - only LY_TYPE_OPTS_INCOMPLETE_DATA is used.
 * @param[in] require_instance Flag if the instance-identifier requires presence of an instance in the data tree.
 * If the flag is zero, the data tree is not needed and the @p token is checked only by checking the schema tree.
 * @param[in,out] token Pointer to the specific position inside the @p orig string where the node-identifier starts.
 * The pointer is updated to point after the processed node-identifier.
 * @param[in,out] prefixes [Sized array](@ref sizedarrays) of known mappings between prefix used in the @p orig and modules from the context.
 * @param[in,out] node_s Parent schema node as input, resolved schema node as output. Alternative parameter for @p node_d
 * in case the instance is not available (@p trees are not yet complete) or required.
 * @param[in,out] node_d Parent data node as input, resolved data node instance as output. Alternative parameter for @p node_s
 * in case the instance is required and @p trees are complete.
 * @param[in] get_prefix Callback to resolve (map it to a schema) prefix used in the @p token.
 * @param[in] parser Context data for @p get_prefix callback.
 * @param[in] trees [Sized array](@ref sizedarrays)) of data trees where the data instance is supposed to be present.
 * @param[out] errmsg Error message in case of failure. Function does not log on its own, instead it creates error message. Caller is supposed to
 * free (or store somewhere) the returned message.
 * @return LY_SUCCESS when node found.
 * @return LY_EMEM or LY_EVALID in case of failure or when the node is not present in the schema/data tree.
 */
static LY_ERR
ly_type_validate_instanceid_checknodeid(struct ly_ctx *ctx, const char *orig, size_t orig_len, int options, int require_instance,
                                        const char **token, struct lyd_value_prefix **prefixes,
                                        const struct lysc_node **node_s, const struct lyd_node **node_d,
                                        ly_type_resolve_prefix get_prefix, void *parser, struct lyd_node **trees,
                                        char **errmsg)
{
    const char *id, *prefix;
    size_t id_len, prefix_len;
    const struct lys_module *mod = NULL;
    unsigned int u;
    int present_prefix = 0;

    if (ly_parse_nodeid(token, &prefix, &prefix_len, &id, &id_len)) {
        asprintf(errmsg, "Invalid instance-identifier \"%.*s\" value at character %lu.",
                 (int)orig_len, orig, *token - orig + 1);
        return LY_EVALID;
    }
    if (!prefix || !prefix_len) {
        asprintf(errmsg, "Invalid instance-identifier \"%.*s\" value - all node names (%.*s) MUST be qualified with explicit namespace prefix.",
                 (int)orig_len, orig, (int)id_len + 1, &id[-1]);
        return LY_EVALID;
    }

    /* map prefix to schema module */
    LY_ARRAY_FOR(*prefixes, u) {
        if (!strncmp((*prefixes)[u].prefix, prefix, prefix_len) && (*prefixes)[u].prefix[prefix_len] == '\0') {
            mod = (*prefixes)[u].mod;
            present_prefix = 1;
            break;
        }
    }
    if (!mod && get_prefix) {
        mod = get_prefix(ctx, prefix, prefix_len, parser);
    }
    if (!mod) {
        asprintf(errmsg, "Invalid instance-identifier \"%.*s\" value - unable to map prefix \"%.*s\" to YANG schema.",
                 (int)orig_len, orig, (int)prefix_len, prefix);
        return LY_EVALID;
    }
    if (!present_prefix) {
        /* store the prefix record for later use */
        struct lyd_value_prefix *p;

        *errmsg = strdup("Memory allocation failed.");
        LY_ARRAY_NEW_RET(ctx, *prefixes, p, LY_EMEM);
        free(*errmsg);
        *errmsg = NULL;
        p->mod = mod;
        p->prefix = lydict_insert(ctx, prefix, prefix_len);
    }

    if ((options & LY_TYPE_OPTS_INCOMPLETE_DATA) || !require_instance) {
        /* a) in schema tree */
        *node_s = lys_child(*node_s, mod, id, id_len, 0, 0);
        if (!(*node_s)) {
            asprintf(errmsg, "Invalid instance-identifier \"%.*s\" value - path \"%.*s\" does not exists in the YANG schema.",
                     (int)orig_len, orig, (int)(*token - orig), orig);
            return LY_EVALID;
        }
    } else {
        /* b) in data tree */
        if (*node_d) {
            /* internal node */
            const struct lyd_node *children = lyd_node_children(*node_d);
            if (!children || !(*node_d = lyd_search(children, mod, id, id_len, 0, NULL, 0))) {
                asprintf(errmsg, "Invalid instance-identifier \"%.*s\" value - path \"%.*s\" does not exists in the data tree(s).",
                         (int)orig_len, orig, (int)(*token - orig), orig);
                return LY_EVALID;
            }
        } else {
            /* top-level node */
            LY_ARRAY_FOR(trees, u) {
                *node_d = lyd_search(trees[u], mod, id, id_len, 0, NULL, 0);
                if (*node_d) {
                    break;
                }
            }
            if (!(*node_d)) {
                /* node not found */
                asprintf(errmsg, "Invalid instance-identifier \"%.*s\" value - path \"%.*s\" does not exists in the data tree(s).",
                         (int)orig_len, orig, (int)(*token - orig), orig);
                return LY_EVALID;
            }
        }
    }

    return LY_SUCCESS;
}

/**
 * @brief Validate value of the YANG built-in instance-identifier type.
 *
 * Implementation of the ly_type_validate_clb.
 */
static LY_ERR
ly_type_validate_instanceid(struct ly_ctx *ctx, struct lysc_type *type, const char *value, size_t value_len, int options,
                             ly_type_resolve_prefix get_prefix, void *parser,
                             struct lyd_node *context_node, struct lyd_node **trees,
                             const char **canonized, struct ly_err_item **err, void **priv)
{
    LY_ERR ret = LY_EVALID;
    struct lysc_type_instanceid *type_inst = (struct lysc_type_instanceid *)type;
    const char *id, *prefix, *val, *token;
    size_t id_len, prefix_len, val_len;
    char *errmsg = NULL;
    const struct lysc_node *node_s = NULL;
    const struct lyd_node *node_d = NULL;
    struct lyd_value_prefix *prefixes = NULL;
    unsigned int u;

    if (((struct lyd_node_term*)context_node)->value.prefixes) {
        /* the second run, the first one ended with LY_EINCOMPLETE */
        prefixes = ((struct lyd_node_term*)context_node)->value.prefixes;
        get_prefix = NULL;
    }

    /* parse the value and try to resolve it in:
     * a) schema tree - instance is not required, just check that the path is instantiable
     * b) data tree - instance is required, so find it */
    for(token = value; (size_t)(token - value) < value_len;) {
        if (token[0] == '/') {
            /* node identifier */
            token++;
            if (ly_type_validate_instanceid_checknodeid(ctx, value, value_len, options, type_inst->require_instance,
                                                        &token, &prefixes, &node_s, &node_d, get_prefix, parser, trees, &errmsg)) {
                goto error;
            }

        } else if (token[0] == '[') {
            /* predicate */
            const char *pred_errmsg = NULL;
            const struct lysc_node *key_s = node_s;
            const struct lyd_node *key_d = node_d;

            if (ly_parse_instance_predicate(&token, value_len - (token - value), &prefix, &prefix_len, &id, &id_len, &val, &val_len, &pred_errmsg)) {
                asprintf(&errmsg, "Invalid instance-identifier's predicate (%s).", pred_errmsg);
                goto error;
            }
            if (prefix) {
                /* key-predicate */
                if (ly_type_validate_instanceid_checknodeid(ctx, value, value_len, options, type_inst->require_instance,
                                                            &prefix, &prefixes, &key_s, &key_d, get_prefix, parser, trees, &errmsg)) {
                    goto error;
                }
                if (key_d) {
                    /* TODO check value */
                } else if (key_s) {
                    /* TODO check type of the value with the type of the node */
                } else {
                    LOGINT(ctx);
                    goto error;
                }
            } else if (id) {
                /* TODO leaf-list-predicate */
            } else {
                /* TODO pos predicate */
            }

        } else {
            asprintf(&errmsg, "Invalid instance-identifier \"%.*s\" value - unexpected character %lu.",
                     (int)value_len, value, token - value + 1);
            goto error;
        }
    }

    if ((options & LY_TYPE_OPTS_CANONIZE) && *canonized != value) {
        if (options & LY_TYPE_OPTS_DYNAMIC) {
            *canonized = lydict_insert_zc(ctx, (char*)value);
            value = NULL;
        } else {
            *canonized = lydict_insert(ctx, value, value_len);
        }
    }
#if 0
    if (options & LY_TYPE_OPTS_STORE) {
        *priv = ident;
    }
#endif
    if (options & LY_TYPE_OPTS_DYNAMIC) {
        free((char*)value);
    }

    *priv = prefixes;

    if ((options & LY_TYPE_OPTS_INCOMPLETE_DATA) && type_inst->require_instance) {
        return LY_EINCOMPLETE;
    } else {
        return LY_SUCCESS;
    }

error:
    if (!((struct lyd_node_term*)context_node)->value.prefixes) {
        LY_ARRAY_FOR(prefixes, u) {
            lydict_remove(ctx, prefixes[u].prefix);
        }
        LY_ARRAY_FREE(prefixes);
    }
    *err = ly_err_new(LY_LLERR, LY_EVALID, LYVE_RESTRICTION, errmsg, NULL, NULL);
    return ret;
}


/**
 * @brief Store value of the YANG built-in instance-identifier type.
 *
 * Implementation of the ly_type_store_clb.
 */
static LY_ERR
ly_type_store_instanceid(struct ly_ctx *UNUSED(ctx), struct lysc_type *UNUSED(type), int options,
                         struct lyd_value *value, struct ly_err_item **UNUSED(err), void **priv)
{
    if (options & LY_TYPE_OPTS_VALIDATE) {
        /* the value was prepared by ly_type_validate_enum() */
        value->prefixes = *priv;
    } else {
        /* TODO if there is usecase for store without validate */
        LOGINT(NULL);
        return LY_EINT;
    }

    return LY_SUCCESS;
}

/**
 * @brief Free value of the YANG built-in instance-identifier type.
 *
 * Implementation of the ly_type_free_clb.
 */
static void
ly_type_free_instanceid(struct ly_ctx *ctx, struct lysc_type *UNUSED(type), struct lyd_value *value)
{
    unsigned int u;

    LY_ARRAY_FOR(value->prefixes, u) {
        lydict_remove(ctx, value->prefixes[u].prefix);
    }
    LY_ARRAY_FREE(value->prefixes);
    value->prefixes = NULL;
}

struct lysc_type_plugin ly_builtin_type_plugins[LY_DATA_TYPE_COUNT] = {
    {0}, /* LY_TYPE_UNKNOWN */
    {.type = LY_TYPE_BINARY, .validate = ly_type_validate_binary, .store = NULL, .free = NULL},
    {.type = LY_TYPE_UINT8, .validate = ly_type_validate_uint, .store = ly_type_store_uint, .free = NULL},
    {.type = LY_TYPE_UINT16, .validate = ly_type_validate_uint, .store = ly_type_store_uint, .free = NULL},
    {.type = LY_TYPE_UINT32, .validate = ly_type_validate_uint, .store = ly_type_store_uint, .free = NULL},
    {.type = LY_TYPE_UINT64, .validate = ly_type_validate_uint, .store = ly_type_store_uint, .free = NULL},
    {.type = LY_TYPE_STRING, .validate = ly_type_validate_string, .store = NULL, .free = NULL},
    {.type = LY_TYPE_BITS, .validate = ly_type_validate_bits, .store = ly_type_store_bits, .free = ly_type_free_bits},
    {.type = LY_TYPE_BOOL, .validate = ly_type_validate_boolean, .store = ly_type_store_boolean, .free = NULL},
    {.type = LY_TYPE_DEC64, .validate = ly_type_validate_decimal64, .store = ly_type_store_decimal64, .free = NULL},
    {.type = LY_TYPE_EMPTY, .validate = ly_type_validate_empty, .store = NULL, .free = NULL},
    {.type = LY_TYPE_ENUM, .validate = ly_type_validate_enum, .store = ly_type_store_enum, .free = NULL},
    {.type = LY_TYPE_IDENT, .validate = ly_type_validate_identityref, .store = ly_type_store_identityref, .free = NULL},
    {.type = LY_TYPE_INST, .validate = ly_type_validate_instanceid, .store = ly_type_store_instanceid, .free = ly_type_free_instanceid},
    {0}, /* TODO LY_TYPE_LEAFREF */
    {0}, /* TODO LY_TYPE_UNION */
    {.type = LY_TYPE_INT8, .validate = ly_type_validate_int, .store = ly_type_store_int, .free = NULL},
    {.type = LY_TYPE_INT16, .validate = ly_type_validate_int, .store = ly_type_store_int, .free = NULL},
    {.type = LY_TYPE_INT32, .validate = ly_type_validate_int, .store = ly_type_store_int, .free = NULL},
    {.type = LY_TYPE_INT64, .validate = ly_type_validate_int, .store = ly_type_store_int, .free = NULL},
};
