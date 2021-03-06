/*
 * @file test_parser_xml.c
 * @author: Radek Krejci <rkrejci@cesnet.cz>
 * @brief unit tests for functions from parser_xml.c
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <string.h>

#include "../../src/context.h"
#include "../../src/tree_data_internal.h"

#define BUFSIZE 1024
char logbuf[BUFSIZE] = {0};
int store = -1; /* negative for infinite logging, positive for limited logging */

struct ly_ctx *ctx; /* context for tests */

/* set to 0 to printing error messages to stderr instead of checking them in code */
#define ENABLE_LOGGER_CHECKING 1

#if ENABLE_LOGGER_CHECKING
static void
logger(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    (void) level; /* unused */
    if (store) {
        if (path && path[0]) {
            snprintf(logbuf, BUFSIZE - 1, "%s %s", msg, path);
        } else {
            strncpy(logbuf, msg, BUFSIZE - 1);
        }
        if (store > 0) {
            --store;
        }
    }
}
#endif

static int
setup(void **state)
{
    (void) state; /* unused */

    const char *schema_a = "module a {namespace urn:tests:a;prefix a;yang-version 1.1;"
            "list l1 { key \"a b c\"; leaf a {type string;} leaf b {type string;} leaf c {type string;} leaf d {type string;}}"
            "leaf foo { type string;}"
            "container c { leaf x {type string;}}"
            "container cp {presence \"container switch\"; leaf y {type string;}}"
            "anydata any {config false;} }";

#if ENABLE_LOGGER_CHECKING
    ly_set_log_clb(logger, 1);
#endif

    assert_int_equal(LY_SUCCESS, ly_ctx_new(NULL, 0, &ctx));
    assert_non_null(lys_parse_mem(ctx, schema_a, LYS_IN_YANG));

    return 0;
}

static int
teardown(void **state)
{
#if ENABLE_LOGGER_CHECKING
    if (*state) {
        fprintf(stderr, "%s\n", logbuf);
    }
#else
    (void) state; /* unused */
#endif

    ly_ctx_destroy(ctx, NULL);
    ctx = NULL;

    return 0;
}

void
logbuf_clean(void)
{
    logbuf[0] = '\0';
}

#if ENABLE_LOGGER_CHECKING
#   define logbuf_assert(str) assert_string_equal(logbuf, str)
#else
#   define logbuf_assert(str)
#endif

static void
test_leaf(void **state)
{
    *state = test_leaf;

    const char *data = "<foo xmlns=\"urn:tests:a\">foo value</foo>";
    struct lyd_node *tree;
    struct lyd_node_term *leaf;

    assert_int_equal(LY_SUCCESS, lyd_parse_xml(ctx, data, 0, NULL, &tree));
    assert_non_null(tree);
    assert_int_equal(LYS_LEAF, tree->schema->nodetype);
    assert_string_equal("foo", tree->schema->name);
    leaf = (struct lyd_node_term*)tree;
    assert_string_equal("foo value", leaf->value.canonized);

    lyd_free_all(tree);
    *state = NULL;
}

static void
test_anydata(void **state)
{
    *state = test_anydata;

    const char *data = "<any xmlns=\"urn:tests:a\">"
                         "<element1><x:element2 x:attr2=\"test\" xmlns:x=\"urn:x\">x:data</x:element2></element1><element1a/>"
                       "</any>";
    struct lyd_node *tree;
    struct lyd_node_any *any;

    assert_int_equal(LY_SUCCESS, lyd_parse_xml(ctx, data, 0, NULL, &tree));
    assert_non_null(tree);
    assert_int_equal(LYS_ANYDATA, tree->schema->nodetype);
    assert_string_equal("any", tree->schema->name);
    any = (struct lyd_node_any*)tree;
    assert_int_equal(LYD_ANYDATA_XML, any->value_type);
    assert_string_equal("<element1><x:element2 x:attr2=\"test\" xmlns:x=\"urn:x\">x:data</x:element2></element1><element1a/>", any->value.xml);

    lyd_free_all(tree);
    *state = NULL;
}

static void
test_list(void **state)
{
    *state = test_list;

    const char *data = "<l1 xmlns=\"urn:tests:a\"><a>one</a><b>one</b><c>one</c></l1>";
    struct lyd_node *tree, *iter;
    struct lyd_node_inner *list;
    struct lyd_node_term *leaf;

    /* check hashes */
    assert_int_equal(LY_SUCCESS, lyd_parse_xml(ctx, data, 0, NULL, &tree));
    assert_non_null(tree);
    assert_int_equal(LYS_LIST, tree->schema->nodetype);
    assert_string_equal("l1", tree->schema->name);
    list = (struct lyd_node_inner*)tree;
    LY_LIST_FOR(list->child, iter) {
        assert_int_not_equal(0, iter->hash);
    }
    lyd_free_all(tree);

    /* keys order */
    data = "<l1 xmlns=\"urn:tests:a\"><d>d</d><a>a</a><c>c</c><b>b</b></l1>";
    assert_int_equal(LY_SUCCESS, lyd_parse_xml(ctx, data, 0, NULL, &tree));
    assert_non_null(tree);
    assert_int_equal(LYS_LIST, tree->schema->nodetype);
    assert_string_equal("l1", tree->schema->name);
    list = (struct lyd_node_inner*)tree;
    assert_non_null(leaf = (struct lyd_node_term*)list->child);
    assert_string_equal("a", leaf->schema->name);
    assert_non_null(leaf = (struct lyd_node_term*)leaf->next);
    assert_string_equal("b", leaf->schema->name);
    assert_non_null(leaf = (struct lyd_node_term*)leaf->next);
    assert_string_equal("c", leaf->schema->name);
    assert_non_null(leaf = (struct lyd_node_term*)leaf->next);
    assert_string_equal("d", leaf->schema->name);
    logbuf_assert("Invalid position of the key \"b\" in a list.");
    lyd_free_all(tree);

    data = "<l1 xmlns=\"urn:tests:a\"><c>c</c><b>b</b><a>a</a></l1>";
    assert_int_equal(LY_SUCCESS, lyd_parse_xml(ctx, data, 0, NULL, &tree));
    assert_non_null(tree);
    assert_int_equal(LYS_LIST, tree->schema->nodetype);
    assert_string_equal("l1", tree->schema->name);
    list = (struct lyd_node_inner*)tree;
    assert_non_null(leaf = (struct lyd_node_term*)list->child);
    assert_string_equal("a", leaf->schema->name);
    assert_non_null(leaf = (struct lyd_node_term*)leaf->next);
    assert_string_equal("b", leaf->schema->name);
    assert_non_null(leaf = (struct lyd_node_term*)leaf->next);
    assert_string_equal("c", leaf->schema->name);
    logbuf_assert("Invalid position of the key \"a\" in a list.");
    logbuf_clean();
    lyd_free_all(tree);

    assert_int_equal(LY_EVALID, lyd_parse_xml(ctx, data, LYD_OPT_STRICT, NULL, &tree));
    logbuf_assert("Invalid position of the key \"b\" in a list. Line number 1.");
/* TODO validation
    data = "<l1 xmlns=\"urn:tests:a\"><a>a</a><c>c</c><d>d</d></l1>";
    assert_int_equal(LY_EVALID, lyd_parse_xml(ctx, data, LYD_OPT_STRICT, NULL, &tree));
    logbuf_assert("Missing key \"b\" in a list. Line number 1.");
*/

    *state = NULL;
}

static void
test_container(void **state)
{
    *state = test_container;

    const char *data = "<c xmlns=\"urn:tests:a\"/>";
    struct lyd_node *tree;
    struct lyd_node_inner *cont;

    assert_int_equal(LY_SUCCESS, lyd_parse_xml(ctx, data, 0, NULL, &tree));
    assert_non_null(tree);
    assert_int_equal(LYS_CONTAINER, tree->schema->nodetype);
    assert_string_equal("c", tree->schema->name);
    cont = (struct lyd_node_inner*)tree;
    assert_true(cont->flags & LYD_DEFAULT);
    lyd_free_all(tree);

    data = "<cp xmlns=\"urn:tests:a\"/>";
    assert_int_equal(LY_SUCCESS, lyd_parse_xml(ctx, data, 0, NULL, &tree));
    assert_non_null(tree);
    assert_int_equal(LYS_CONTAINER, tree->schema->nodetype);
    assert_string_equal("cp", tree->schema->name);
    cont = (struct lyd_node_inner*)tree;
    assert_false(cont->flags & LYD_DEFAULT);
    lyd_free_all(tree);

    *state = NULL;
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_leaf, setup, teardown),
        cmocka_unit_test_setup_teardown(test_anydata, setup, teardown),
        cmocka_unit_test_setup_teardown(test_list, setup, teardown),
        cmocka_unit_test_setup_teardown(test_container, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
