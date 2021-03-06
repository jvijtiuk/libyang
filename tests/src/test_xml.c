/*
 * @file xml.c
 * @author: Radek Krejci <rkrejci@cesnet.cz>
 * @brief unit tests for functions from xml.c
 *
 * Copyright (c) 2018 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../../src/xml.h"

LY_ERR lyxml_ns_add(struct lyxml_context *context, const char *prefix, size_t prefix_len, char *uri);
LY_ERR lyxml_ns_rm(struct lyxml_context *context);

#define BUFSIZE 1024
char logbuf[BUFSIZE] = {0};

/* set to 0 to printing error messages to stderr instead of checking them in code */
#define ENABLE_LOGGER_CHECKING 1

static void
logger(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    (void) level; /* unused */

    if (path) {
        snprintf(logbuf, BUFSIZE - 1, "%s %s", msg, path);
    } else {
        strncpy(logbuf, msg, BUFSIZE - 1);
    }
}

static int
logger_setup(void **state)
{
    (void) state; /* unused */
#if ENABLE_LOGGER_CHECKING
    ly_set_log_clb(logger, 1);
#endif
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
test_element(void **state)
{
    (void) state; /* unused */

    size_t name_len, prefix_len;
    size_t buf_len, len;
    const char *name, *prefix;
    char *buf = NULL, *out = NULL;
    const char *str, *p;
    int dynamic;

    struct lyxml_context ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.line = 1;

    /* empty */
    str = "";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_null(name);
    assert_int_equal(LYXML_END, ctx.status);
    assert_true(str[0] == '\0');
    ctx.status = 0;

    /* end element */
    str = "</element>";
    assert_int_equal(LY_EVALID, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    logbuf_assert("Opening and closing elements tag missmatch (\"element\"). Line number 1.");

    /* no element */
    logbuf_clean();
    str = p = "no data present";
    assert_int_equal(LY_EINVAL, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_null(name);
    assert_ptr_equal(p, str); /* input data not eaten */
    logbuf_assert("");

    /* not supported DOCTYPE */
    str = p = "<!DOCTYPE greeting SYSTEM \"hello.dtd\"><greeting/>";
    assert_int_equal(LY_EVALID, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_null(name);
    assert_ptr_equal(p, str); /* input data not eaten */
    logbuf_assert("Document Type Declaration not supported. Line number 1.");

    /* invalid XML */
    str = p = "<!NONSENCE/>";
    assert_int_equal(LY_EVALID, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_null(name);
    assert_ptr_equal(p, str); /* input data not eaten */
    logbuf_assert("Unknown XML section \"<!NONSENCE/>\". Line number 1.");

    /* unqualified element */
    str = "  <  element/>";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_null(prefix);
    assert_false(strncmp("element", name, name_len));
    assert_int_equal(7, name_len);
    assert_int_equal(LYXML_END, ctx.status);
    assert_string_equal("", str);
    assert_int_equal(0, ctx.elements.count);
    lyxml_context_clear(&ctx);

    str = "  <  element attr=\'x\'/>";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_int_equal(LYXML_ATTRIBUTE, ctx.status);
    assert_string_equal("attr=\'x\'/>", str);
    assert_int_equal(1, ctx.elements.count);
    assert_int_equal(LY_SUCCESS, lyxml_get_attribute(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_int_equal(LYXML_ATTR_CONTENT, ctx.status);
    assert_string_equal("\'x\'/>", str);
    assert_int_equal(1, ctx.elements.count);
    assert_int_equal(LY_SUCCESS, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    assert_int_equal(LYXML_END, ctx.status);
    assert_string_equal("", str);
    assert_int_equal(0, ctx.elements.count);
    lyxml_context_clear(&ctx);

    str = "<?xml version=\"1.0\"?>  <!-- comment --> <![CDATA[<greeting>Hello, world!</greeting>]]> <?TEST xxx?> <element/>";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_null(prefix);
    assert_false(strncmp("element", name, name_len));
    assert_int_equal(7, name_len);
    assert_int_equal(LYXML_END, ctx.status);
    assert_string_equal("", str);
    lyxml_context_clear(&ctx);

    str = "<element xmlns=\"urn\"></element>";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_null(prefix);
    assert_false(strncmp("element", name, name_len));
    assert_int_equal(7, name_len);
    assert_int_equal(LYXML_ATTRIBUTE, ctx.status);
    assert_string_equal("xmlns=\"urn\"></element>", str);
    /* cleean context by getting closing tag */
    str += 12;
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    lyxml_context_clear(&ctx);

    /* qualified element */
    str = "  <  yin:element/>";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_false(strncmp("yin", prefix, prefix_len));
    assert_false(strncmp("element", name, name_len));
    assert_int_equal(3, prefix_len);
    assert_int_equal(7, name_len);
    assert_int_equal(LYXML_END, ctx.status);
    assert_string_equal("", str);
    lyxml_context_clear(&ctx);

    str = "<yin:element xmlns=\"urn\"></element>";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_false(strncmp("yin", prefix, prefix_len));
    assert_false(strncmp("element", name, name_len));
    assert_int_equal(3, prefix_len);
    assert_int_equal(7, name_len);
    assert_int_equal(LYXML_ATTRIBUTE, ctx.status);
    assert_string_equal("xmlns=\"urn\"></element>", str);
    /* cleean context by getting closing tag */
    str += 12;
    assert_int_equal(LY_EVALID, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    logbuf_assert("Opening and closing elements tag missmatch (\"element\"). Line number 1.");
    str = "</yin:element/>";
    assert_int_equal(LY_EVALID, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    logbuf_assert("Unexpected data \"/>\" in closing element tag. Line number 1.");
    lyxml_context_clear(&ctx);

    /* UTF8 characters */
    str = "<𠜎€𠜎Øn:𠜎€𠜎Øn/>";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_false(strncmp("𠜎€𠜎Øn", prefix, prefix_len));
    assert_false(strncmp("𠜎€𠜎Øn", name, name_len));
    assert_int_equal(14, prefix_len);
    assert_int_equal(14, name_len);
    assert_int_equal(LYXML_END, ctx.status);
    assert_string_equal("", str);
    lyxml_context_clear(&ctx);

    /* invalid UTF-8 character */
    str = "<¢:element>";
    assert_int_equal(LY_EVALID, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    logbuf_assert("Identifier \"¢:element>\" starts with invalid character. Line number 1.");
    str = "<yin:c⁐element>";
    assert_int_equal(LY_EVALID, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    logbuf_assert("Invalid character sequence \"⁐element>\", expected whitespace or element tag termination ('>' or '/>'. Line number 1.");
    lyxml_context_clear(&ctx);

    /* mixed content */
    str = "<a>text <b>x</b></a>";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_string_equal("text <b>x</b></a>", str);
    assert_int_equal(LYXML_ELEM_CONTENT, ctx.status);
    assert_int_equal(LY_EVALID, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    logbuf_assert("Mixed XML content is not allowed (text <b>). Line number 1.");
    lyxml_context_clear(&ctx);

}

static void
test_attribute(void **state)
{
    (void) state; /* unused */

    size_t name_len, prefix_len;
    const char *name, *prefix;
    const char *str, *p;

    struct lyxml_context ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.line = 1;

    /* empty - without element tag termination */
    str = "";
    assert_int_equal(LY_EVALID, lyxml_get_attribute(&ctx, &str, &prefix, &prefix_len, &name, &name_len));

    /* not an attribute */
    str = p = "unknown/>";
    assert_int_equal(LY_EVALID, lyxml_get_attribute(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_ptr_equal(p, str); /* input data not eaten */
    logbuf_assert("Invalid character sequence \"/>\", expected whitespace or '='. Line number 1.");
    str = p = "unknown />";
    assert_int_equal(LY_EVALID, lyxml_get_attribute(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_ptr_equal(p, str); /* input data not eaten */
    logbuf_assert("Invalid character sequence \"/>\", expected '='. Line number 1.");
    str = p = "xxx=/>";
    assert_int_equal(LY_EVALID, lyxml_get_attribute(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_ptr_equal(p, str); /* input data not eaten */
    logbuf_assert("Invalid character sequence \"/>\", expected either single or double quotation mark. Line number 1.");
    str = p = "xxx\n = yyy/>";
    assert_int_equal(LY_EVALID, lyxml_get_attribute(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_ptr_equal(p, str); /* input data not eaten */
    logbuf_assert("Invalid character sequence \"yyy/>\", expected either single or double quotation mark. Line number 2.");

    /* valid attribute */
    str = "xmlns=\"urn\">";
    assert_int_equal(LY_SUCCESS, lyxml_get_attribute(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_null(name);
    assert_null(prefix);
    assert_int_equal(0, name_len);
    assert_int_equal(0, prefix_len);
    assert_int_equal(1, ctx.ns.count);
    assert_string_equal("", str);
    assert_int_equal(LYXML_ELEM_CONTENT, ctx.status);

    str = "xmlns:nc\n = \'urn\'>";
    assert_int_equal(LY_SUCCESS, lyxml_get_attribute(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_null(name);
    assert_null(prefix);
    assert_int_equal(0, name_len);
    assert_int_equal(0, prefix_len);
    assert_int_equal(3, ctx.line);
    assert_int_equal(2, ctx.ns.count);
    assert_string_equal("", str);
    assert_int_equal(LYXML_ELEM_CONTENT, ctx.status);

    lyxml_context_clear(&ctx);
}

static void
test_text(void **state)
{
    (void) state; /* unused */

    size_t buf_len, len;
    int dynamic;
    const char *str, *p;
    char *buf = NULL, *out = NULL;
    const char *prefix, *name;
    size_t prefix_len, name_len;

    struct lyxml_context ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.line = 1;

    /* empty attribute value */
    ctx.status = LYXML_ATTR_CONTENT;
    str = "\"\"";
    assert_int_equal(LY_SUCCESS, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    assert_null(buf);
    assert_ptr_equal(&str[-1], out);
    assert_int_equal(0, dynamic);
    assert_int_equal(0, len);
    assert_true(str[0] == '\0'); /* everything eaten */
    assert_int_equal(LYXML_ATTRIBUTE, ctx.status);

    ctx.status = LYXML_ATTR_CONTENT;
    str = "\'\'";
    assert_int_equal(LY_SUCCESS, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    assert_null(buf);
    assert_ptr_equal(&str[-1], out);
    assert_int_equal(0, dynamic);
    assert_int_equal(0, len);
    assert_true(str[0] == '\0'); /* everything eaten */
    assert_int_equal(LYXML_ATTRIBUTE, ctx.status);

    /* empty element content - only formating before defining child */
    ctx.status = LYXML_ELEM_CONTENT;
    str = "<x>\n  <y>";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_int_equal(LY_EINVAL, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    assert_null(buf);
    assert_string_equal("<y>", str);
    lyxml_context_clear(&ctx);

    /* empty element content is invalid - missing content terminating character < */
    ctx.status = LYXML_ELEM_CONTENT;
    str = "";
    assert_int_equal(LY_EVALID, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    assert_null(buf);
    logbuf_assert("Unexpected end-of-input. Line number 2.");

    ctx.status = LYXML_ELEM_CONTENT;
    str = p = "xxx";
    assert_int_equal(LY_EVALID, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    assert_null(buf);
    logbuf_assert("Unexpected end-of-input. Line number 2.");
    assert_ptr_equal(p, str); /* input data not eaten */

    /* valid strings */
    ctx.status = LYXML_ELEM_CONTENT;
    str = "<a>€𠜎Øn \n&lt;&amp;&quot;&apos;&gt; &#82;&#x4f;&#x4B;</a>";
    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &str, &prefix, &prefix_len, &name, &name_len));
    assert_int_equal(LY_SUCCESS, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    assert_int_not_equal(0, dynamic);
    assert_non_null(buf);
    assert_ptr_equal(out, buf);
    assert_int_equal(22, buf_len);
    assert_int_equal(21, len);
    assert_string_equal("€𠜎Øn \n<&\"\'> ROK", buf);
    assert_string_equal("</a>", str);
    assert_int_equal(LYXML_ELEMENT, ctx.status);
    lyxml_context_clear(&ctx);

    /* test using n-bytes UTF8 hexadecimal code points */
    ctx.status = LYXML_ATTR_CONTENT;
    str = "\'&#x0024;&#x00A2;&#x20ac;&#x10348;\'";
    assert_int_equal(LY_SUCCESS, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    assert_int_not_equal(0, dynamic);
    assert_non_null(buf);
    assert_ptr_equal(out, buf);
    assert_int_equal(22, buf_len);
    assert_int_equal(10, len);
    assert_string_equal("$¢€𐍈", buf);
    assert_int_equal(LYXML_ATTRIBUTE, ctx.status);

    free(buf);
    buf = NULL;

    /* invalid characters in string */
    ctx.status = LYXML_ATTR_CONTENT;
    str = p = "\'&#x52\'";
    assert_int_equal(LY_EVALID, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    logbuf_assert("Invalid character sequence \"'\", expected ;. Line number 3.");
    assert_null(buf);
    assert_ptr_equal(p, str); /* input data not eaten */
    ctx.status = LYXML_ATTR_CONTENT;
    str = p = "\"&#82\"";
    assert_int_equal(LY_EVALID, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    logbuf_assert("Invalid character sequence \"\"\", expected ;. Line number 3.");
    assert_null(buf);
    assert_ptr_equal(p, str); /* input data not eaten */
    ctx.status = LYXML_ATTR_CONTENT;
    str = p = "\"&nonsence;\"";
    assert_int_equal(LY_EVALID, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    logbuf_assert("Entity reference \"&nonsence;\" not supported, only predefined references allowed. Line number 3.");
    assert_null(buf);
    assert_ptr_equal(p, str); /* input data not eaten */
    ctx.status = LYXML_ELEM_CONTENT;
    str = p = "&#o122;";
    assert_int_equal(LY_EVALID, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    logbuf_assert("Invalid character reference \"&#o122;\". Line number 3.");
    assert_null(buf);
    assert_ptr_equal(p, str); /* input data not eaten */

    ctx.status = LYXML_ATTR_CONTENT;
    str = p = "\'&#x06;\'";
    assert_int_equal(LY_EVALID, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    logbuf_assert("Invalid character reference \"&#x06;\'\" (0x00000006). Line number 3.");
    assert_null(buf);
    assert_ptr_equal(p, str); /* input data not eaten */
    ctx.status = LYXML_ATTR_CONTENT;
    str = p = "\'&#xfdd0;\'";
    assert_int_equal(LY_EVALID, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    logbuf_assert("Invalid character reference \"&#xfdd0;\'\" (0x0000fdd0). Line number 3.");
    assert_null(buf);
    assert_ptr_equal(p, str); /* input data not eaten */
    ctx.status = LYXML_ATTR_CONTENT;
    str = p = "\'&#xffff;\'";
    assert_int_equal(LY_EVALID, lyxml_get_string(&ctx, &str, &buf, &buf_len, &out, &len, &dynamic));
    logbuf_assert("Invalid character reference \"&#xffff;\'\" (0x0000ffff). Line number 3.");
    assert_null(buf);
    assert_ptr_equal(p, str); /* input data not eaten */
}

static void
test_ns(void **state)
{
    (void) state; /* unused */

    const struct lyxml_ns *ns;

    struct lyxml_context ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.line = 1;

    /* simulate adding open element1 into context */
    ctx.elements.count++;
    /* processing namespace definitions */
    assert_int_equal(LY_SUCCESS, lyxml_ns_add(&ctx, NULL, 0, strdup("urn:default")));
    assert_int_equal(LY_SUCCESS, lyxml_ns_add(&ctx, "nc", 2, strdup("urn:nc1")));
    /* simulate adding open element2 into context */
    ctx.elements.count++;
    /* processing namespace definitions */
    assert_int_equal(LY_SUCCESS, lyxml_ns_add(&ctx, "nc", 2, strdup("urn:nc2")));
    assert_int_equal(3, ctx.ns.count);
    assert_int_not_equal(0, ctx.ns.size);

    ns = lyxml_ns_get(&ctx, NULL, 0);
    assert_non_null(ns);
    assert_null(ns->prefix);
    assert_string_equal("urn:default", ns->uri);

    ns = lyxml_ns_get(&ctx, "nc", 2);
    assert_non_null(ns);
    assert_string_equal("nc", ns->prefix);
    assert_string_equal("urn:nc2", ns->uri);

    /* simulate closing element2 */
    ctx.elements.count--;
    lyxml_ns_rm(&ctx);
    assert_int_equal(2, ctx.ns.count);

    ns = lyxml_ns_get(&ctx, "nc", 2);
    assert_non_null(ns);
    assert_string_equal("nc", ns->prefix);
    assert_string_equal("urn:nc1", ns->uri);

    /* simulate closing element1 */
    ctx.elements.count--;
    lyxml_ns_rm(&ctx);
    assert_int_equal(0, ctx.ns.count);

    assert_null(lyxml_ns_get(&ctx, "nc", 2));
    assert_null(lyxml_ns_get(&ctx, NULL, 0));
}

static void
test_ns2(void **state)
{
    (void) state; /* unused */

    struct lyxml_context ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.line = 1;

    /* simulate adding open element1 into context */
    ctx.elements.count++;
    /* default namespace defined in parent element1 */
    assert_int_equal(LY_SUCCESS, lyxml_ns_add(&ctx, NULL, 0, strdup("urn:default")));
    assert_int_equal(1, ctx.ns.count);
    /* going into child element1 */
    /* simulate adding open element1 into context */
    ctx.elements.count++;
    /* no namespace defined, going out (first, simulate closing of so far open element) */
    ctx.elements.count--;
    lyxml_ns_rm(&ctx);
    assert_int_equal(1, ctx.ns.count);
    /* nothing else, going out of the parent element1 (first, simulate closing of so far open element) */
    ctx.elements.count--;
    lyxml_ns_rm(&ctx);
    assert_int_equal(0, ctx.ns.count);
}

static void
test_simple_xml(void **state)
{
    (void)state; /* unused */
    size_t name_len, prefix_len;
    const char *prefix, *name;
    struct lyxml_context ctx;

    char *buf = NULL, *output = NULL;
    size_t buf_size, length;
    int dynamic;
    const char *test_input = "<elem1 attr1=\"value\"> <elem2 attr2=\"value\" /> </elem1>";

    memset(&ctx, 0, sizeof ctx);
    ctx.line = 1;

    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &test_input, &prefix, &prefix_len, &name, &name_len));
    assert_int_equal(ctx.status, LYXML_ATTRIBUTE);
    assert_string_equal(test_input, "attr1=\"value\"> <elem2 attr2=\"value\" /> </elem1>");

    assert_int_equal(LY_SUCCESS, lyxml_get_attribute(&ctx, &test_input, &prefix, &prefix_len, &name, &name_len));
    assert_int_equal(ctx.status, LYXML_ATTR_CONTENT);
    assert_string_equal(test_input, "\"value\"> <elem2 attr2=\"value\" /> </elem1>");

    assert_int_equal(LY_SUCCESS, lyxml_get_string(&ctx, &test_input, &buf, &buf_size, &output, &length, &dynamic));
    assert_int_equal(ctx.status, LYXML_ELEM_CONTENT);
    assert_string_equal(test_input, " <elem2 attr2=\"value\" /> </elem1>");

    /* try to get string content of elem1 whitespace is removed and EINVAL is expected in this case as well as moving status from element
     * content to the element */
    assert_int_equal(LY_EINVAL, lyxml_get_string(&ctx, &test_input, &buf, &buf_size, &output, &length, &dynamic));
    assert_int_equal(ctx.status, LYXML_ELEMENT);
    assert_string_equal(test_input, "<elem2 attr2=\"value\" /> </elem1>");

    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &test_input, &prefix, &prefix_len, &name, &name_len));
    assert_int_equal(ctx.status, LYXML_ATTRIBUTE);
    assert_string_equal(test_input, "attr2=\"value\" /> </elem1>");

    assert_int_equal(LY_SUCCESS, lyxml_get_attribute(&ctx, &test_input, &prefix, &prefix_len, &name, &name_len));
    assert_int_equal(ctx.status, LYXML_ATTR_CONTENT);
    assert_string_equal(test_input, "\"value\" /> </elem1>");

    assert_int_equal(LY_SUCCESS, lyxml_get_string(&ctx, &test_input, &buf, &buf_size, &output, &length, &dynamic));
    assert_int_equal(ctx.status, LYXML_ELEMENT);
    assert_string_equal(test_input, " </elem1>");

    assert_int_equal(LY_SUCCESS, lyxml_get_element(&ctx, &test_input, &prefix, &prefix_len, &name, &name_len));
    assert_int_equal(ctx.status, LYXML_END);
    assert_string_equal(test_input, "");

    lyxml_context_clear(&ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_element, logger_setup),
        cmocka_unit_test_setup(test_attribute, logger_setup),
        cmocka_unit_test_setup(test_text, logger_setup),
        cmocka_unit_test_setup(test_ns, logger_setup),
        cmocka_unit_test_setup(test_ns2, logger_setup),
        cmocka_unit_test_setup(test_simple_xml, logger_setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
