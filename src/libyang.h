/**
 * @file libyang.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief The main libyang public header.
 *
 * Copyright (c) 2015 - 2018 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef LY_LIBYANG_H_
#define LY_LIBYANG_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "log.h"
#include "set.h"
#include "dict.h"
#include "context.h"
#include "tree.h"
#include "tree_data.h"
#include "tree_schema.h"
#include "printer_schema.h"
#include "printer_data.h"
#include "plugins_types.h"

/**
 * @mainpage About
 *
 * libyang is a library implementing processing of the YANG schemas and data modeled by the YANG language. The
 * library is implemented in C for GNU/Linux and provides C API.
 *
 * @section about-features Main Features
 *
 * - [Parsing (and validating) schemas](@ref howtoschemasparsers) in YANG format.
 * - [Parsing (and validating) schemas](@ref howtoschemasparsers) in YIN format.
 * - [Parsing, validating and printing instance data](@ref howtodata) in XML format.
 * - [Parsing, validating and printing instance data](@ref howtodata) in JSON format
 *   ([RFC 7951](https://tools.ietf.org/html/rfc7951)).
 * - [Manipulation with the instance data](@ref howtodatamanipulators).
 * - Support for [default values in the instance data](@ref howtodatawd) ([RFC 6243](https://tools.ietf.org/html/rfc6243)).
 * - Support for [YANG extensions and user types](@ref howtoschemaplugins).
 * - Support for [YANG Metadata](@ref howtoschemametadata) ([RFC 7952](https://tools.ietf.org/html/rfc6243)).
 *
 * The current implementation covers YANG 1.0 ([RFC 6020](https://tools.ietf.org/html/rfc6020)) as well as
 * YANG 1.1 ([RFC 7950](https://tools.ietf.org/html/rfc7950)).
 *
 * @section about-license License
 *
 * Copyright (c) 2015-2017 CESNET, z.s.p.o.
 *
 * (The BSD 3-Clause License)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 */

/**
 * @page howto How To ...
 *
 * - @subpage howtocontext
 * - @subpage howtoschemas
 * - @subpage howtodata
 * - @subpage howtoxpath
 * - @subpage howtoxml
 * - @subpage howtothreads
 * - @subpage howtologger
 * - @subpage howtostructures
 */

/**
 * @page howtostructures Data Structures
 *
 * @section sizedarrays Sized Arrays
 *
 * The structure starts with 32bit number storing size of the array - the number of the items inside. The size is part of the
 * array to have it allocated together with the array itself only when it is needed. However, the pointers to the array always
 * points after the 32b number, so items can be accessed directly as for standard C arrays. Because of a known size (available
 * via ::LY_ARRAY_SIZE macro), it is not terminated by any special byte (sequence), so there is also no limitation for specific
 * content of the stored records (e.g. that first byte must not be NULL).
 *
 * The sized arrays must be carefully freed (which should be done anyway only internally), since pointers to the sized arrays used
 * in libyang structures, does not point to the beginning of the allocated space.
 *
 * - ::LY_ARRAY_SIZE
 * - ::LY_ARRAY_FOR
 *
 * @section struct_lists Lists
 *
 * The lists are structures connected via a `next` pointer. Iterating over the siblings can be simply done by ::LY_LIST_FOR macro.
 */

#ifdef __cplusplus
}
#endif

#endif /* LY_LIBYANG_H_ */
