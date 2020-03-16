#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "libyang.h"

int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len)
{
	struct lys_module *mod = NULL;
	struct lys_parser_ctx *context = NULL;
	struct ly_ctx *ctx = NULL;
	static bool log = false; 
	LY_ERR err;
	
	if (!log) {
		ly_log_options(0);
		log = true;
	}

	err = ly_ctx_new(NULL, 0, &ctx);
	if (err != LY_SUCCESS) {
		fprintf(stderr, "Failed to create new context\n");
		return 0;
	}

	mod = calloc(1, sizeof *mod);
	if (mod == NULL) {
		fprintf(stderr, "Out of memory\n");
		return 0;
	}
	mod->ctx = ctx;

	yang_parse_module(&context, data, mod);
	ly_ctx_destroy(ctx, NULL);
	return 0;
}
