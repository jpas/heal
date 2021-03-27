#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "heal/heal.h"

heal_err heal_iv_context_init_seal_bfv(heal_iv_context *ctx, heal_iv_params params);
heal_err heal_iv_context_fini_seal_bfv(heal_iv_context *ctx);

#ifdef __cplusplus
}
#endif
