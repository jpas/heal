#include "heal/heal.h"

#include "seal.h"

#if 0
he_err
he_iv_context_init_(he_iv_context *ctx, he_iv_params params)
{
	if (ctx == NULL) {
		return HE_IV_CONTEXT_INVALID;
	}

	he_err err = he_iv_params_validate(params);
	if (err != HE_OK) {
		return err;
	}

	switch (params.backend) {
	case HE_IV_BACKEND_SEAL_BFV:
		return he_iv_context_init_seal_bfv(ctx, params);
	default:
		return HE_IV_CONTEXT_INVALID;
	}
}
#endif
