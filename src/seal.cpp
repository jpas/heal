#include <seal/seal.h>

extern "C" {

#include "heal/heal.h"
#include "seal.h"

struct heal_iv_context_ {
	heal_iv_backend backend;
	seal::EncryptionParameters *params;
	seal::SEALContext *context;
	seal::BatchEncoder *encoder;
};

heal_err
heal_iv_context_init_seal_bfv(heal_iv_context *ctx, heal_iv_params params)
{
	heal_err ret = HEAL_OK;

	if (ctx == nullptr) {
		return HEAL_IV_CONTEXT_INVALID;
	}

	if (params.backend != HEAL_IV_BACKEND_SEAL_BFV) {
		return HEAL_IV_BACKEND_INVALID;
	}

	struct heal_iv_context_ *impl = new (std::nothrow) struct heal_iv_context_;
	if (impl == nullptr) {
		return HEAL_OUT_OF_MEMORY;
	}

	impl->params = new (std::nothrow) seal::EncryptionParameters(seal::scheme_type::bfv);
	if (impl->params == nullptr) {
		ret = HEAL_OUT_OF_MEMORY;
		goto out_delete_impl;
	}

	try {
		seal::EncryptionParameters *p = impl->params;
		p->set_poly_modulus_degree(params.degree);
		p->set_coeff_modulus(seal::CoeffModulus::BFVDefault(params.degree));
		p->set_plain_modulus(params.p_modulus);
	} catch (...) {
		// XXX(jpas): Yes, catch everything, we do not want to leak exceptions to
		// the C wrapper.
		ret = HEAL_INVALID_PARAMETERS;
		goto out_delete_params;
	}

	impl->context = new (std::nothrow) seal::SEALContext(*impl->params);
	if (impl->context == nullptr) {
		ret = HEAL_OUT_OF_MEMORY;
		goto out_delete_params;
	}

	impl->encoder = new (std::nothrow) seal::BatchEncoder(*impl->context);
	if (impl->encoder == nullptr) {
		ret = HEAL_OUT_OF_MEMORY;
		goto out_delete_context;
	}

	*ctx = impl;
	goto out;

out_delete_context:
	delete impl->context;
out_delete_params:
	delete impl->params;
out_delete_impl:
	delete impl;
out:
	return ret;
}

heal_err
heal_iv_context_fini_seal_bfv(heal_iv_context *ctx)
{
	if (ctx == nullptr) {
		return HEAL_OK;
	};

	struct heal_iv_context_ *impl = *ctx;
	if (impl == nullptr) {
		return HEAL_OK;
	}

	if (impl->backend != HEAL_IV_BACKEND_SEAL_BFV) {
		return HEAL_IV_BACKEND_INVALID;
	}

	delete impl->encoder;
	delete impl->context;
	delete impl->params;
	delete impl;
	*ctx = nullptr;

	return HEAL_OK;
}

} // extern "C"
