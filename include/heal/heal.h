#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <inttypes.h>

typedef enum {
	HEAL_OK,
	HEAL_OUT_OF_MEMORY,
	HEAL_INVALID_PARAMETERS,
	HEAL_IV_CONTEXT_INVALID,
	HEAL_IV_BACKEND_INVALID,
	HEAL_IV_SECURITY_INVALID,
	HEAL_IV_P_MODULUS_MUST_BE_1_MOD_2_TIMES_DEGREE,
} heal_err;

typedef enum {
	HEAL_IV_BACKEND_NONE,
	HEAL_IV_BACKEND_SEAL_BFV,
	HEAL_IV_BACKEND_PALISADE_BGV,
	HEAL_IV_BACKEND_PALISADE_BFV_HPS,
	HEAL_IV_BACKEND_PALISADE_BFV_BEHZ,
	HEAL_IV_BACKEND_HELIB_BGV,
} heal_iv_backend;

// this will give enough space for maximum modulus of about 60*32 = 1920 bits.
#define HEAL_IV_MAX_RNS_BASIS_SIZE 32

typedef struct heal_iv_context_ *heal_iv_context;

typedef struct {
	heal_iv_backend backend;
	size_t degree;
	size_t security;
	int64_t p_modulus;
	int64_t q_modulus[HEAL_IV_MAX_RNS_BASIS_SIZE];
	// double sigma; // should always be 3.2
} heal_iv_params;

heal_err heal_iv_params_validate(const heal_iv_params params);

// macro trickery to increase readability of arguments
#define heal_iv_context_init(ctx, ...) \
	heal_iv_context_init_(ctx, (struct heal_iv_params){ \
		.backend = HEAL_IV_BACKEND_NONE, \
		.degree = 0, \
		.p_modulus = 0, \
		.security = 128, \
		.sigma = 3.2, \
		__VA_ARGS__ \
	})

// we require params.security = 0 to use a specific q_modulus
heal_err heal_iv_context_init_(heal_iv_context *ctx, const heal_iv_params params);

#if 0
typedef enum {
	Public,
	Relinearize,
	KeySwitch,
	Automorphism
} heal_public_key_kind;

int heal_generate_secret_key(heal_backend *be, heal_secret_key *key);
int heal_generate_public_key(heal_backend *be, heal_public_key *pkey, heal_secret_key *skey);
int heal_generate_evaluation_key(heal_backend *be, heal_evaluation_key *ekey, heal_secret_key *skey);

int heal_load_secret_key(heal_backend *be, heal_secret_key *key);
int heal_load_public_key(heal_backend *be, heal_public_key *key);
int heal_load_evaluation_key(heal_backend *be, heal_evaluation_key *key);

struct heal_context_init_opts {
	heal_backend backend;
	heal_secret_key secret_key;
	heal_public_key public_key;
	heal_evaluation_key evaluation_key;
};

#define heal_context_init(ctx, ...) \
	heal_context_init_(ctx, (struct heal_context_init_opts){ \
		.backend = NULL, \
		.secret_key = NULL, \
		.public_key = NULL, \
		.evaluation_key = NULL, \
		__VA_ARGS__ \
	})

int heal_context_init_(heal_context *ctx, heal_context_init_opts opts);
int heal_context_fini(heal_context *ctx,)
#endif

#ifdef __cplusplus
}
#endif
