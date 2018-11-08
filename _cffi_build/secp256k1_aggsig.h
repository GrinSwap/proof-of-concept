typedef struct secp256k1_aggsig_context_struct secp256k1_aggsig_context;

typedef struct {
    unsigned char data[32];
} secp256k1_aggsig_partial_signature;

secp256k1_aggsig_context* secp256k1_aggsig_context_create(
    const secp256k1_context *ctx,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys,
    const unsigned char *seed
);

void secp256k1_aggsig_context_destroy(
    secp256k1_aggsig_context *aggctx
);

int secp256k1_aggsig_generate_nonce(
    const secp256k1_context* ctx,
    secp256k1_aggsig_context* aggctx,
    size_t index
);

int secp256k1_aggsig_export_secnonce_single(
    const secp256k1_context* ctx,
    unsigned char* secnonce32,
    const unsigned char* seed
);

int secp256k1_aggsig_sign_single(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const unsigned char *seckey32,
    const unsigned char* secnonce32,
    const unsigned char* extra32,
    const secp256k1_pubkey *pubnonce_for_e,
    const secp256k1_pubkey* pubnonce_total,
    const secp256k1_pubkey* pubkey_for_e,
    const unsigned char* seed
);

int secp256k1_aggsig_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_aggsig_context* aggctx,
    secp256k1_aggsig_partial_signature *partial,
    const unsigned char *msg32,
    const unsigned char *seckey32,
    size_t index
);

int secp256k1_aggsig_combine_signatures(
    const secp256k1_context* ctx,
    secp256k1_aggsig_context* aggctx,
    unsigned char *sig64,
    const secp256k1_aggsig_partial_signature *partial,
    size_t n_sigs
);

int secp256k1_aggsig_add_signatures_single(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char** sigs,
    size_t num_sigs,
    const secp256k1_pubkey* pubnonce_total
);

int secp256k1_aggsig_verify_single(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubnonce,
    const secp256k1_pubkey *pubkey,
    const secp256k1_pubkey *pubkey_total,
    const secp256k1_pubkey *extra_pubkey,
    const int is_partial
);

int secp256k1_aggsig_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys
);

int secp256k1_aggsig_build_scratch_and_verify(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys
);
