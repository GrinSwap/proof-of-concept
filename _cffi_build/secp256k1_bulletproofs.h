typedef struct secp256k1_bulletproof_generators secp256k1_bulletproof_generators;

#define SECP256K1_BULLETPROOF_MAX_DEPTH ...
#define SECP256K1_BULLETPROOF_MAX_PROOF ...

secp256k1_bulletproof_generators *secp256k1_bulletproof_generators_create(
    const secp256k1_context* ctx,
    const secp256k1_generator *blinding_gen,
    size_t n
);

void secp256k1_bulletproof_generators_destroy(
    const secp256k1_context* ctx,
    secp256k1_bulletproof_generators *gen
);

int secp256k1_bulletproof_rangeproof_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators *gens,
    const unsigned char* proof,
    size_t plen,
    const uint64_t* min_value,
    const secp256k1_pedersen_commitment* commit,
    size_t n_commits,
    size_t nbits,
    const secp256k1_generator* value_gen,
    const unsigned char* extra_commit,
    size_t extra_commit_len
);

int secp256k1_bulletproof_rangeproof_verify_multi(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators *gens,
    const unsigned char* const* proof,
    size_t n_proofs,
    size_t plen,
    const uint64_t* const* min_value,
    const secp256k1_pedersen_commitment* const* commit,
    size_t n_commits,
    size_t nbits,
    const secp256k1_generator* value_gen,
    const unsigned char* const* extra_commit,
    size_t *extra_commit_len
);

int secp256k1_bulletproof_rangeproof_rewind(
    const secp256k1_context* ctx,
    const secp256k1_bulletproof_generators* gens,
    uint64_t* value,
    unsigned char* blind,
    const unsigned char* proof,
    size_t plen,
    uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const secp256k1_generator* value_gen,
    const unsigned char* nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len
);

int secp256k1_bulletproof_rangeproof_prove(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators *gens,
    unsigned char* proof,
    size_t* plen,
    const uint64_t *value,
    const uint64_t *min_value,
    const unsigned char* const* blind,
    size_t n_commits,
    const secp256k1_generator* value_gen,
    size_t nbits,
    const unsigned char* nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len
);

void secp256k1_bulletproof_rangeproof_1(
    const secp256k1_context* ctx,
    const secp256k1_bulletproof_generators* gens,
    secp256k1_pubkey* t_one,
    secp256k1_pubkey* t_two,
    const unsigned char* nonce
);

int secp256k1_bulletproof_rangeproof_2(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators* gens,
    unsigned char* tauxc,
    const secp256k1_pubkey* t_one,
    const secp256k1_pubkey* t_two,
    const uint64_t* value,
    const uint64_t* min_value,
    const unsigned char* const* blind,
    const secp256k1_pubkey* const* commit,
    size_t n_commits,
    const secp256k1_generator* value_gen,
    size_t nbits,
    const unsigned char* nonce,
    const unsigned char* common_nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len
);

int secp256k1_bulletproof_rangeproof_3(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators* gens,
    unsigned char* proof,
    size_t* plen,
    const unsigned char* tauxc,
    const secp256k1_pubkey* t_one,
    const secp256k1_pubkey* t_two,
    const uint64_t* value,
    const uint64_t* min_value,
    const unsigned char* const* blind,
    const secp256k1_pubkey* const* commit,
    size_t n_commits,
    const secp256k1_generator* value_gen,
    size_t nbits,
    const unsigned char* nonce,
    const unsigned char* common_nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len
);