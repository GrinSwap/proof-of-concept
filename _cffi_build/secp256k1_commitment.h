typedef struct {
    unsigned char data[64];
} secp256k1_pedersen_commitment;

int secp256k1_pedersen_commitment_parse(
    const secp256k1_context* ctx,
    secp256k1_pedersen_commitment* commit,
    const unsigned char *input
);

int secp256k1_pedersen_commitment_serialize(
    const secp256k1_context* ctx,
    unsigned char *output,
    const secp256k1_pedersen_commitment* commit
);

int secp256k1_pedersen_commit(
  const secp256k1_context* ctx,
  secp256k1_pedersen_commitment *commit,
  const unsigned char *blind,
  uint64_t value,
  const secp256k1_generator *value_gen,
  const secp256k1_generator *blind_gen
);

int secp256k1_pedersen_blind_sum(
  const secp256k1_context* ctx,
  unsigned char *blind_out,
  const unsigned char * const *blinds,
  size_t n,
  size_t npositive
);

int secp256k1_pedersen_commit_sum(
  const secp256k1_context* ctx,
  secp256k1_pedersen_commitment *commit_out,
  const secp256k1_pedersen_commitment * const* commits,
  size_t pcnt,
  const secp256k1_pedersen_commitment * const* ncommits,
  size_t ncnt
);

int secp256k1_pedersen_verify_tally(
  const secp256k1_context* ctx,
  const secp256k1_pedersen_commitment * const* pos,
  size_t n_pos,
  const secp256k1_pedersen_commitment * const* neg,
  size_t n_neg
);

int secp256k1_pedersen_blind_generator_blind_sum(
  const secp256k1_context* ctx,
  const uint64_t *value,
  const unsigned char* const* generator_blind,
  unsigned char* const* blinding_factor,
  size_t n_total,
  size_t n_inputs
);

int secp256k1_pedersen_commitment_to_pubkey(
  const secp256k1_context* ctx,
  secp256k1_pubkey* pubkey,
  const secp256k1_pedersen_commitment* commit
);