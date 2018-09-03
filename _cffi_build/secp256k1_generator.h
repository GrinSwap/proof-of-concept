typedef struct {
    unsigned char data[33];
} secp256k1_generator;

int secp256k1_generator_parse(
    const secp256k1_context* ctx,
    secp256k1_generator* commit,
    const unsigned char *input
);

int secp256k1_generator_serialize(
    const secp256k1_context* ctx,
    unsigned char *output,
    const secp256k1_generator* commit
);

int secp256k1_generator_generate(
    const secp256k1_context* ctx,
    secp256k1_generator* gen,
    const unsigned char *seed32
);

int secp256k1_generator_generate_blinded(
    const secp256k1_context* ctx,
    secp256k1_generator* gen,
    const unsigned char *key32,
    const unsigned char *blind32
);
