#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * C interface for 'wedpr_secp256k1_ecies_encrypt'.
 */
char *wedpr_secp256k1_ecies_encrypt(char *encoded_public_key, char *encoded_plaintext);

/**
 * C interface for 'wedpr_secp256k1_ecies_decrypt'.
 */
char *wedpr_secp256k1_ecies_decrypt(char *encoded_private_key, char *encoded_ciphertext);

/**
 * C interface for 'wedpr_secp256k1_gen_key_pair'.
 */
char *wedpr_secp256k1_gen_key_pair(void);

/**
 * C interface for 'wedpr_secp256k1_sign'.
 */
char *wedpr_secp256k1_sign(char *encoded_private_key, char *encoded_message_hash);

/**
 * C interface for 'wedpr_secp256k1_verify'.
 */
int8_t wedpr_secp256k1_verify(char *encoded_public_key,
                              char *encoded_message_hash,
                              char *encoded_signature);

/**
 * C interface for 'wedpr_keccak256_hash'.
 */
char *wedpr_keccak256_hash(char *encoded_message);
