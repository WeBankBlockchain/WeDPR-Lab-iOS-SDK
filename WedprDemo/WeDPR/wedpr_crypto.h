#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct backtrace_state backtrace_state;

typedef void (*backtrace_error_callback)(void *data, const char *msg, int errnum);

typedef int (*backtrace_full_callback)(void *data, uintptr_t pc, const char *filename, int lineno, const char *function);

typedef void (*backtrace_syminfo_callback)(void *data, uintptr_t pc, const char *symname, uintptr_t symval, uintptr_t symsize);

backtrace_state *__rbt_backtrace_create_state(const char *_filename,
                                              int _threaded,
                                              backtrace_error_callback _error,
                                              void *_data);

int __rbt_backtrace_pcinfo(backtrace_state *_state,
                           uintptr_t _addr,
                           backtrace_full_callback _cb,
                           backtrace_error_callback _error,
                           void *_data);

int __rbt_backtrace_syminfo(backtrace_state *_state,
                            uintptr_t _addr,
                            backtrace_syminfo_callback _cb,
                            backtrace_error_callback _error,
                            void *_data);

/**
 * C interface for 'wedpr_keccak256_hash'.
 */
char *wedpr_keccak256_hash(char *encoded_message);

/**
 * C interface for 'wedpr_secp256k1_ecies_decrypt'.
 */
char *wedpr_secp256k1_ecies_decrypt(char *encoded_private_key, char *encoded_ciphertext);

/**
 * C interface for 'wedpr_secp256k1_ecies_encrypt'.
 */
char *wedpr_secp256k1_ecies_encrypt(char *encoded_public_key, char *encoded_plaintext);

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
