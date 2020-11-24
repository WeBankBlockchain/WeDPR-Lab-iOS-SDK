#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * C interface for 'wedpr_blind_credential_signature'.
 */
char *wedpr_blind_credential_signature(char *credential_signature_cstring,
                                       char *credential_info_cstring,
                                       char *credential_template_cstring,
                                       char *master_secret_cstring,
                                       char *credential_secrets_blinding_factors_cstring,
                                       char *nonce_credential_cstring);

/**
 * C interface for 'wedpr_get_revealed_attrs_from_verification_request'.
 */
char *wedpr_get_revealed_attrs_from_verification_request(char *verification_request_cstring);

/**
 * C interface for 'wedpr_sign_credential'.
 */
char *wedpr_make_credential(char *credential_info_cstring, char *credential_template_cstring);

/**
 * C interface for 'wedpr_make_credential_template'.
 */
char *wedpr_make_credential_template(char *attribute_template_cstring);

/**
 * C interface for 'wedpr_prove_credential_info'.
 */
char *wedpr_prove_credential_info(char *verification_predicate_rule_cstring,
                                  char *credential_signature_cstring,
                                  char *credential_info_cstring,
                                  char *credential_template_cstring,
                                  char *master_secret_cstring);

/**
 * C interface for 'wedpr_sign_credential'.
 */
char *wedpr_sign_credential(char *credential_template_cstring,
                            char *template_secret_key_cstring,
                            char *credential_request_cstring,
                            char *user_id_cstring,
                            char *nonce_cstring);

/**
 * C interface for 'wedpr_verify_proof'.
 */
char *wedpr_verify_proof(char *verification_predicate_rule_cstring,
                         char *verification_request_cstring);
