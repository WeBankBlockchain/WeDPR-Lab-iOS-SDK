#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * C interface for 'wedpr_scd_blind_certificate_signature'.
 */
char *wedpr_scd_blind_certificate_signature(char *certificate_signature_cstring,
                                            char *attribute_dict_cstring,
                                            char *certificate_template_cstring,
                                            char *user_private_key_cstring,
                                            char *certificate_secrets_blinding_factors_cstring,
                                            char *issuer_nonce_cstring);

/**
 * C interface for 'wedpr_scd_fill_certificate'.
 */
char *wedpr_scd_fill_certificate(char *attribute_dict_cstring, char *certificate_template_cstring);

/**
 * C interface for 'wedpr_scd_get_revealed_attributes'.
 */
char *wedpr_scd_get_revealed_attributes(char *verify_request_cstring);

/**
 * C interface for 'wedpr_scd_get_verification_nonce'.
 */
char *wedpr_scd_get_verification_nonce(void);

/**
 * C interface for 'wedpr_scd_make_certificate_template'.
 */
char *wedpr_scd_make_certificate_template(char *schema_cstring);

/**
 * C interface for 'wedpr_scd_prove_selective_disclosure'.
 */
char *wedpr_scd_prove_selective_disclosure(char *rule_set_cstring,
                                           char *certificate_signature_cstring,
                                           char *attribute_dict_cstring,
                                           char *certificate_template_cstring,
                                           char *user_private_key_cstring,
                                           char *verification_nonce_cstring);

/**
 * C interface for 'wedpr_scd_sign_certificate'.
 */
char *wedpr_scd_sign_certificate(char *certificate_template_cstring,
                                 char *template_private_key_cstring,
                                 char *sign_request_cstring,
                                 char *user_id_cstring,
                                 char *user_nonce_cstring);

/**
 * C interface for 'wedpr_scd_verify_selective_disclosure'.
 */
char *wedpr_scd_verify_selective_disclosure(char *rule_set_cstring, char *verify_request_cstring);
