#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * C interface for 'wedpr_vcl_make_credit'.
 */
char *wedpr_vcl_make_credit(unsigned long value);

/**
 * C interface for 'wedpr_vcl_prove_sum_balance'.
 */
char *wedpr_vcl_prove_sum_balance(char *c1_secret_cstring,
                                  char *c2_secret_cstring,
                                  char *c3_secret_cstring);

/**
 * C interface for 'wedpr_vcl_verify_sum_balance'.
 */
int8_t wedpr_vcl_verify_sum_balance(char *c1_credit_cstring,
                                    char *c2_credit_cstring,
                                    char *c3_credit_cstring,
                                    char *proof_cstring);

/**
 * C interface for 'wedpr_vcl_prove_product_balance'.
 */
char *wedpr_vcl_prove_product_balance(char *c1_secret_cstring,
                                      char *c2_secret_cstring,
                                      char *c3_secret_cstring);

/**
 * C interface for 'wedpr_vcl_verify_product_balance'.
 */
int8_t wedpr_vcl_verify_product_balance(char *c1_credit_cstring,
                                        char *c2_credit_cstring,
                                        char *c3_credit_cstring,
                                        char *proof_cstring);

/**
 * C interface for 'wedpr_vcl_prove_range'.
 */
char *wedpr_vcl_prove_range(char *secret_cstring);

/**
 * C interface for 'wedpr_vcl_verify_range'.
 */
int8_t wedpr_vcl_verify_range(char *credit_cstring, char *proof_cstring);
