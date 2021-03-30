#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * C interface for 'wedpr_ktb_hdk_create_master_key_en'.
 */
char *wedpr_ktb_hdk_create_master_key_en(char *password_cstring, char *mnemonic_cstring);

/**
 * C interface for 'wedpr_ktb_hdk_create_mnemonic_en'.
 */
char *wedpr_ktb_hdk_create_mnemonic_en(unsigned char word_count);

/**
 * C interface for 'wedpr_ktb_hdk_derive_extended_key'.
 */
char *wedpr_ktb_hdk_derive_extended_key(char *master_key_cstring,
                                    int purpose_type,
                                    int asset_type,
                                    int account,
                                    int change,
                                    int address_index);
