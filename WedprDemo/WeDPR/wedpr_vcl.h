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
 * C interface for 'com.webank.wedpr.vcl.NativeInterface->makeCredit'.
 */
char *wedpr_vcl_makeCredit(unsigned long value);

/**
 * C interface for proveProductBalance'.
 */
char *wedpr_vcl_proveProductBalance(char *c1_secret_cstring,
                                    char *c2_secret_cstring,
                                    char *c3_secret_cstring);

/**
 * C interface for 'proveRange'.
 */
char *wedpr_vcl_proveRange(char *secret_cstring);

/**
 * C interface for 'proveSumBalance'.
 */
char *wedpr_vcl_proveSumBalance(char *c1_secret_cstring,
                                char *c2_secret_cstring,
                                char *c3_secret_cstring);

/**
 * C interface for verifyProductBalance'.
 */
int8_t wedpr_vcl_verifyProductBalance(char *c1_credit_cstring,
                                      char *c2_credit_cstring,
                                      char *c3_credit_cstring,
                                      char *proof_cstring);

/**
 * C interface for 'verifyRange'.
 */
int8_t wedpr_vcl_verifyRange(char *credit_cstring, char *proof_cstring);

/**
 * C interface for 'verifySumBalance'.
 */
int8_t wedpr_vcl_verifySumBalance(char *c1_credit_cstring,
                                  char *c2_credit_cstring,
                                  char *c3_credit_cstring,
                                  char *proof_cstring);
