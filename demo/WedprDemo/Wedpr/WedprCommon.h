#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct backtrace_state backtrace_state;

typedef void (*backtrace_error_callback)(void *data, const char *msg, int errnum);

typedef void (*backtrace_syminfo_callback)(void *data, uintptr_t pc, const char *symname, uintptr_t symval, uintptr_t symsize);

typedef int (*backtrace_full_callback)(void *data, uintptr_t pc, const char *filename, int lineno, const char *function);

backtrace_state *__rbt_backtrace_create_state(const char *_filename,
                                              int _threaded,
                                              backtrace_error_callback _error,
                                              void *_data);

int __rbt_backtrace_syminfo(backtrace_state *_state,
                            uintptr_t _addr,
                            backtrace_syminfo_callback _cb,
                            backtrace_error_callback _error,
                            void *_data);

int __rbt_backtrace_pcinfo(backtrace_state *_state,
                           uintptr_t _addr,
                           backtrace_full_callback _cb,
                           backtrace_error_callback _error,
                           void *_data);
