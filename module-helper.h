#ifndef MODULE_HELPER_H
#define MODULE_HELPER_H

#include <emacs-module.h>

#define NELEMS(a) (sizeof(a) / sizeof((a)[0]))

extern emacs_value el_nil, el_t;

char *copy_lisp_string(emacs_env *env, emacs_value s_val);

emacs_value define_error(emacs_env *env, const char *name, const char *message,
                         const char *parent);
emacs_value define_constant(emacs_env *env, const char *name, emacs_value val,
                            const char *doc);
emacs_value bind_function(emacs_env *env, const char *name, emacs_value fn_val);

void provide(emacs_env *env, const char *feature);

#endif  // MODULE_HELPER_H
