#include <stdlib.h>
#include <string.h>

#include "module-helper.h"

/* copy_lisp_string gives a null terminated string
   i.e. the last byte is not part of lisp string
   (copy_string_contents semantics) */
char *
copy_lisp_string(emacs_env *env, emacs_value s_val)
{
  ptrdiff_t len = 0;
  env->copy_string_contents(env, s_val, NULL, &len);
  if (env->non_local_exit_check(env)) return NULL;

  char *c_str = malloc(len);
  bool ok = env->copy_string_contents(env, s_val, c_str, &len);
  if (!ok || env->non_local_exit_check(env)) {
    free(c_str);
    return NULL;
  }

  return c_str;
}

emacs_value
define_error(emacs_env *env, const char *name, const char *message,
             const char *parent)
{
  if (!name || !message) {
    return el_nil;
  }

  emacs_value Qdeferr = env->intern(env, "define-error"), Qparent;
  if (parent) {
    Qparent = env->intern(env, parent);
  } else {
    Qparent = env->intern(env, "error");
  }
  emacs_value args[] = {env->intern(env, name),
                        env->make_string(env, message, strlen(message)),
                        Qparent};
  return env->funcall(env, Qdeferr, NELEMS(args), args);
}

emacs_value
define_constant(emacs_env *env, const char *name, emacs_value val,
                const char *doc)
{
  if (!name || !doc) {
    return el_nil;
  }

  emacs_value Qeval = env->intern(env, "eval");
  emacs_value Qlist = env->intern(env, "list");
  emacs_value args[] = {env->intern(env, "defconst"), env->intern(env, name),
                        val, env->make_string(env, doc, strlen(doc))};
  return env->funcall(env, Qeval, 1, (emacs_value[1]){env->funcall(
                                         env, Qlist, NELEMS(args), args)});
}

emacs_value
bind_function(emacs_env *env, const char *name, emacs_value fn_val)
{
  if (!name) {
    return el_nil;
  }

  emacs_value args[] = {env->intern(env, name), fn_val};
  env->funcall(env, env->intern(env, "fset"), NELEMS(args), args);
  return args[0];
}

void
provide(emacs_env *env, const char *feature)
{
  if (!feature) {
    return;
  }

  emacs_value args[] = {env->intern(env, feature)};
  env->funcall(env, env->intern(env, "provide"), NELEMS(args), args);
}
