#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <keyutils.h>
#include <errno.h>
#include <emacs-module.h>

#include "macro-args-iter.h"
#include "module-helper.h"

int plugin_is_GPL_compatible;

enum {
  keyctl_EACCES = EACCES,
  keyctl_EPERM = EPERM,
  keyctl_EINVAL = EINVAL,
  keyctl_EKEYEXPIRED = EKEYEXPIRED,
  keyctl_EKEYREJECTED = EKEYREJECTED,
  keyctl_EKEYREVOKED = EKEYREVOKED,
  keyctl_EOPNOTSUPP = EOPNOTSUPP,
  keyctl_ENOKEY = ENOKEY,
  keyctl_ENOMEM = ENOMEM,
  keyctl_EDQUOT = EDQUOT,
  keyctl_EINTR = EINTR,
  keyctl_ENOTDIR = ENOTDIR
};

#define ERRGROUP "keyctl-errors"
#define ERRLIST                                                   \
  keyctl_EACCES, keyctl_EPERM, keyctl_EINVAL, keyctl_EKEYEXPIRED, \
      keyctl_EKEYREJECTED, keyctl_EKEYREVOKED, keyctl_EOPNOTSUPP, \
      keyctl_ENOKEY, keyctl_ENOMEM, keyctl_EDQUOT, keyctl_EINTR,  \
      keyctl_ENOTDIR

emacs_value el_nil, el_t;

static emacs_value
symbol_of_errno(emacs_env *env, int errv)
{
#define ERRNOTOSYM(ERRNO)           \
  case ERRNO:                       \
    sym = env->intern(env, #ERRNO); \
    break;

  emacs_value sym;
  switch (errv) {
    FOR_EACH(ERRNOTOSYM, ERRLIST)
    default:
      sym = el_nil;
  }
  return sym;
}

static void
signal_error(emacs_env *env, const char *data)
{
  if (symbol_of_errno(env, errno) == el_nil) {
    char *err_str = strerror(errno);
    char *nerr_str = malloc(strlen(err_str) + strlen(data) + 3);
    nerr_str[0] = 0;
    strcat(nerr_str, err_str);
    strcat(nerr_str, ": ");
    strcat(nerr_str, data);
    env->non_local_exit_signal(
        env, env->intern(env, ERRGROUP),
        env->make_string(env, nerr_str, strlen(nerr_str)));
    free(nerr_str);
  } else {
    env->non_local_exit_signal(env, symbol_of_errno(env, errno),
                               env->make_string(env, data, strlen(data)));
  }
}

static emacs_value
add_key_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
  emacs_value ret = el_nil;
  char *type, *descr, *payload;
  if (!(type = copy_lisp_string(env, args[0])) ||
      !(descr = copy_lisp_string(env, args[1])) ||
      !(payload = copy_lisp_string(env, args[2]))) {
    return el_nil;
  }

  ptrdiff_t plen = 0;
  env->copy_string_contents(env, args[2], NULL, &plen);
  key_serial_t keyring = env->extract_integer(env, args[3]);
  if (env->non_local_exit_check(env)) {
    goto cleanup_return;
  }

  /* plen-1 because we don't want to store \0 that is not part of data */
  int key = add_key(type, descr, payload, plen - 1, keyring);
  if (key < 0) {
    signal_error(env, "add_key");
    goto cleanup_return;
  }
  ret = env->make_integer(env, key);

cleanup_return:
  free(type);
  free(descr);
  free(payload);
  return ret;
}

static emacs_value
new_keyring_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
  emacs_value ret = el_nil;
  char *name;
  if (!(name = copy_lisp_string(env, args[0]))) {
    return el_nil;
  }

  key_serial_t dest = env->extract_integer(env, args[1]);
  if (env->non_local_exit_check(env)) {
    goto cleanup_return;
  }

  int keyring = add_key("keyring", name, NULL, 0, dest);
  if (keyring < 0) {
    signal_error(env, "add_key");
    goto cleanup_return;
  }
  ret = env->make_integer(env, keyring);

cleanup_return:
  free(name);
  return ret;
}

static emacs_value
update_key_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
  key_serial_t key = env->extract_integer(env, args[0]);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  char *payload;
  if (!(payload = copy_lisp_string(env, args[1]))) {
    return el_nil;
  }
  ptrdiff_t plen = 0;
  env->copy_string_contents(env, args[1], NULL, &plen);
  int ret = keyctl_update(key, payload, plen - 1);
  free(payload);  // no longer needed
  if (ret < 0) {
    signal_error(env, "keyctl_update");
    return el_nil;
  }
  return el_t;
}

static emacs_value
keyctl_link_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
  key_serial_t key = env->extract_integer(env, args[0]);
  key_serial_t keyring = env->extract_integer(env, args[1]);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  if (keyctl_link(key, keyring) < 0) {
    signal_error(env, "keyctl_link");
    return el_nil;
  }
  return el_t;
}

static emacs_value
keyctl_unlink_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[],
                 void *data)
{
  key_serial_t key = env->extract_integer(env, args[0]);
  key_serial_t keyring = env->extract_integer(env, args[1]);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  if (keyctl_unlink(key, keyring) < 0) {
    signal_error(env, "keyctl_unlink");
    return el_nil;
  }
  return el_t;
}

static emacs_value
keyctl_rdescribe_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[],
                    void *data)
{
  key_serial_t key = env->extract_integer(env, args[0]);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  char *buffer;
  ptrdiff_t len = keyctl_describe_alloc(key, &buffer);
  if (len < 0) {
    signal_error(env, "keyctl_describe");
    return el_nil;
  }
  emacs_value lstr = env->make_string(env, buffer, len);
  free(buffer);
  return lstr;
}

static emacs_value
keyctl_describe_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[],
                   void *data)
{
  emacs_value ret = el_nil;
  key_serial_t key = env->extract_integer(env, args[0]);
  if (env->non_local_exit_check(env)) {
    return ret;
  }

  char *buffer;
  ptrdiff_t len = keyctl_describe_alloc(key, &buffer);
  if (len < 0) {
    signal_error(env, "keyctl_describe");
    return ret;
  }

  uid_t uid;
  gid_t gid;
  key_perm_t perm;
  int tlen, dpos, n;
  n = sscanf(buffer, "%*[^;]%n;%u;%u;%x;%n", &tlen, &uid, &gid, &perm, &dpos);
  if (n != 3) {
    char *err_s = "Unparseable description obtained for key %d";
    emacs_value lisp_str = env->funcall(
        env, env->intern(env, "format"), 2,
        (emacs_value[2]){env->make_string(env, err_s, strlen(err_s)), args[0]});
    env->non_local_exit_signal(env, env->intern(env, ERRGROUP), lisp_str);
    goto cleanup_return;
  }

  emacs_value vargs[] = {
      env->make_string(env, buffer, tlen), env->make_integer(env, uid),
      env->make_integer(env, gid), env->make_integer(env, perm),
      env->make_string(env, buffer + dpos, strlen(buffer) - dpos)};
  ret = env->funcall(env, env->intern(env, "vector"), NELEMS(vargs), vargs);
cleanup_return:
  free(buffer);
  return ret;
}

static emacs_value
keyctl_read_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
  key_serial_t key = env->extract_integer(env, args[0]);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  void *buffer;
  ptrdiff_t len = keyctl_read_alloc(key, &buffer);
  if (len < 0) {
    signal_error(env, "keyctl_read");
    return el_nil;
  }
  emacs_value lstr = env->make_string(env, buffer, len);
  free(buffer);
  return lstr;
}

static emacs_value
keyctl_list_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
  key_serial_t keyring = env->extract_integer(env, args[0]);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  char *buffer;
  int ret = keyctl_describe_alloc(keyring, &buffer);
  if (ret < 0) {
    signal_error(env, "keyctl_describe");
    return el_nil;
  }
  char *sep = strchr(buffer, ';');
  *sep = 0;
  if (strcmp(buffer, "keyring")) {
    char *err_s = "Key Id: %d is not a keyring";
    emacs_value lisp_str = env->funcall(
        env, env->intern(env, "format"), 2,
        (emacs_value[2]){env->make_string(env, err_s, strlen(err_s)), args[0]});
    env->non_local_exit_signal(env, env->intern(env, ERRGROUP), lisp_str);
  }
  free(buffer);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  void *buf;
  ptrdiff_t len = keyctl_read_alloc(keyring, &buf);
  if (len < 0) {
    signal_error(env, "keyctl_read");
    return el_nil;
  }
  len /= sizeof(key_serial_t);
  if (len <= 0) {
    return el_nil;
  }
  key_serial_t *pk = buf;
  emacs_value fargs[len];
  for (int i = 0, j = len; j > 0; i++, j--) {
    fargs[i] = env->make_integer(env, *pk++);
  }
  return env->funcall(env, env->intern(env, "list"), len, fargs);
}

static emacs_value
keyctl_search_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[],
                 void *data)
{
  key_serial_t keyring = env->extract_integer(env, args[0]);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  char *type, *descr;
  if (!(type = copy_lisp_string(env, args[1])) ||
      !(descr = copy_lisp_string(env, args[2]))) {
    return el_nil;
  }

  emacs_value ret = el_nil;
  key_serial_t dest = 0;
  if (nargs == 4) {
    dest = env->extract_integer(env, args[3]);
    if (env->non_local_exit_check(env)) {
      goto cleanup_return;
    }
  }

  key_serial_t found = keyctl_search(keyring, type, descr, dest);
  if (found < 0) {
    signal_error(env, "keyctl_search");
    goto cleanup_return;
  }
  ret = env->make_integer(env, found);

cleanup_return:
  free(type);
  free(descr);
  return ret;
}

static emacs_value
keyctl_clear_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
  key_serial_t keyring = env->extract_integer(env, args[0]);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  if (keyctl_clear(keyring) < 0) {
    signal_error(env, "keyctl_clear");
    return el_nil;
  }
  return el_t;
}

static emacs_value
keyctl_set_timeout_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[],
                      void *data)
{
  key_serial_t keyring = env->extract_integer(env, args[0]);
  unsigned timeout = env->extract_integer(env, args[1]);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  if (keyctl_set_timeout(keyring, timeout) < 0) {
    signal_error(env, "keyctl_set_timeout");
    return el_nil;
  }
  return el_t;
}

static emacs_value
keyctl_revoke_fn(emacs_env *env, ptrdiff_t nargs, emacs_value args[],
                 void *data)
{
  key_serial_t keyring = env->extract_integer(env, args[0]);
  if (env->non_local_exit_check(env)) {
    return el_nil;
  }

  if (keyctl_revoke(keyring) < 0) {
    signal_error(env, "keyctl_revoke");
    return el_nil;
  }
  return el_t;
}

/* TODO: add the rest of the api */
int
emacs_module_init(struct emacs_runtime *ert)
{
#define DEFUN(name, amin, amax, fn, doc, data) \
  bind_function(env, (name),                   \
                env->make_function(env, (amin), (amax), (fn), (doc), (data)));

#define DEFCONSTI(name, ival, doc) \
  define_constant(env, (name), env->make_integer(env, (ival)), (doc));

#define DEFERROR(ERRNO) \
  define_error(env, #ERRNO, strerror(ERRNO), "keyctl-errors");

  emacs_env *env = ert->get_environment(ert);

  el_nil = env->intern(env, "nil");
  el_t = env->intern(env, "t");

  DEFCONSTI("KEY-SPEC-THREAD-KEYRING", KEY_SPEC_THREAD_KEYRING,
            "key ID for thread-specific keyring")
  DEFCONSTI("KEY-SPEC-PROCESS-KEYRING", KEY_SPEC_PROCESS_KEYRING,
            "key ID for process-specific keyring")
  DEFCONSTI("KEY-SPEC-SESSION-KEYRING", KEY_SPEC_SESSION_KEYRING,
            "key ID for session-specific keyring")
  DEFCONSTI("KEY-SPEC-USER-SESSION-KEYRING", KEY_SPEC_USER_SESSION_KEYRING,
            "key ID for UID-session keyring")
  DEFCONSTI("KEY-SPEC-USER-KEYRING", KEY_SPEC_USER_KEYRING,
            "key ID for UID-specific keyring")
  DEFCONSTI("KEY-SPEC-GROUP-KEYRING", KEY_SPEC_GROUP_KEYRING,
            "key ID for GID-specific keyring")

  define_error(env, "keyctl-errors", "keyctl error", NULL);
  FOR_EACH(DEFERROR, ERRLIST)

  DEFUN("keyctl~add-key", 4, 4, add_key_fn,
        "(keyctl~add-key type description payload keyring)\n\n"
        "Asks the kernel to create or update a key of the given type and "
        "description, instantiate it with the payload and to "
        "attach it to the nominated keyring and to return its serial number.",
        NULL)
  DEFUN("keyctl~new-keyring", 2, 2, new_keyring_fn,
        "(keyctl~new-keyring name keyring)\n\n"
        "creates a new keyring of the specified name and attaches it to the "
        "specified keyring.\nReturns the ID of the new keyring.",
        NULL)
  DEFUN("keyctl~update-key", 2, 2, update_key_fn,
        "(keyctl~update-key keyID payload)\n\n"
        "Replaces the data attached to a key with a new set of data. Returns "
        "nil if unsuccessful.",
        NULL)
  DEFUN("keyctl~link", 2, 2, keyctl_link_fn,
        "(keyctl~link key keyring)\n\n"
        "Makes a link from the key to the keyring if there's enough capacity "
        "to do so.\nReturns nil if unsuccessful.",
        NULL)
  DEFUN("keyctl~unlink", 2, 2, keyctl_unlink_fn,
        "(keyctl~unlink key keyring)\n\n"
        "Removes a link to the key from the keyring."
        "\nReturns nil if unsuccessful.",
        NULL)
  DEFUN("keyctl~rdescribe", 1, 1, keyctl_rdescribe_fn,
        "(keyctl~rdescribe keyID)\n\n"
        "Returns a raw description of a keyring. The returned string is "
        "\"<type>;<uid>;<gid>;<perms>;<description>\"",
        NULL)
  DEFUN("keyctl~describe", 1, 1, keyctl_describe_fn,
        "(keyctl~describe keyID)\n\n"
        "Returns a description of a keyring as a 5-element vector. The vector "
        "looks like:"
        "[type(stringp) uid(integerp) gid(integerp) perms(integerp) "
        "description(stringp)] ",
        NULL)
  DEFUN("keyctl~read", 1, 1, keyctl_read_fn,
        "(keyctl~read keyID)\n\n"
        "Returns the payload of a key.",
        NULL)
  DEFUN("keyctl~list", 1, 1, keyctl_list_fn,
        "(keyctl~list keyring)\n\n"
        "Returns list of key IDs attached to a keyring.",
        NULL)
  DEFUN("keyctl~search", 3, 4, keyctl_search_fn,
        "(keyctl~search keyring type description &optional dest_keyring)\n\n"
        "Recursively searches a keyring for a key of a particular type and "
        "description."
        "Returns the id of key or nil and attaches to the "
        "dest_keyring if present",
        NULL)
  DEFUN("keyctl~clear", 1, 1, keyctl_clear_fn,
        "(keyctl~clear keyring)\n\n"
        "Unlinks all the keys attached to the specified keyring."
        "\nReturns nil if unsuccessful.",
        NULL)
  DEFUN("keyctl~set-timeout", 2, 2, keyctl_set_timeout_fn,
        "(keyctl~set-timeout keyID timeout)\n\n"
        "Sets the expiration timer on a key to  timeout seconds into the "
        "future. Setting timeout to zero cancels the expiration."
        "\nReturns nil if unsuccessful.",
        NULL)
  DEFUN("keyctl~revoke", 1, 1, keyctl_revoke_fn,
        "(keyctl~revoke keyID)\n\n"
        "Marks a key as being revoked. Any further access will meet with error "
        "EKEYREVOKED.\n"
        "Returns nil if unsuccessful.",
        NULL)
  provide(env, "keyctl");
  return 0;
}
