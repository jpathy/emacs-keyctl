;; -*- lexical-binding: t; -*-

;; Some code is copied from auth-source.el because it stores netrc
;; entries and i couldn't find clean way to reuse that code.
;; Most of the copied code is in -normalize and -create function.

(eval-when-compile
  (require 'rx)
  (require 'cl-lib))
(require 'seq)
(require 'auth-source)

(autoload 'keyctl~new-keyring "keyctl")
(autoload 'keyctl~add-key "keyctl")
(autoload 'keyctl~describe "keyctl")
(autoload 'keyctl~read "keyctl")
(autoload 'keyctl~list "keyctl")
(autoload 'keyctl~unlink "keyctl")

(defconst COUNTER-KEY-NAME "auth-source:counter"
  "Description for the counter key under the keyring chosen by backend")

(defun auth-source-backends-parser-linux-keyrings (entry)
  "Create a linux-keyrings auth-source backend from ENTRY."
  ;; take linux-keyrings:XYZ and use it as a process-keyring "XYZ"
  ;; matching any user, host, and protocol
  (when (and (stringp entry) (string-match "^linux-keyrings:\\(.+\\)" entry))
    (setq entry `(:source (:linux-keyrings ,(match-string 1 entry)))))
  ;; take 'linux-keyrings and use "authinfo" as a process-keyring
  ;; matching any user, host, and protocol
  (when (eq entry 'linux-keyrings)
    (setq entry '(:source (:linux-keyrings "auth-source:authinfo"))))
  (let ((source-spec (plist-get entry :source)))
    (cond
     ((and
       (not (null source-spec))
       (listp source-spec)
       (stringp (plist-get source-spec :linux-keyrings))
       (require 'keyctl nil t))
      (let ((source (plist-get source-spec :linux-keyrings)))
        (if (featurep 'keyctl)
            (auth-source-backend
             (format "Linux process-keyring (%s)" source)
             :source source
             :type 'linux-keyrings
             :search-function #'auth-source-linux-keyrings-search
             :create-function #'auth-source-linux-keyrings-create
             :data (keyctl~get-keyring source))
          (auth-source-do-warn
           "auth-source-backend-parse: no keyctl API, ignoring spec: %S" entry)
          (auth-source-backend
           (format "Ignored Linux process-keyring (%s)" source)
           :source ""
           :type 'ignore)))))))

(if (boundp 'auth-source-backend-parser-functions)
    (add-hook 'auth-source-backend-parser-functions
              #'auth-source-backends-parser-linux-keyrings)
  (advice-add 'auth-source-backend-parse
              :before-until #'auth-source-backends-parser-linux-keyrings))

(defvar auth-source-keyrings-cache nil)
(advice-add 'auth-source-forget-all-cached
            :after #'(lambda ()
                       (setq auth-source-keyrings-cache nil)))

(defun keyctl~get-keyring (source)
  (or (cdr-safe (assoc source auth-source-keyrings-cache))
      (let* ((keyring (or
                       (ignore-errors
                         (keyctl~search KEY-SPEC-PROCESS-KEYRING
                                        "keyring" source))
                       (keyctl~new-keyring source KEY-SPEC-PROCESS-KEYRING)))
             (counter (or
                       (ignore-errors
                         (keyctl~search keyring "user" COUNTER-KEY-NAME))
                       (keyctl~add-key "user" COUNTER-KEY-NAME "0" keyring)))
             (next-key (string-to-number (keyctl~read counter)))
             (plist (list
                     :keyring keyring
                     :next-key next-key)))
        (auth-source--aput
         auth-source-keyrings-cache source
         plist)
        plist)))

(defun auth-source-keyrings-netrc-normalize (alist)
  (mapcar (lambda (entry)
            (let (ret item)
              (while (setq item (pop entry))
                (let ((k (car item))
                      (v (cdr item)))

                  ;; apply key aliases
                  (setq k (cond ((member k '("machine")) "host")
                                ((member k '("login" "account")) "user")
                                ((member k '("protocol")) "port")
                                ((member k '("password")) "secret")
                                (t k)))

                  ;; send back the secret in a function (lexical binding)
                  (when (equal k "secret")
                    (setq v (lambda ()
                              v)))
                  (setq ret (plist-put ret
                                       (auth-source--symbol-keyword k)
                                       v))))
              ret))
          alist))

(defun auth-source-keyrings-parse-item (str idx)
  "Read one item from payload of a key"
  (when (eq (string-match (rx (+ (any " \t\n"))) str idx) idx)
    (setq idx (match-end 0)))
  (when (eq (string-match (rx (or (seq "'"
                                       (group (* (not-char "'")))
                                       "'")
                                  (seq "\""
                                       (group (* (not-char "\"")))
                                       "\"")
                                  (group (+ (not-char " \t\n")))))
                          str idx)
            idx)
    (cons (or (match-string-no-properties 1 str)
              (match-string-no-properties 2 str)
              (match-string-no-properties 3 str))
          (match-end 0))))

(defun auth-source-keyrings-parse-entry (id)
  "Return an alist parsing the payload of the key id"
  (let* ((str (keyctl~read id))
         (idx 0)
         alist item item2 res)
    (while (setq res (auth-source-keyrings-parse-item str idx))
      (setq item (car res)
            idx (cdr res))
      (if (equal item "default")
          (push (cons "machine" "t") alist)
        (when (setq res (auth-source-keyrings-parse-item str idx))
          (setq item2 (car res)
                idx (cdr res))
          (push (cons item item2) alist))))
    (nreverse alist)))

(cl-defun auth-source-keyrings-parse-entries (&key keyring max host user port
                                                   require delete
                                                   &allow-other-keys)
  "Parse up to MAX netrc entries, passed by CHECK, from the keyring.
the keyring has keys with payload containing an entry with a single
machine item."
  (let ((max (or max 5000))
        (check (lambda (alist)
                 (and alist
                      (auth-source-search-collection
                       host
                       (or
                        (auth-source--aget alist "machine")
                        (auth-source--aget alist "host")
                        t))
                      (auth-source-search-collection
                       user
                       (or
                        (auth-source--aget alist "login")
                        (auth-source--aget alist "account")
                        (auth-source--aget alist "user")
                        t))
                      (auth-source-search-collection
                       port
                       (or
                        (auth-source--aget alist "port")
                        (auth-source--aget alist "protocol")
                        t))
                      (or
                       ;; the required list of keys is nil, or
                       (null require)
                       ;; every element of require is in n (normalized)
                       (let ((n (nth 0 (auth-source-keyrings-netrc-normalize
                                        (list alist)))))
                         (cl-loop for req in require
                                  always (plist-get n req))))))))
    (cl-loop for key in (keyctl~list keyring)
             for alist = (auth-source-keyrings-parse-entry key)
             with count = 0
             while (< count max)
             when (and (funcall check alist)
                       (progn
                         (setq count (1+ count))
                         ;; unlink the matching entry when delete is non-nil.
                         (when delete
                           (keyctl~unlink key keyring))
                         t))
             collect alist)))

(cl-defun auth-source-linux-keyrings-search (&rest spec
                                                   &key backend require create
                                                   type max host user port
                                                   &allow-other-keys)
  "Given a property list SPEC, return search matches from the :backend.
See `auth-source-search' for details on SPEC."
  ;; just in case, check that the type is correct (null or same as the backend)
  (cl-assert (or (null type) (eq type (oref backend type)))
             t "Invalid linux-keyrings search: %s %s")

  (let* ((keyring (plist-get (oref backend data) :keyring))
         (results (auth-source-keyrings-netrc-normalize
                   (auth-source-keyrings-parse-entries
                    :keyring keyring
                    :max max
                    :require require
                    :host (or host t)
                    :user (or user t)
                    :port (or port t)))))
    ;; when delete is non-nil we are guaranteed to get results(which are deleted)
    (when (and create
               (not results))
      ;; create based on the spec and record the value
      (setq results (or
                     ;; if the user did not want to create the entry
                     ;; in the file, it will be returned
                     (apply (slot-value backend 'create-function) spec)
                     ;; if not, we do the search again without :create
                     ;; to get the updated data.

                     ;; the result will be returned, even if the search fails
                     (apply #'auth-source-linux-keyrings-search
                            (plist-put spec :create nil)))))))

(cl-defun auth-source-linux-keyrings-create (&rest spec
                                                   &key backend create
                                                   &allow-other-keys)
  (let* ((base-required '(host user port secret))
         ;; we know (because of an assertion in auth-source-search) that the
         ;; :create parameter is either t or a list (which includes nil)
         (create-extra (if (eq t create) nil create))
         (required (append base-required create-extra))
         (add "")
         ;; `valist' is an alist
         valist
         ;; `artificial' will be returned if no creation is needed
         artificial)
    ;; only for base required elements (defined as function parameters):
    ;; fill in the valist with whatever data we may have from the search
    ;; we complete the first value if it's a list and use the value otherwise
    (dolist (br base-required)
      (let ((val (plist-get spec (auth-source--symbol-keyword br))))
        (when val
          (let ((br-choice (cond
                            ;; all-accepting choice (predicate is t)
                            ((eq t val) nil)
                            ;; just the value otherwise
                            (t val))))
            (when br-choice
              (auth-source--aput valist br br-choice))))))

    ;; for extra required elements, see if the spec includes a value for them
    (dolist (er create-extra)
      (let ((k (auth-source--symbol-keyword er))
            (keys (cl-loop for i below (length spec) by 2
                           collect (nth i spec))))
        (when (memq k keys)
          (auth-source--aput valist er (plist-get spec k)))))

    ;; for each required element
    (dolist (r required)
      (let* ((data (auth-source--aget valist r))
             ;; take the first element if the data is a list
             (data (auth-source-netrc-element-or-first data))
             ;; this is the default to be offered
             (given-default (auth-source--aget
                             auth-source-creation-defaults r))
             ;; the default supplementals are simple:
             ;; for the user, try `given-default' and then (user-login-name);
             ;; otherwise take `given-default'
             (default (cond
                       ((and (not given-default) (eq r 'user))
                        (user-login-name))
                       (t given-default)))
             (printable-defaults (list
                                  (cons 'user
                                        (or
                                         (auth-source-netrc-element-or-first
                                          (auth-source--aget valist 'user))
                                         (plist-get artificial :user)
                                         "[any user]"))
                                  (cons 'host
                                        (or
                                         (auth-source-netrc-element-or-first
                                          (auth-source--aget valist 'host))
                                         (plist-get artificial :host)
                                         "[any host]"))
                                  (cons 'port
                                        (or
                                         (auth-source-netrc-element-or-first
                                          (auth-source--aget valist 'port))
                                         (plist-get artificial :port)
                                         "[any port]"))))
             (prompt (or (auth-source--aget auth-source-creation-prompts r)
                         (cl-case r
                           (secret "%p password for %u@%h: ")
                           (user "%p user name for %h: ")
                           (host "%p host name for user %u: ")
                           (port "%p port for %u@%h: "))
                         (format "Enter %s (%%u@%%h:%%p): " r)))
             (prompt (auth-source-format-prompt
                      prompt
                      `((?u ,(auth-source--aget printable-defaults 'user))
                        (?h ,(auth-source--aget printable-defaults 'host))
                        (?p ,(auth-source--aget printable-defaults 'port))))))

        ;; Store the data, prompting for the password if needed.
        (setq data (or data
                       (if (eq r 'secret)
                           ;; Special case prompt for passwords.
                           (or (eval default) (read-passwd prompt))
                         (if (stringp default)
                             (read-string (if (string-match ": *\\'" prompt)
                                              (concat (substring prompt 0 (match-beginning 0))
                                                      " (default " default "): ")
                                            (concat prompt "(default " default ") "))
                                          nil nil default)
                           (eval default)))))

        (when data
          (setq artificial (plist-put artificial
                                      (auth-source--symbol-keyword r)
                                      (if (eq r 'secret)
                                          (let ((data data))
                                            (lambda () data))
                                        data))))

        ;; When r is not an empty string...
        (when (and (stringp data)
                   (< 0 (length data)))
          ;; this function is not strictly necessary but I think it
          ;; makes the code clearer -tzz
          (let ((printer (lambda ()
                           ;; append the key (the symbol name of r)
                           ;; and the value in r
                           (format "%s%s %s"
                                   ;; prepend a space
                                   (if (zerop (length add)) "" " ")
                                   ;; remap auth-source tokens to netrc
                                   (cl-case r
                                     (user   "login")
                                     (host   "machine")
                                     (secret "password")
                                     (port   "port") ; redundant but clearer
                                     (t (symbol-name r)))
                                   (if (string-match "[\"# ]" data)
                                       (format "%S" data)
                                     data)))))
            (setq add (concat add (funcall printer)))))))

    (plist-put
     artificial
     :save-function
     (let ((keyring (plist-get (oref backend data) :keyring))
           (next-key (plist-get (oref backend data) :next-key))
           (add add))
       (plist-put (cdr-safe (assoc (oref backend source)
                                   auth-source-keyrings-cache))
                  :next-key (1+ next-key))
       (lambda ()
         (keyctl~update-key (keyctl~search keyring "user" COUNTER-KEY-NAME)
                            (number-to-string (1+ next-key)))
         (keyctl~add-key "user" (number-to-string next-key) add keyring))))

    (list artificial)))

(provide 'auth-source-keyctl)
