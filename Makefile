CFLAGS := -std=c99 -O2 -Wall -Wextra -Wpedantic -Wno-unused-parameter -pedantic-errors -Werror -fPIC -I$(PWD)

.PHONY: test clean
all: keyctl.so

keyctl.so : module-helper.o keyctl.o
	$(LD) -shared $(LDFLAGS) -lkeyutils -o $@ $^
module-helper.o : module-helper.c module-helper.h
keyctl.o : keyctl.c macro-args-iter.h module-helper.h
test:
	emacs -Q -batch -l test.el -f ert-run-tests-batch-and-exit
clean:
	rm -f keyctl.so keyctl.o module-helper.o

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $<
