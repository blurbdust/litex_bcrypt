CFLAGS=-O2 -Wall -g -I../kernel -Iliblitepcie -MMD -fPIC
LDFLAGS=-g
CC=$(CROSS_COMPILE)gcc
AR=ar

PROGS=litepcie_util litepcie_test bcrypt_test cleanup_test

all: $(PROGS)

liblitepcie/liblitepcie.a: liblitepcie/litepcie_dma.o liblitepcie/litepcie_flash.o liblitepcie/litepcie_helpers.o
	ar rcs $@ $^
	ranlib $@

litepcie_util: liblitepcie/liblitepcie.a litepcie_util.o
	$(CC) $(LDFLAGS) -o $@ $^ -Lliblitepcie -llitepcie

litepcie_test: liblitepcie/liblitepcie.a litepcie_test.o
	$(CC) $(LDFLAGS) -o $@ $^ -Lliblitepcie -lm -llitepcie

bcrypt_test: liblitepcie/liblitepcie.a bcrypt_test.o
	$(CC) $(LDFLAGS) -o $@ $^ -Lliblitepcie -llitepcie

cleanup_test: liblitepcie/liblitepcie.a cleanup_test.o
	$(CC) $(LDFLAGS) -o $@ $^ -Lliblitepcie -llitepcie

clean:
	rm -f $(PROGS) *.o *.a *.d *~ liblitepcie/*.a liblitepcie/*.o liblitepcie/*.d

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

liblitepcie/%.o: liblitepcie/%.c
	$(CC) -c $(CFLAGS) -o $@ $<

-include $(wildcard *.d)
