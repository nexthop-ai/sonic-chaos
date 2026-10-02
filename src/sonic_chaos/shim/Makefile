# sonic-chaos SAI shim.
#
#   make            build/sonic_chaos_sai.so
#   make test       build both, then prove interposition works against stand-in daemons
#   make spin-test  just the spin half
#   make abi        show the glibc versions the .so needs (must be <= the syncd container's)
#
# Build it somewhere no newer than the syncd container: a binary linked against glibc 2.41
# will not load on a bookworm image. build.sh picks a container for you.

CC      ?= gcc
BUILD   ?= build
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Werror -fPIC -fvisibility=hidden -D_GNU_SOURCE
LDFLAGS += -shared -Wl,--no-undefined
LDLIBS  += -ldl -lpthread

SHIM    := $(BUILD)/sonic_chaos_sai.so
SOURCES := sonic_chaos_sai.c hs_json.c
SPIN    := $(BUILD)/sonic_chaos_spin.so
SPIN_SRC := sonic_chaos_spin.c hs_json.c

.PHONY: all test spin-test abi clean

all: $(SHIM) $(SPIN)

$(SHIM): $(SOURCES) hs_json.h hs_tags.h | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES) $(LDLIBS)

$(SPIN): $(SPIN_SRC) hs_json.h | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SPIN_SRC) $(LDLIBS)

$(BUILD):
	mkdir -p $(BUILD)

test: $(SHIM) $(SPIN)
	@BUILD=$(BUILD) CC=$(CC) ./test/run_tests.sh
	@BUILD=$(BUILD) CC=$(CC) ./test/run_spin_tests.sh

spin-test: $(SPIN)
	@BUILD=$(BUILD) CC=$(CC) ./test/run_spin_tests.sh

# sai_api_query must be the one symbol we export, and the glibc floor must stay low.
abi: $(SHIM) $(SPIN)
	@echo "exported:"
	@nm -D --defined-only $(SHIM) | grep -v ' [a-z] ' || true
	@echo "glibc versions required:"
	@objdump -T $(SHIM) | grep -o 'GLIBC_[0-9.]*' | sort -u -V
	@echo "spin exported:"
	@nm -D --defined-only $(SPIN) | grep -v ' [a-z] ' || true
	@echo "spin glibc versions required:"
	@objdump -T $(SPIN) | grep -o 'GLIBC_[0-9.]*' | sort -u -V

clean:
	rm -rf $(BUILD)
