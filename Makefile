CC ?= gcc
PYTHON ?= python3
CFLAGS ?= -Wall -Wextra -O2 -std=c99 -I.
TARGET = test_des
OBJS = des.o munit.o test.o edge_vectors.o

# Opt-in NIST CAVP response-file validation (make DES_CAVP=1 test)
DES_CAVP ?= 0
CAVP_CONFIG = .des_cavp_$(DES_CAVP)
ifeq ($(DES_CAVP),1)
CFLAGS += -DDES_CAVP=1
OBJS += cavp.o
endif

.PHONY: all clean test size

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

des.o: des.c des.h
	$(CC) $(CFLAGS) -c $< -o $@

munit.o: munit.c munit.h
	$(CC) $(CFLAGS) -c $< -o $@

edge_vectors.o: test_edge_vectors.c des.h edge_vectors.h munit.h
	$(CC) $(CFLAGS) -c $< -o $@

test.o: test.c des.h munit.h test_vectors.h $(CAVP_CONFIG)
	$(CC) $(CFLAGS) -c $< -o $@

$(CAVP_CONFIG):
	@touch $@

cavp.o: cavp.c des.h munit.h
	$(CC) $(CFLAGS) -c $< -o $@

test_vectors.h: generate_test_vectors.py
	$(PYTHON) $<

edge_vectors.h: generate_edge_vectors.py
	$(PYTHON) $<

test: $(TARGET)
	./$(TARGET)

size: des.o
	size des.o

clean:
	rm -f des.o munit.o test.o edge_vectors.o cavp.o $(TARGET) .des_cavp_*
