CC ?= gcc
PYTHON ?= python3
CFLAGS ?= -Wall -Wextra -O2 -std=c99 -I.
TARGET = test_des
OBJS = des.o munit.o test.o

.PHONY: all clean test size

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

des.o: des.c des.h
	$(CC) $(CFLAGS) -c $< -o $@

munit.o: munit.c munit.h
	$(CC) $(CFLAGS) -c $< -o $@

test.o: test.c des.h munit.h test_vectors.h
	$(CC) $(CFLAGS) -c $< -o $@

test_vectors.h: generate_test_vectors.py
	$(PYTHON) $<

test: $(TARGET)
	./$(TARGET)

size: des.o
	size des.o

clean:
	rm -f $(OBJS) $(TARGET)
