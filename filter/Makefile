CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -O2
CFLAGS  += -D_GNU_SOURCE -Iinclude -I../common
SRC      = $(wildcard src/*.c)
OBJ      = $(SRC:.c=.o)
BIN      = fw-filter

TEST_BINS = tests/test_parser tests/test_rules tests/test_pktlog tests/test_conntrack tests/test_control tests/test_pipeline

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "==> Running $$t..."; \
		./$$t || exit 1; \
	done

tests/test_parser: tests/test_parser.o src/parser.o src/net_utils.o
	$(CC) $(CFLAGS) -o $@ $^

tests/test_rules: tests/test_rules.o src/rules.o src/parser.o src/net_utils.o src/io.o src/json_utils.o
	$(CC) $(CFLAGS) -o $@ $^

tests/test_pktlog: tests/test_pktlog.o src/pktlog_client.o src/rules.o src/parser.o src/net_utils.o src/io.o src/json_utils.o
	$(CC) $(CFLAGS) -o $@ $^

tests/test_conntrack: tests/test_conntrack.o src/conntrack.o src/rules.o src/parser.o src/net_utils.o src/io.o src/json_utils.o
	$(CC) $(CFLAGS) -o $@ $^

tests/test_control: tests/test_control.o src/control.o src/json_utils.o src/conntrack.o src/rules.o src/parser.o src/net_utils.o src/pktlog_client.o src/io.o
	$(CC) $(CFLAGS) -o $@ $^

tests/test_pipeline: tests/test_pipeline.o src/io.o src/control.o src/json_utils.o src/conntrack.o src/rules.o src/parser.o src/net_utils.o src/pktlog_client.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJ) $(BIN) tests/*.o $(TEST_BINS)

.PHONY: all clean test
