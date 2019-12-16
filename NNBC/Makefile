CC = gcc

CFLAGS = -g -O2 -Wall -Wextra -I/usr/local/include -I./include -I/usr/include/postgresql

NNBC_CONF_FILE?=nnbc_conf.yaml

PREFIX=/usr/local

HEADERS = $(wildcard include/*.h)
TSOURCES = $(wildcard tsrc/*.c)
SOURCES = $(wildcard src/libnnbc/*.c)
OBJECTS = $(patsubst src/libnnbc%.c,obj/%.o,$(SOURCES))

all: prep lib/libnnbc.so

.PHONY: prep
prep:
	mkdir -p obj
	mkdir -p lib
	mkdir -p bin

obj/%.o: src/libnnbc/%.c
	$(CC) $(CFLAGS) -fPIC $< -c -o $@

lib/libnnbc.so: $(OBJECTS)
	$(CC) $(OBJECTS) -fPIC --shared -o lib/libnnbc.so -lpthread -lpq -lyaml

bin/%: tsrc/%.c lib/libnnbc.so
	$(CC) $(CFLAGS) $< -o $@ -Llib -lnnbc -lyaml

.PHONY: install
install: lib/libnnbc.so
	install -m 644 include/nnbc.h $(PREFIX)/include
	install -m 644 lib/libnnbc.so $(PREFIX)/lib
	mkdir -p $(PREFIX)/bin/nnbc
	install -m 755 src/*.py $(PREFIX)/bin/nnbc
	mkdir -p /etc/nnbc
	install -m 644 conf/$(NNBC_CONF_FILE) /etc/nnbc/nnbc_conf.yaml

.PHONY: clean
clean:
	rm -rf obj lib bin
